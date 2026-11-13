import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const revalidate = 300;

type OpenRouterModel = {
  id?: string;
  name?: string;
  context_length?: number;
  hugging_face_id?: string;
  supported_parameters?: string[];
  architecture?: { modality?: string };
};

const openWeightProvider = /^(qwen|deepseek|mistralai|meta-llama|nousresearch|cognitivecomputations|google|microsoft|tii|01-ai|internlm)\\//i;

export async function GET() {
  try {
    const response = await fetch("https://openrouter.ai/api/v1/models", {
      headers: process.env.OPENROUTER_API_KEY ? { Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}` } : {},
      next: { revalidate: 300 },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) {
      return NextResponse.json({ models: [], error: "OpenRouter model catalogue is temporarily unavailable." }, { status: 502 });
    }
    const payload = (await response.json()) as { data?: OpenRouterModel[] };
    const models = (payload.data ?? [])
      .filter((item) => typeof item.id === "string" && item.id.includes("/") && (!item.architecture?.modality || item.architecture.modality.includes("text")))
      .map((item) => {
        const id = item.id ?? "";
        const supportsTools = item.supported_parameters?.includes("tools") === true;
        return {
          id,
          name: item.name ?? id,
          provider: id.split("/")[0],
          contextLength: item.context_length ?? null,
          openWeight: Boolean(supportsTools && (item.hugging_face_id || openWeightProvider.test(id))),
        };
      })
      .sort((a, b) => a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name));
    return NextResponse.json({ models }, {
      headers: { "Cache-Control": "public, s-maxage=300, stale-while-revalidate=600" },
    });
  } catch {
    return NextResponse.json({ models: [], error: "Could not reach the OpenRouter model catalogue." }, { status: 502 });
  }
}
