import { NextResponse } from "next/server";
import { getUnfilteredModels } from "@/lib/ai-gateway";

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

const openWeightProviders: string[] = ["qwen/", "deepseek/", "mistralai/", "meta-llama/", "nousresearch/", "cognitivecomputations/", "google/", "microsoft/", "tii/", "01-ai/", "internlm/"];

export async function GET() {
  try {
    const response = await fetch("https://openrouter.ai/api/v1/models", {
      headers: process.env.OPENROUTER_API_KEY ? { Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}` } : {},
      next: { revalidate: 300 },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) {
      const unfiltered = getUnfilteredModels();
      return NextResponse.json({ models: unfiltered, error: unfiltered.length ? undefined : "Model catalogues are temporarily unavailable." }, { status: unfiltered.length ? 200 : 502 });
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
          openWeight: Boolean(supportsTools && (item.hugging_face_id || openWeightProviders.some((provider) => id.toLowerCase().startsWith(provider)))),
        };
      })
      .sort((a, b) => a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name));
    const combined = [...getUnfilteredModels(), ...models];
    return NextResponse.json({ models: combined }, {
      headers: { "Cache-Control": "private, no-store" },
    });
  } catch {
    const unfiltered = getUnfilteredModels();
    return NextResponse.json({ models: unfiltered, error: unfiltered.length ? undefined : "Could not reach an available model catalogue." }, { status: unfiltered.length ? 200 : 502 });
  }
}
