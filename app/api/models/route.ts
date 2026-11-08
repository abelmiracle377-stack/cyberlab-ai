import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const revalidate = 300;

type GatewayModel = {
  id?: string;
  name?: string;
  owned_by?: string;
  context_length?: number;
};

export async function GET() {
  try {
    const response = await fetch("https://ai-gateway.vercel.sh/v1/models", {
      next: { revalidate: 300 },
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) {
      return NextResponse.json({ models: [], error: "Model catalogue is temporarily unavailable." }, { status: 502 });
    }
    const payload = (await response.json()) as { data?: GatewayModel[] };
    const models = (payload.data ?? [])
      .filter((item) => typeof item.id === "string" && item.id.includes("/"))
      .map((item) => ({
        id: item.id as string,
        name: item.name || item.id,
        provider: item.id!.split("/")[0],
        contextLength: item.context_length ?? null,
      }))
      .sort((a, b) => a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name));
    return NextResponse.json({ models }, {
      headers: { "Cache-Control": "public, s-maxage=300, stale-while-revalidate=600" },
    });
  } catch {
    return NextResponse.json({ models: [], error: "Could not reach the model catalogue." }, { status: 502 });
  }
}