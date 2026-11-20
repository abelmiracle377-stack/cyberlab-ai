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

const openWeightProviders = ["qwen/", "deepseek/", "mistralai/", "meta-llama/", "nousresearch/", "cognitivecomputations/", "google/", "microsoft/", "tii/", "01-ai/", "internlm/"];

function ollamaBaseUrl() {
  const raw = process.env.OLLAMA_BASE_URL?.trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) return null;
    return url.toString().replace(/\/$/, "");
  } catch { return null; }
}

type CatalogueModel = {
  id: string;
  name: string;
  provider: string;
  contextLength: number | null;
  openWeight: boolean;
  uncensored?: boolean;
  supportsTools?: boolean;
  source: "unfiltered" | "openrouter" | "ollama";
};

const sourceOrder: Record<CatalogueModel["source"], number> = { unfiltered: 0, openrouter: 1, ollama: 2 };

export async function GET() {
  const models: CatalogueModel[] = getUnfilteredModels().map((item) => ({ ...item, source: "unfiltered" as const }));
  const errors: string[] = [];
  try {
    // The OpenRouter model list is public; send the key only when one is configured.
    const response = await fetch("https://openrouter.ai/api/v1/models", {
      headers: process.env.OPENROUTER_API_KEY ? { Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}` } : {},
      next: { revalidate: 300 },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error("OpenRouter catalogue unavailable.");
    const payload = (await response.json()) as { data?: OpenRouterModel[] };
    models.push(...(payload.data ?? [])
      .filter((item) => typeof item.id === "string" && item.id.includes("/") && (!item.architecture?.modality || item.architecture.modality.includes("text")))
      .map((item) => {
        const id = item.id ?? "";
        return {
          id,
          name: item.name ?? id,
          provider: id.split("/")[0],
          contextLength: item.context_length ?? null,
          openWeight: Boolean(item.hugging_face_id || openWeightProviders.some((provider) => id.toLowerCase().startsWith(provider))),
          supportsTools: item.supported_parameters?.includes("tools") === true,
          source: "openrouter" as const,
        };
      }));
  } catch { errors.push("OpenRouter catalogue unavailable."); }
  const ollama = ollamaBaseUrl();
  if (ollama) {
    try {
      const response = await fetch(`${ollama}/api/tags`, { headers: process.env.OLLAMA_API_KEY ? { Authorization: `Bearer ${process.env.OLLAMA_API_KEY}` } : {}, cache: "no-store", signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw new Error("Ollama model catalogue unavailable.");
      const payload = await response.json() as { models?: Array<{ name?: string; model?: string; details?: { parameter_size?: string } }> };
      models.push(...(payload.models ?? []).flatMap((item) => {
        const id = item.name || item.model;
        if (!id) return [];
        return [{ id, name: id, provider: "Ollama", contextLength: null, openWeight: true, source: "ollama" as const }];
      }));
    } catch { errors.push("Configured Ollama endpoint is unavailable."); }
  }
  models.sort((a, b) => sourceOrder[a.source] - sourceOrder[b.source] || a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name));
  const providers = {
    unfiltered: models.some((item) => item.source === "unfiltered"),
    openrouter: Boolean(process.env.OPENROUTER_API_KEY),
    ollamaConfigured: Boolean(ollama),
    ollamaAvailable: models.some((item) => item.source === "ollama"),
  };
  if (!models.length) {
    return NextResponse.json({ models, providers, errors, error: "Could not reach an available model catalogue." }, { status: 502, headers: { "Cache-Control": "no-store" } });
  }
  return NextResponse.json({ models, providers, errors }, {
    headers: { "Cache-Control": "private, no-store" },
  });
}
