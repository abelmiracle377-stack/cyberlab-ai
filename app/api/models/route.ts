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

export async function GET() {
  const models: Array<{ id: string; name: string; provider: string; contextLength: number | null; openWeight: boolean; source: "openrouter" | "ollama" }> = [];
  const errors: string[] = [];
  if (process.env.OPENROUTER_API_KEY) {
    try {
      const response = await fetch("https://openrouter.ai/api/v1/models", {
        headers: { Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}` },
        next: { revalidate: 300 },
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw new Error("OpenRouter catalogue unavailable.");
      const payload = await response.json() as { data?: OpenRouterModel[] };
      models.push(...(payload.data ?? [])
        .filter((item) => typeof item.id === "string" && item.id.includes("/") && (!item.architecture?.modality || item.architecture.modality.includes("text")))
        .map((item) => {
          const id = item.id ?? "";
          const supportsTools = item.supported_parameters?.includes("tools") === true;
          return { id, name: item.name ?? id, provider: id.split("/")[0], contextLength: item.context_length ?? null, openWeight: Boolean(supportsTools && (item.hugging_face_id || openWeightProviders.some((provider) => id.toLowerCase().startsWith(provider)))), source: "openrouter" as const };
        }));
    } catch { errors.push("OpenRouter catalogue unavailable."); }
  }
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
  models.sort((a, b) => a.source.localeCompare(b.source) || a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name));
  return NextResponse.json({ models, providers: { openrouter: Boolean(process.env.OPENROUTER_API_KEY), ollamaConfigured: Boolean(ollama), ollamaAvailable: models.some((item) => item.source === "ollama") }, errors }, {
    headers: { "Cache-Control": "no-store" },
  });
}
