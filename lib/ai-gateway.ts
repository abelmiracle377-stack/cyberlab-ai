export type GatewayMessage = { role: "system" | "user" | "assistant"; content: string };
export type GatewayResult = { text: string; usage: { promptTokens: number; completionTokens: number; totalTokens: number }; provider: string; model: string };

function getProviderConfig() {
  const apiKey = process.env.CYBERLAB_UNCENSORED_API_KEY || process.env.UNCENSOREDLLM_API_KEY;
  const configuredUrl = process.env.CYBERLAB_UNCENSORED_BASE_URL || "";
  let baseUrl = "";
  try {
    const parsed = new URL(configuredUrl);
    if (parsed.protocol === "https:" && !parsed.username && !parsed.password && !parsed.search && !parsed.hash) {
      baseUrl = parsed.toString().replace(/\/+$/, "");
    }
  } catch { /* Missing or invalid configuration remains unavailable. */ }
  return { apiKey, baseUrl };
}

type ConfiguredModel = { id: string; name: string; contextLength: number | null; supportsTools: boolean };
export function getUnfilteredModels(): Array<{ id: string; name: string; provider: string; contextLength: number | null; openWeight: boolean; uncensored: boolean; supportsTools: boolean }> {
  const raw = process.env.CYBERLAB_UNCENSORED_MODELS;
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.flatMap((entry: unknown) => {
      if (!entry || typeof entry !== "object") return [];
      const item = entry as { id?: unknown; name?: unknown; contextLength?: unknown; tools?: unknown };
      if (typeof item.id !== "string" || !/^[a-zA-Z0-9._:/-]{3,180}$/.test(item.id)) return [];
      if (item.contextLength !== undefined && (typeof item.contextLength !== "number" || !Number.isInteger(item.contextLength) || item.contextLength < 256 || item.contextLength > 2000000)) return [];
      return [{
        id: `uncensored:${item.id}`,
        name: typeof item.name === "string" ? item.name.slice(0, 120) : item.id,
        provider: "Unfiltered inference",
        contextLength: typeof item.contextLength === "number" ? item.contextLength : null,
        openWeight: true,
        uncensored: true,
        supportsTools: item.tools === true,
      }];
    });
  } catch { return []; }
}

export async function runUnfilteredCompletion(input: { model: string; messages: GatewayMessage[]; maxTokens?: number }): Promise<GatewayResult> {
  const { apiKey, baseUrl } = getProviderConfig();
  if (!apiKey || !baseUrl) throw new Error("Unfiltered model provider is not configured. Add server-only provider secrets.");
  const configured = getUnfilteredModels().find((item) => item.id === `uncensored:${input.model}`);
  if (!configured) throw new Error("This model is not in CyberLab's server-approved model catalogue.");
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST", headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json", "X-Title": "CyberLab AI" },
    body: JSON.stringify({ model: input.model, messages: input.messages, temperature: 0.25, max_tokens: Math.min(Math.max(input.maxTokens ?? 1800, 128), 4096), stream: false }),
    cache: "no-store", signal: AbortSignal.timeout(90000),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof payload?.error?.message === "string" ? payload.error.message : `Provider returned HTTP ${response.status}.`;
    throw new Error(message.slice(0, 500));
  }
  const content = payload?.choices?.[0]?.message?.content;
  if (typeof content !== "string" || !content.trim()) throw new Error("The selected model returned an empty response.");
  const usage = payload?.usage || {};
  const promptTokens = Number.isFinite(usage.prompt_tokens) ? Math.max(0, Number(usage.prompt_tokens)) : 0;
  const completionTokens = Number.isFinite(usage.completion_tokens) ? Math.max(0, Number(usage.completion_tokens)) : 0;
  return { text: content.slice(0, 30000), usage: { promptTokens, completionTokens, totalTokens: promptTokens + completionTokens }, provider: "uncensoredllm-compatible", model: input.model };
}

export function getToolCallingModel(model: string) {
  return getUnfilteredModels().find((item) => item.id === `uncensored:${model}` && item.supportsTools) || null;
}

export function getUnfilteredProviderConfig() {
  return getProviderConfig();
}
