export const runtime = "nodejs";
export const maxDuration = 45;

type OpenRouterSearchResponse = {
  choices?: Array<{ message?: { content?: string | Array<{ type?: string; text?: string }> } }>;
  citations?: string[];
  search_results?: Array<{ title?: string; url?: string; date?: string; snippet?: string }>;
  error?: { message?: string };
};

export async function POST(request: Request) {
  let body: unknown;
  try { body = await request.json(); }
  catch { return Response.json({ error: "Invalid JSON request." }, { status: 400 }); }

  const query = body && typeof body === "object" && "query" in body
    ? (body as { query?: unknown }).query : null;
  if (typeof query !== "string" || query.trim().length < 4 || query.length > 1200 || /[\u0000-\u0008]/.test(query)) {
    return Response.json({ error: "Enter a research question between 4 and 1,200 characters." }, { status: 400 });
  }
  if (!process.env.OPENROUTER_API_KEY) {
    return Response.json({ error: "OpenRouter is not configured. Add OPENROUTER_API_KEY in Vercel and redeploy." }, { status: 503 });
  }

  try {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cyberlab-ai.vercel.app",
        "X-Title": "CyberLab AI Live Research",
      },
      body: JSON.stringify({
        model: "perplexity/sonar",
        temperature: 0.1,
        max_tokens: 1600,
        messages: [
          { role: "system", content: "You are CyberLab AI's live cybersecurity research analyst. Search the current public web for the user's question. Prioritise primary sources: vendor advisories, NIST NVD, CISA, CERTs, official project documentation and maintainer announcements. Clearly distinguish confirmed facts from analysis, include dates where available, and never invent citations. Do not provide instructions for unauthorised compromise, credential theft, stealth, persistence or disruption. Return a concise, evidence-led answer." },
          { role: "user", content: query.trim() },
        ],
      }),
      signal: AbortSignal.timeout(40000),
      cache: "no-store",
    });
    const payload = await response.json() as OpenRouterSearchResponse;
    if (!response.ok) {
      const message = payload.error?.message || `OpenRouter research request failed with HTTP ${response.status}.`;
      return Response.json({ error: message }, { status: response.status === 429 ? 429 : 502 });
    }
    const raw = payload.choices?.[0]?.message?.content;
    const answer = typeof raw === "string" ? raw : Array.isArray(raw) ? raw.map((part) => part.text || "").join("\n") : "";
    if (!answer.trim()) return Response.json({ error: "The live research provider returned an empty answer. Please retry." }, { status: 502 });
    const citations = (payload.citations || []).filter((url) => typeof url === "string" && /^https:\/\//i.test(url)).slice(0, 12);
    const results = (payload.search_results || []).filter((item) => item.url && /^https:\/\//i.test(item.url)).slice(0, 12);
    return Response.json({
      answer,
      citations,
      results,
      model: "perplexity/sonar",
      source: "OpenRouter · Perplexity Sonar live web search",
      note: "Search results can be incomplete or stale. Verify critical security findings against the linked primary source and vendor advisory.",
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return Response.json({ error: timedOut ? "Live research timed out. Try a narrower question." : "Could not reach the live research provider." }, { status: 502 });
  }
}
