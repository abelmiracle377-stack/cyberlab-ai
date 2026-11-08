import { isIP } from "node:net";
import { lookup, resolve4, resolve6, resolveMx, resolveNs, resolveTxt } from "node:dns/promises";
import { stepCountIs, streamText, tool } from "ai";
import { z } from "zod";

export const runtime = "nodejs";
export const maxDuration = 60;

const modelSchema = z.string().min(3).max(160).regex(/^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._:-]+$/);

const agentInstructions = `You are CyberLab AI, an evidence-first cybersecurity research assistant.
Help with defensive security, authorised testing, OSINT from public sources, network intelligence, vulnerability research, safe malware triage, and technical reporting.
Use available tools when they materially improve accuracy. Explain what a tool checked and distinguish observed facts from inference.
Never claim a scan or lookup occurred unless a tool returned its result. Do not identify a private person from an IP address, infer subscriber registration details, retrieve private browsing history, or facilitate covert camera capture or deceptive tracking.
Do not provide instructions for unauthorised access, credential theft, persistence, evasion, malware deployment, or disruption. For active testing, ask for explicit authorisation and scope; this first version only performs passive IP and DNS lookups.
Keep responses clear, technically precise, and include uncertainty and limitations.`;

const tools = {
  ip_intelligence: tool({
    description: "Look up public IP intelligence: network owner, ASN, ISP, country and approximate region. This does not identify a person or subscriber.",
    inputSchema: z.object({ ip: z.string().min(3).max(64).describe("IPv4 or IPv6 address") }),
    execute: async ({ ip }) => {
      if (!isIP(ip)) return { error: "Enter a valid IPv4 or IPv6 address." };
      const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(8000) });
      if (!response.ok) return { error: "The public IP intelligence source is unavailable." };
      const data = await response.json();
      if (data.success === false) return { error: data.message || "Lookup failed." };
      return {
        ip: data.ip,
        type: data.type,
        continent: data.continent,
        country: data.country,
        region: data.region,
        city: data.city,
        latitude: data.latitude,
        longitude: data.longitude,
        connection: data.connection ? {
          isp: data.connection.isp,
          organization: data.connection.org,
          asn: data.connection.asn,
        } : null,
        note: "Geolocation is approximate and describes network registration or routing context, not a verified person's location or identity.",
        source: "ipwho.is",
      };
    },
  }),
  dns_intelligence: tool({
    description: "Perform passive DNS resolution for a domain: A, AAAA, MX, NS and TXT records. Does not scan or probe services.",
    inputSchema: z.object({ domain: z.string().min(3).max(253).describe("Domain name, without a URL or path") }),
    execute: async ({ domain }) => {
      const normalized = domain.trim().toLowerCase().replace(/\.$/, "");
      if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(normalized)) {
        return { error: "Enter a valid public domain name, without https:// or a path." };
      }
      const safeResolve = async (fn: (domain: string) => Promise<unknown>) => {
        try { return await fn(normalized); } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          return code === "ENODATA" || code === "ENOTFOUND" ? [] : { lookupError: code || "DNS_ERROR" };
        }
      };
      const [a, aaaa, mx, ns, txt] = await Promise.all([
        safeResolve(resolve4), safeResolve(resolve6), safeResolve(resolveMx),
        safeResolve(resolveNs), safeResolve(resolveTxt),
      ]);
      return { domain: normalized, records: { A: a, AAAA: aaaa, MX: mx, NS: ns, TXT: txt }, source: "System DNS resolver" };
    },
  }),
};

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const prompt = typeof body.prompt === "string" ? body.prompt.trim() : "";
    const model = modelSchema.safeParse(body.model || "openai/gpt-5.5");
    if (!prompt || prompt.length > 8000) {
      return Response.json({ error: "Enter a prompt between 1 and 8,000 characters." }, { status: 400 });
    }
    if (!model.success) {
      return Response.json({ error: "Choose a valid provider/model identifier." }, { status: 400 });
    }
    if (!process.env.AI_GATEWAY_API_KEY && !process.env.VERCEL_OIDC_TOKEN) {
      return Response.json({
        error: "AI Gateway authentication is not configured. Enable Vercel OIDC for this project or add AI_GATEWAY_API_KEY as a protected Vercel environment variable.",
        needsConfiguration: true,
      }, { status: 503 });
    }

    const result = streamText({
      model: model.data,
      system: agentInstructions,
      prompt,
      tools,
      stopWhen: stepCountIs(5),
      temperature: 0.2,
      maxOutputTokens: 1800,
    });
    return result.toTextStreamResponse();
  } catch (error) {
    console.error("CyberLab agent request failed:", error);
    return Response.json({ error: "The agent could not complete this request. Check provider configuration and deployment logs." }, { status: 500 });
  }
}