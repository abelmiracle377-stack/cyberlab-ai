import { isIP } from "node:net";
import { resolve4, resolve6, resolveMx, resolveNs, resolveTxt, reverse } from "node:dns/promises";
import { stepCountIs, streamText, tool } from "ai";
import { z } from "zod";

export const runtime = "nodejs";
export const maxDuration = 60;

const modelSchema = z.string().min(3).max(160).regex(/^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._:-]+$/);
const openWeightPrefixes = [
  "openai/gpt-oss-", "meta-llama/", "qwen/", "deepseek/", "mistralai/",
  "google/gemma-", "microsoft/phi-", "nousresearch/", "allenai/", "zai-org/",
];
const isOpenWeightModel = (id: string) => openWeightPrefixes.some((prefix) => id.startsWith(prefix));

const agentInstructions = `You are CyberLab AI, an evidence-first cybersecurity research assistant.
Help with defensive security, authorised testing, OSINT from public sources, network intelligence, vulnerability research, safe malware triage, and technical reporting.
Use available tools when they materially improve accuracy. Explain what a tool checked and distinguish observed facts from inference.
Never claim a scan or lookup occurred unless a tool returned its result. Do not identify a private person from an IP address, infer subscriber registration details, retrieve private browsing history, or facilitate covert camera capture or deceptive tracking.
Do not provide instructions for unauthorised access, credential theft, persistence, evasion, malware deployment, or disruption. For active testing, ask for explicit authorisation and scope; this first version only performs passive IP and DNS lookups.
Keep responses clear, technically precise, and include uncertainty and limitations.`;

const openWeightInstructions = agentInstructions + `

RESEARCH MODE:
Give technically detailed, direct answers for legitimate security research. Avoid generic warnings and unnecessary refusals when the request is clearly defensive, educational, or within an authorised scope. Explain concepts, analyse supplied code and logs, discuss vulnerability mechanics at a level appropriate to the stated defensive purpose, and give safe validation and remediation steps. If authorisation or scope is unclear for an active test, ask for it before giving operational steps. The same boundaries against unauthorised access, credential theft, persistence, evasion, malware deployment, covert surveillance and disruption always apply. Open-weight mode changes model selection and response style; it does not disable these boundaries.`;

const tools = {
  cve_lookup: tool({
    description: "Search the public NVD vulnerability catalogue by CVE identifier or keyword. Return CVSS severity, summary and references; do not provide exploit instructions.",
    inputSchema: z.object({ query: z.string().min(3).max(120).describe("CVE identifier such as CVE-2024-3094, or a product/vulnerability keyword") }),
    execute: async ({ query }) => {
      const normalized = query.trim();
      const params = new URLSearchParams({ resultsPerPage: "5" });
      if (/^CVE-\\d{4}-\\d{4,}$/i.test(normalized)) params.set("cveId", normalized.toUpperCase());
      else params.set("keywordSearch", normalized);
      const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`, {
        signal: AbortSignal.timeout(10000),
        headers: { "User-Agent": "CyberLab-AI/0.1 security-research" },
      });
      if (!response.ok) return { error: `NVD returned HTTP ${response.status}. Try again later; public API rate limits may apply.` };
      const data = await response.json();
      const findings = (data.vulnerabilities ?? []).map((entry: any) => {
        const cve = entry.cve;
        const description = cve.descriptions?.find((item: any) => item.lang === "en")?.value ?? "No English summary available.";
        const metric = cve.metrics?.cvssMetricV40?.[0]?.cvssData ?? cve.metrics?.cvssMetricV31?.[0]?.cvssData ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData ?? cve.metrics?.cvssMetricV2?.[0]?.cvssData;
        return {
          id: cve.id,
          published: cve.published,
          lastModified: cve.lastModified,
          status: cve.vulnStatus,
          description,
          cvss: metric ? { version: metric.version, score: metric.baseScore, severity: metric.baseSeverity, vector: metric.vectorString } : null,
          references: (cve.references ?? []).slice(0, 4).map((ref: any) => ref.url),
        };
      });
      return { query: normalized, totalResults: data.totalResults ?? findings.length, results: findings, source: "NIST National Vulnerability Database", note: "Verify applicability against the affected product version and vendor advisories. A CVE match alone does not prove a system is vulnerable." };
    },
  }),
  reverse_dns: tool({
    description: "Resolve PTR records for a public or private IP address. This is passive DNS resolution and does not identify an individual.",
    inputSchema: z.object({ ip: z.string().min(3).max(64).describe("IPv4 or IPv6 address") }),
    execute: async ({ ip }) => {
      if (!isIP(ip)) return { error: "Enter a valid IPv4 or IPv6 address." };
      try {
        return { ip, hostnames: await reverse(ip), source: "System reverse-DNS resolver" };
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        return { ip, hostnames: [], result: code === "ENOTFOUND" || code === "ENODATA" ? "No PTR record found." : "Reverse DNS lookup failed.", code };
      }
    },
  }),
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
    const agentMode = body.agentMode === "open-weight" ? "open-weight" : "standard";
    const history = Array.isArray(body.history)
      ? body.history.slice(-12).flatMap((entry: unknown) => {
          if (!entry || typeof entry !== "object") return [];
          const item = entry as { role?: unknown; content?: unknown };
          if ((item.role === "user" || item.role === "assistant") && typeof item.content === "string" && item.content.length <= 8000) {
            return [{ role: item.role, content: item.content }];
          }
          return [];
        })
      : [];
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
      system: agentMode === "open-weight" ? openWeightInstructions : agentInstructions,
      messages: [...history, { role: "user" as const, content: prompt }],
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