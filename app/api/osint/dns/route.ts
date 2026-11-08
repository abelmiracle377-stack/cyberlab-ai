import { resolve4, resolve6, resolveMx, resolveNs, resolveTxt } from "node:dns/promises";

export const runtime = "nodejs";

const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$/i;

export async function POST(request: Request) {
  let body: unknown;
  try { body = await request.json(); }
  catch { return Response.json({ error: "Invalid JSON request." }, { status: 400 }); }

  const raw = body && typeof body === "object" && "domain" in body ? (body as { domain?: unknown }).domain : null;
  const domain = typeof raw === "string" ? raw.trim().toLowerCase().replace(/\\.$/, "") : "";
  if (!DOMAIN_PATTERN.test(domain) || /^\\d+(?:\\.\\d+){3}$/.test(domain)) {
    return Response.json({ error: "Enter a valid domain name, such as example.com." }, { status: 400 });
  }

  const lookup = async (fn: (name: string) => Promise<unknown>) => {
    try { return await fn(domain); }
    catch (cause) {
      const code = (cause as NodeJS.ErrnoException).code;
      if (code === "ENODATA" || code === "ENOTFOUND") return [];
      return { error: code || "DNS_LOOKUP_FAILED" };
    }
  };

  const [a, aaaa, mx, ns, txt] = await Promise.all([
    lookup(resolve4), lookup(resolve6), lookup(resolveMx), lookup(resolveNs), lookup(resolveTxt),
  ]);

  return Response.json({
    domain,
    records: { A: a, AAAA: aaaa, MX: mx, NS: ns, TXT: txt },
    source: "DNS resolver",
    note: "DNS records are public technical metadata. They can change, be incomplete, or be affected by DNS providers and caching.",
  }, { headers: { "Cache-Control": "no-store" } });
}
