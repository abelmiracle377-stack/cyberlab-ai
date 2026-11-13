import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { createHash } from "node:crypto";

export const runtime = "nodejs";
export const maxDuration = 20;
const MAX_BYTES = 4 * 1024 * 1024;
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$/i;

function publicIPv4(value: string) {
  const p = value.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a,b,c] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0) || a === 255) return false;
  return true;
}
function publicIPv6(value: string) {
  const v = value.toLowerCase();
  return !v.startsWith("::") && !v.startsWith("fc") && !v.startsWith("fd") && !v.startsWith("fe8") && !v.startsWith("fe9") && !v.startsWith("fea") && !v.startsWith("feb") && !v.startsWith("ff") && !v.startsWith("2001:db8");
}
async function validateHost(host: string) {
  const ip = isIP(host);
  if (ip === 4) { if (!publicIPv4(host)) throw new Error("Private, loopback, reserved or non-public IPv4 targets are blocked."); return; }
  if (ip === 6) { if (!publicIPv6(host)) throw new Error("Non-public IPv6 targets are blocked."); return; }
  if (!HOST.test(host)) throw new Error("Enter a valid public website hostname.");
  const records = await lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some(r => r.family === 4 ? !publicIPv4(r.address) : !publicIPv6(r.address))) throw new Error("Hostname must resolve only to public IP addresses. Private or mixed DNS answers are blocked.");
}
function safeUrl(raw: string) {
  let url: URL;
  try { url = new URL(raw.includes("://") ? raw : "https://" + raw); } catch { throw new Error("Enter a valid website URL."); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.port && !["80","443"].includes(url.port)) throw new Error("Only public HTTP/HTTPS URLs on standard ports are supported.");
  url.hash = "";
  return url;
}
async function fetchPublic(raw: string) {
  let url = safeUrl(raw);
  for (let hop = 0; hop <= 3; hop++) {
    await validateHost(url.hostname);
    const response = await fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(12000), headers: { "User-Agent": "CyberLab-AI-Security-Review/1.0", Accept: "text/html,application/octet-stream,*/*;q=0.5" } });
    if ([301,302,303,307,308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location || hop === 3) throw new Error("Redirect limit reached.");
      const next = new URL(location, url);
      if (next.protocol !== "https:" && next.protocol !== "http:") throw new Error("Unsupported redirect scheme.");
      url = safeUrl(next.toString());
      continue;
    }
    return { response, url };
  }
  throw new Error("Could not safely follow website redirects.");
}
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const raw = typeof body.url === "string" ? body.url.trim() : "";
    if (!raw || raw.length > 2048) return Response.json({ error: "Enter a URL up to 2,048 characters." }, { status: 400 });
    const { response, url } = await fetchPublic(raw);
    const contentType = response.headers.get("content-type") || "unknown";
    const length = Number(response.headers.get("content-length") || 0);
    if (length > MAX_BYTES) return Response.json({ error: "Response exceeds the 4 MB inspection limit." }, { status: 413 });
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_BYTES) { await reader.cancel(); throw new Error("Downloaded response exceeds the 4 MB inspection limit."); }
        chunks.push(value);
      }
    }
    const bytes = Buffer.concat(chunks.map(chunk => Buffer.from(chunk)));
    const text = bytes.toString("utf8");
    const headers = response.headers;
    const securityHeaders = [
      ["Strict-Transport-Security","strict-transport-security","Use HSTS on HTTPS sites to reduce downgrade risk."],
      ["Content-Security-Policy","content-security-policy","Define a restrictive Content Security Policy."],
      ["X-Content-Type-Options","x-content-type-options","Set X-Content-Type-Options: nosniff."],
      ["Referrer-Policy","referrer-policy","Set an explicit Referrer-Policy."],
      ["Permissions-Policy","permissions-policy","Restrict browser features not required by the application."],
      ["X-Frame-Options","x-frame-options","Use frame-ancestors in CSP or X-Frame-Options to reduce clickjacking risk."]
    ] as const;
    const findings = securityHeaders.map(([name,key,advice]) => ({ name, present: headers.has(key), value: headers.get(key), recommendation: advice }))
      .filter(item => !item.present);
    const cookies = headers.getSetCookie?.() || [];
    const cookieFindings = cookies.flatMap((cookie,index) => [
      ...(!/;\\s*secure(?:;|$)/i.test(cookie) && url.protocol === "https:" ? [{ name: "Cookie " + (index+1) + " missing Secure", severity: "review" }] : []),
      ...(!/;\\s*httponly(?:;|$)/i.test(cookie) ? [{ name: "Cookie " + (index+1) + " missing HttpOnly", severity: "review" }] : []),
      ...(!/;\\s*samesite=/i.test(cookie) ? [{ name: "Cookie " + (index+1) + " missing SameSite", severity: "review" }] : [])
    ]);
    const html = /text\\/html|application\\/xhtml/i.test(contentType);
    const externalScripts = html ? [...text.matchAll(/<script[^>]+src=["']([^"']+)/gi)].slice(0,30).map(m => m[1]) : [];
    return Response.json({
      requestedUrl: raw, finalUrl: url.toString(), status: response.status, contentType, bytes: total,
      https: url.protocol === "https:", server: headers.get("server"), poweredBy: headers.get("x-powered-by"),
      securityHeaders: securityHeaders.map(([name,key]) => ({ name, present: headers.has(key), value: headers.get(key) })),
      findings: [...findings.map(item => ({ name: item.name + " missing", severity: "review", recommendation: item.recommendation })), ...cookieFindings],
      cookiesObserved: cookies.length, externalScriptReferences: externalScripts,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      note: "One bounded HTTP GET was performed. This is a passive configuration review, not a vulnerability scan or penetration test. Missing headers are review opportunities, not proof of exploitable vulnerabilities. Response body was not executed or stored.",
      fetchedAt: new Date().toISOString()
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "Website review failed." }, { status: 400 });
  }
}
