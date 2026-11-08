export const runtime = "nodejs";
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
function validDomain(value: unknown): value is string {
  return typeof value === "string" && DOMAIN_PATTERN.test(value) && !/^\d+(?:\.\d+){3}$/.test(value);
}
export async function POST(request: Request) {
  let body: unknown;
  try { body = await request.json(); } catch { return Response.json({ error: "Invalid JSON request." }, { status: 400 }); }
  const raw = body && typeof body === "object" && "domain" in body ? (body as { domain?: unknown }).domain : null;
  const domain = typeof raw === "string" ? raw.trim().toLowerCase().replace(/\.$/, "") : "";
  if (!validDomain(domain)) return Response.json({ error: "Enter a valid public domain name, such as example.com." }, { status: 400 });
  const headers = { Accept: "application/rdap+json, application/json", "User-Agent": "CyberLabAI-OSINT/1.0 (public research)" };
  const [rdapResult, certResult] = await Promise.allSettled([
    fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { headers, signal: AbortSignal.timeout(9000), cache: "no-store" }),
    fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { headers: { "User-Agent": headers["User-Agent"] }, signal: AbortSignal.timeout(9000), cache: "no-store" }),
  ]);
  let registration: Record<string, unknown> | null = null;
  let registrationError = "";
  if (rdapResult.status === "fulfilled" && rdapResult.value.ok) {
    try {
      const data = await rdapResult.value.json();
      const events = Array.isArray(data.events) ? data.events.map((event: any) => ({ action: String(event.eventAction || ""), date: String(event.eventDate || "") })).filter((event: any) => event.action && event.date) : [];
      const nameservers = Array.isArray(data.nameservers) ? data.nameservers.map((ns: any) => String(ns.ldhName || "")).filter(Boolean).slice(0, 30) : [];
      const registrar = Array.isArray(data.entities) ? data.entities.find((entity: any) => Array.isArray(entity.roles) && entity.roles.includes("registrar")) : null;
      const registrarName = Array.isArray(registrar?.vcardArray?.[1]) ? registrar.vcardArray[1].find((item: any) => item?.[0] === "fn")?.[3] : null;
      registration = { domain: String(data.ldhName || domain), status: Array.isArray(data.status) ? data.status.map(String).slice(0, 20) : [], events: events.slice(0, 15), nameservers, registrar: typeof registrarName === "string" ? registrarName : null };
    } catch { registrationError = "The registration service returned unreadable data."; }
  } else registrationError = rdapResult.status === "rejected" ? "Registration lookup timed out or was unavailable." : `Registration lookup returned HTTP ${rdapResult.value.status}.`;
  let certificates: { commonName: string; issuer: string; notBefore: string; notAfter: string }[] = [];
  let certificateError = "";
  if (certResult.status === "fulfilled" && certResult.value.ok) {
    try {
      const text = await certResult.value.text();
      if (text.length > 1_500_000) throw new Error("Response too large");
      const rows = JSON.parse(text);
      if (Array.isArray(rows)) {
        const seen = new Set<string>();
        certificates = rows.map((row: any) => ({ commonName: String(row.common_name || ""), issuer: String(row.issuer_name || ""), notBefore: String(row.not_before || ""), notAfter: String(row.not_after || "") })).filter((row: any) => {
          const names = row.commonName.toLowerCase().split(/[\s,]+/).map((name: string) => name.replace(/^\*\./, ""));
          const matches = names.some((name: string) => name === domain || name.endsWith(`.${domain}`));
          if (!matches || seen.has(row.commonName)) return false;
          seen.add(row.commonName); return true;
        }).slice(0, 40);
      }
    } catch { certificateError = "Certificate transparency data could not be parsed."; }
  } else certificateError = certResult.status === "rejected" ? "Certificate transparency lookup timed out or was unavailable." : `Certificate lookup returned HTTP ${certResult.value.status}.`;
  return Response.json({
    domain, registration, certificates, errors: [registrationError, certificateError].filter(Boolean),
    sources: [{ name: "RDAP", url: "https://rdap.org/", description: "Public domain registration metadata" }, { name: "crt.sh", url: "https://crt.sh/", description: "Public certificate transparency records" }],
    note: "Passive public-source research only. Certificate names and registration metadata are clues, not proof of ownership, control, vulnerability or a person's identity. Results may be incomplete or delayed.",
  });
}
