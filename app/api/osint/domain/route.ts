export const runtime = "nodejs";

const timeout = (ms: number) => AbortSignal.timeout(ms);
const domainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function cleanDomain(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const input = value.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/\.$/, "");
  if (!domainPattern.test(input) || input.includes("..") || input === "localhost") return null;
  return input;
}

function eventDate(events: unknown, action: string): string | null {
  if (!Array.isArray(events)) return null;
  const event = events.find((item) => item && typeof item === "object" && (item as { eventAction?: string }).eventAction === action) as { eventDate?: string } | undefined;
  return event?.eventDate || null;
}

export async function GET(request: Request) {
  const domain = cleanDomain(new URL(request.url).searchParams.get("domain"));
  if (!domain) return Response.json({ error: "Enter a valid public domain, such as example.com." }, { status: 400 });

  const rdapPromise = fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { Accept: "application/rdap+json" }, signal: timeout(8000), cache: "no-store",
  }).then(async (response) => {
    if (!response.ok) throw new Error(`RDAP returned HTTP ${response.status}`);
    const data = await response.json();
    const nameservers = Array.isArray(data.nameservers) ? data.nameservers.map((item: { ldhName?: string }) => item.ldhName).filter(Boolean).slice(0, 20) : [];
    const statuses = Array.isArray(data.status) ? data.status.slice(0, 20) : [];
    const registrarEntity = Array.isArray(data.entities) ? data.entities.find((entity: { roles?: string[] }) => entity.roles?.includes("registrar")) : null;
    const registrar = registrarEntity?.vcardArray?.[1]?.find((field: unknown[]) => field[0] === "fn")?.[3] || null;
    return {
      available: true,
      handle: typeof data.handle === "string" ? data.handle : null,
      registrar: typeof registrar === "string" ? registrar : null,
      created: eventDate(data.events, "registration"),
      updated: eventDate(data.events, "last changed"),
      expires: eventDate(data.events, "expiration"),
      nameservers,
      statuses,
    };
  }).catch((error) => ({ available: false, error: error instanceof Error ? error.message : "RDAP lookup failed" }));

  const certPromise = fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
    headers: { Accept: "application/json" }, signal: timeout(10000), cache: "no-store",
  }).then(async (response) => {
    if (!response.ok) throw new Error(`Certificate source returned HTTP ${response.status}`);
    const data: unknown = await response.json();
    if (!Array.isArray(data)) throw new Error("Certificate source returned an unexpected response");
    const names = new Set<string>();
    for (const row of data.slice(0, 2000)) {
      if (row && typeof row === "object" && "name_value" in row && typeof row.name_value === "string") {
        for (const candidate of row.name_value.split(/\r?\n/)) {
          const name = candidate.trim().toLowerCase().replace(/^\*\./, "");
          if ((name === domain || name.endsWith(`.${domain}`)) && domainPattern.test(name)) names.add(name);
        }
      }
    }
    return { available: true, names: [...names].sort().slice(0, 100), totalUnique: names.size };
  }).catch((error) => ({ available: false, error: error instanceof Error ? error.message : "Certificate lookup failed", names: [], totalUnique: 0 }));

  const [rdap, certificates] = await Promise.all([rdapPromise, certPromise]);
  return Response.json({
    domain,
    rdap,
    certificates,
    sources: ["Public RDAP records", "Certificate Transparency logs via crt.sh"],
    privacy: "Registrant personal contact details are intentionally not collected or displayed.",
    disclaimer: "Public records can be incomplete or delayed. Certificate names indicate observed certificates, not proof that a service is currently online or vulnerable.",
  }, { headers: { "Cache-Control": "public, s-maxage=300, stale-while-revalidate=600" } });
}
