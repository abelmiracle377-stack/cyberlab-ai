export const runtime = "nodejs";

const MAX_BYTES = 2 * 1024 * 1024;

function attributes(tag: string) {
  const result: Record<string, string> = {};
  for (const match of tag.matchAll(/([a-zA-Z_:][\w:.-]*)\s*=\s*["']([^"']*)["']/g)) {
    result[match[1]] = match[2];
  }
  return result;
}

function tags(source: string, name: string) {
  return [...source.matchAll(new RegExp(`<${name}\\b[^>]*>`, "g"))].map((match) => match[0]);
}

export async function POST(request: Request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    return Response.json({ error: "Send the Nmap XML as JSON: { xml: string }." }, { status: 415 });
  }

  let body: unknown;
  try { body = await request.json(); } catch {
    return Response.json({ error: "Invalid JSON request." }, { status: 400 });
  }
  const xml = body && typeof body === "object" && "xml" in body ? (body as { xml?: unknown }).xml : null;
  if (typeof xml !== "string" || !xml.trim()) {
    return Response.json({ error: "Paste or upload an Nmap XML file first." }, { status: 400 });
  }
  if (Buffer.byteLength(xml, "utf8") > MAX_BYTES) {
    return Response.json({ error: "File is too large. Maximum size is 2 MB." }, { status: 413 });
  }
  if (!/<\?xml\b|<nmaprun\b/i.test(xml) || !/<\/nmaprun\s*>/i.test(xml)) {
    return Response.json({ error: "This does not look like a complete Nmap XML document." }, { status: 400 });
  }
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    return Response.json({ error: "DOCTYPE and entity declarations are not accepted." }, { status: 400 });
  }

  const hosts = [...xml.matchAll(/<host\b[^>]*>([\s\S]*?)<\/host>/gi)].map((hostMatch, index) => {
    const block = hostMatch[1];
    const statusTag = tags(block, "status")[0];
    const status = attributes(statusTag || "<status state=\"unknown\"/>").state || "unknown";
    const addresses = tags(block, "address").map((tag) => {
      const attr = attributes(tag);
      return { address: attr.addr || "", type: attr.addrtype || "unknown" };
    }).filter((item) => item.address);
    const hostnameTags = tags(block, "hostname");
    const hostnames = hostnameTags.map((tag) => attributes(tag).name).filter(Boolean);
    const portsBlock = block.match(/<ports\b[^>]*>([\s\S]*?)<\/ports>/i)?.[1] || "";
    const ports = [...portsBlock.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/gi)].map((portMatch) => {
      const portAttr = attributes(`<port ${portMatch[1]}>`);
      const portBody = portMatch[2];
      const stateTag = tags(portBody, "state")[0];
      const serviceTag = tags(portBody, "service")[0];
      const stateAttr = attributes(stateTag || "<state/>");
      const serviceAttr = attributes(serviceTag || "<service/>");
      return {
        protocol: portAttr.protocol || "unknown",
        port: Number(portAttr.portid),
        state: stateAttr.state || "unknown",
        reason: stateAttr.reason || "",
        reason_ttl: stateAttr.reason_ttl || null,
        service: serviceAttr.name || "unknown",
        product: serviceAttr.product || "",
        version: serviceAttr.version || "",
        extra_info: serviceAttr.extrainfo || "",
        tunnel: serviceAttr.tunnel || "",
        method: serviceAttr.method || "",
        confidence: serviceAttr.conf || null,
      };
    }).filter((item) => Number.isInteger(item.port) && item.port > 0 && item.port <= 65535);
    return { index: index + 1, status, status_reason: attributes(statusTag || "").reason || "", addresses, hostnames, ports };
  });

  const allPorts = hosts.flatMap((host) => host.ports);
  const states = ["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered", "unknown"];
  const openPorts = hosts.flatMap((host) => host.ports.filter((port) => port.state === "open").map((port) => ({ host: host.addresses[0]?.address || `Host ${host.index}`, ...port })));
  const scaninfo = tags(xml, "scaninfo").map((tag) => attributes(tag));
  const finishedTag = tags(xml.match(/<runstats\\b[^>]*>([\\s\\S]*?)<\\/runstats>/i)?.[1] || "", "finished")[0];
  const hostStatsTag = tags(xml.match(/<runstats\\b[^>]*>([\\s\\S]*?)<\\/runstats>/i)?.[1] || "", "hosts")[0];
  const completion = {
    finished: attributes(finishedTag || ""),
    hosts: attributes(hostStatsTag || ""),
    scanner: attributes(tags(xml, "nmaprun")[0] || "").scanner || "",
    version: attributes(tags(xml, "nmaprun")[0] || "").version || "",
    args: attributes(tags(xml, "nmaprun")[0] || "").args || "",
    start: attributes(tags(xml, "nmaprun")[0] || "").start || "",
  };
  return Response.json({
    summary: { hosts: hosts.length, up: hosts.filter((host) => host.status === "up").length, ports: allPorts.length, openPorts: openPorts.length, stateCounts: Object.fromEntries(states.map((state) => [state, allPorts.filter((port) => port.state === state).length])) },
    hosts, openPorts, scaninfo, completion,
    evidenceStatus: Object.keys(completion.finished).length ? "completed" : (hosts.length ? "partial" : "no_port_evidence"),
    source: "User-supplied Nmap XML",
    note: "This tool parses an existing report only. It does not run Nmap, contact hosts, validate authorisation, or determine exploitability. Missing evidence is not interpreted as zero findings.",
  });
}
