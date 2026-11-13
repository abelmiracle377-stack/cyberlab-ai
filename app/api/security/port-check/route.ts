import { isIP } from "node:net";
import { connect } from "node:net";
import { lookup } from "node:dns/promises";

export const runtime = "nodejs";
export const maxDuration = 30;

const ALLOWED_PORTS = new Set([21, 22, 80, 443, 3000, 5000, 8000, 8080, 8443]);
const HOST_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function isPublicIPv4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b, c] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function checkTcp(ip: string, port: number): Promise<"open" | "closed-or-filtered"> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: "open" | "closed-or-filtered") => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const socket = connect({ host: ip, port, family: 4 });
    socket.setTimeout(1400);
    socket.once("connect", () => finish("open"));
    socket.once("timeout", () => finish("closed-or-filtered"));
    socket.once("error", () => finish("closed-or-filtered"));
  });
}

export async function POST(request: Request) {
  let body: unknown;
  try { body = await request.json(); }
  catch { return Response.json({ error: "Invalid JSON request." }, { status: 400 }); }

  const input = body && typeof body === "object" ? body as Record<string, unknown> : {};
  const target = typeof input.target === "string" ? input.target.trim().toLowerCase().replace(/\.$/, "") : "";
  const confirmationTarget = typeof input.confirmationTarget === "string" ? input.confirmationTarget.trim().toLowerCase().replace(/\.$/, "") : "";
  const reference = typeof input.authorizationReference === "string" ? input.authorizationReference.trim() : "";
  const confirmed = input.authorizationConfirmed === true;
  const portsRaw = Array.isArray(input.ports) ? input.ports : [];
  const ports = [...new Set(portsRaw.filter((port): port is number => Number.isInteger(port) && ALLOWED_PORTS.has(port)))];

  if (!confirmed || !reference || reference.length > 160 || !target || confirmationTarget !== target) {
    return Response.json({ error: "Confirm ownership or written authorisation, enter an approval/reference note, and retype the exact target." }, { status: 400 });
  }
  if (isIP(target) !== 4 && !HOST_PATTERN.test(target)) {
    return Response.json({ error: "Enter a public IPv4 address or a valid fully-qualified domain name." }, { status: 400 });
  }
  if (!ports.length || ports.length > 5 || ports.length !== portsRaw.length) {
    return Response.json({ error: "Choose between one and five supported TCP ports. Allowed ports: 21, 22, 80, 443, 3000, 5000, 8000, 8080, 8443." }, { status: 400 });
  }

  try {
    const addresses = isIP(target) === 4 ? [{ address: target, family: 4 }] : await lookup(target, { all: true, verbatim: true });
    const ipv4 = addresses.filter((item) => item.family === 4 && isPublicIPv4(item.address));
    if (!ipv4.length || ipv4.length !== addresses.filter((item) => item.family === 4).length) {
      return Response.json({ error: "Target must resolve only to public IPv4 addresses. Private, loopback, link-local, reserved and mixed public/private DNS answers are blocked." }, { status: 400 });
    }
    const ip = ipv4[0].address;
    const results: { port: number; status: string; service: string }[] = [];
    const serviceNames: Record<number, string> = { 21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3000: "Web application", 5000: "Web application", 8000: "Web application", 8080: "HTTP alternate", 8443: "HTTPS alternate" };
    for (let i = 0; i < ports.length; i += 2) {
      const batch = ports.slice(i, i + 2);
      const states = await Promise.all(batch.map((port) => checkTcp(ip, port)));
      batch.forEach((port, index) => results.push({ port, status: states[index], service: serviceNames[port] }));
    }
    return Response.json({
      target,
      resolvedAddress: ip,
      checkedAt: new Date().toISOString(),
      method: "TCP connection check",
      results: results.sort((a, b) => a.port - b.port),
      note: "This is a low-volume TCP reachability check from CyberLab's Vercel runtime. 'Closed or filtered' cannot distinguish a closed port from firewall filtering. It is not Nmap, a vulnerability scan, banner grab, or proof of security. For full Nmap assessment, use the Kali companion on an explicitly authorised network.",
    }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "DNS resolution or TCP checks failed. Confirm the target is reachable and try again." }, { status: 502 });
  }
}
