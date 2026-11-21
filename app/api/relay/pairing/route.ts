import { z } from "zod";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const pairingSchema = z.object({
  deviceName: z.string().trim().min(1).max(80),
  platform: z.enum(["kali", "desktop-browser"]),
}).strict();

function gatewayConfig() {
  const url = process.env.CYBERLAB_GATEWAY_URL?.replace(/\/$/, "");
  const token = process.env.CYBERLAB_GATEWAY_OWNER_TOKEN;
  if (!url || !url.startsWith("https://") || !token) throw new Error("Secure CyberLab gateway is not configured.");
  return { url, token };
}

async function requireUser(request: Request) {
  const expectedOrigin = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  if (origin && origin !== expectedOrigin) throw new Error("Cross-origin relay requests are blocked.");
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getUser();
  if (error || !data.user) throw new Error("Authentication required.");
}

export async function GET(request: Request) {
  try {
    await requireUser(request);
    const config = gatewayConfig();
    const response = await fetch(config.url + "/v1/devices", {
      headers: { Authorization: "Bearer " + config.token },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    const result = await response.json().catch(() => ({}));
    return Response.json(result, { status: response.status, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Device lookup failed.";
    return Response.json({ error: message }, { status: message === "Authentication required." ? 401 : 503 });
  }
}

export async function POST(request: Request) {
  try {
    await requireUser(request);
    const raw = await request.text();
    if (raw.length > 4096) return Response.json({ error: "Request body is too large." }, { status: 413 });
    let value: unknown;
    try { value = JSON.parse(raw); } catch { return Response.json({ error: "A valid JSON body is required." }, { status: 400 }); }
    const parsed = pairingSchema.safeParse(value);
    if (!parsed.success) return Response.json({ error: "Provide a device name and platform: kali or desktop-browser." }, { status: 400 });
    const config = gatewayConfig();
    const response = await fetch(config.url + "/v1/pairing", {
      method: "POST",
      headers: { Authorization: "Bearer " + config.token, "Content-Type": "application/json" },
      body: JSON.stringify({ device_name: parsed.data.deviceName, platform: parsed.data.platform }),
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    const result = await response.json().catch(() => ({}));
    return Response.json(result, { status: response.status, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Device pairing failed.";
    return Response.json({ error: message }, { status: message === "Authentication required." ? 401 : 503 });
  }
}
