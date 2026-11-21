import { z } from "zod";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const actionSchema = z.enum([
  "desktop.browser.inspect",
  "kali.health",
  "kali.tools.inventory",
  "kali.ollama.models",
  "kali.tool.run",
]);

const bodySchema = z.object({
  deviceId: z.string().min(1).max(80),
  action: actionSchema,
  payload: z.record(z.string(), z.unknown()).default({}),
  approvalReference: z.string().trim().min(3).max(160),
  operatorApproved: z.literal(true),
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
  return data.user;
}

export async function POST(request: Request) {
  try {
    await requireUser(request);
    const raw = await request.text();
    if (raw.length > 16_384) return Response.json({ error: "Request body is too large." }, { status: 413 });
    let parsedJson: unknown;
    try { parsedJson = JSON.parse(raw); }
    catch { return Response.json({ error: "A valid JSON body is required." }, { status: 400 }); }
    const parsed = bodySchema.safeParse(parsedJson);
    if (!parsed.success) return Response.json({ error: "Provide a paired device, supported action, approval reference and explicit operator approval." }, { status: 400 });

    const config = gatewayConfig();
    const response = await fetch(config.url + "/v1/jobs", {
      method: "POST",
      headers: { Authorization: "Bearer " + config.token, "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: parsed.data.deviceId,
        action: parsed.data.action,
        payload: parsed.data.payload,
        approval_reference: parsed.data.approvalReference,
        operator_approved: parsed.data.operatorApproved,
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    const result = await response.json().catch(() => ({}));
    return Response.json(result, { status: response.status, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Relay job creation failed.";
    const status = message === "Authentication required." ? 401 : message === "Cross-origin relay requests are blocked." ? 403 : 503;
    return Response.json({ error: message }, { status });
  }
}

export async function GET(request: Request) {
  try {
    await requireUser(request);
    const config = gatewayConfig();
    const query = new URL(request.url).searchParams;
    const deviceId = query.get("deviceId");
    const params = new URLSearchParams();
    if (deviceId) params.set("device_id", deviceId.slice(0, 80));
    params.set("limit", "100");
    const response = await fetch(config.url + "/v1/jobs?" + params.toString(), {
      headers: { Authorization: "Bearer " + config.token },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    const result = await response.json().catch(() => ({}));
    return Response.json(result, { status: response.status, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Relay job lookup failed.";
    const status = message === "Authentication required." ? 401 : message === "Cross-origin relay requests are blocked." ? 403 : 503;
    return Response.json({ error: message }, { status });
  }
}
