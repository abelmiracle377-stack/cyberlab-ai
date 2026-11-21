import { randomUUID } from "node:crypto";
import { adminGate } from "@/lib/billing/admin";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

type RouteContext = { params: Promise<{ path: string[] }> };

function config() {
  const url = process.env.CYBERLAB_GATEWAY_URL?.replace(/\/$/, "");
  const token = process.env.CYBERLAB_GATEWAY_OWNER_TOKEN;
  if (!url || !url.startsWith("https://") || !token) throw new Error("Secure CyberLab gateway is not configured.");
  return { url, token };
}

function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

async function gatewayFetch(url: string, token: string, init: RequestInit = {}) {
  const response = await fetch(url, {
    ...init,
    headers: { Authorization: "Bearer " + token, ...(init.headers || {}) },
    cache: "no-store",
    signal: AbortSignal.timeout(10000),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : typeof data.error === "string" ? data.error : "Secure Kali relay request failed (" + response.status + ").");
  return data;
}

async function proxy(request: Request, context: RouteContext) {
  try {
    if (!sameOrigin(request)) return Response.json({ error: "Cross-origin Kali relay requests are blocked." }, { status: 403 });
    const gate = await adminGate();
    if (gate.error) return gate.error;
    const { url, token } = config();
    const { path: segments } = await context.params;
    if (!Array.isArray(segments) || !segments.length) return Response.json({ error: "A Kali bridge endpoint is required." }, { status: 400 });
    const method = request.method;
    if (method !== "GET" && method !== "POST") return Response.json({ error: "Only GET and POST bridge requests are supported." }, { status: 405 });
    const bridgePath = "/" + segments.map(segment => encodeURIComponent(segment)).join("/") + new URL(request.url).search;
    let body: Record<string, unknown> | undefined;
    if (method === "POST") {
      const raw = await request.text();
      if (raw.length > 32768) return Response.json({ error: "Kali bridge request body exceeds 32 KB." }, { status: 413 });
      try { body = JSON.parse(raw); } catch { return Response.json({ error: "Kali bridge requests must use a JSON object body." }, { status: 400 }); }
      if (!body || Array.isArray(body) || typeof body !== "object") return Response.json({ error: "Kali bridge requests must use a JSON object body." }, { status: 400 });
    }

    const devicesData = await gatewayFetch(url + "/v1/devices", token);
    const devices = Array.isArray(devicesData.devices) ? devicesData.devices : [];
    const online = devices.filter((device: any) =>
      device.platform === "kali" && device.status === "online" &&
      device.revoked !== true && device.permissions?.job_execution === true
    );
    if (online.length === 0) {
      return Response.json({ error: "No online Kali companion with execution permission is paired. Start the relay worker on your separate Kali machine and grant CyberLab execution jobs during pairing." }, { status: 409 });
    }
    if (online.length > 1) {
      return Response.json({ error: "More than one Kali companion is online. Select one device in the Execution Relay before sending bridge tasks.", devices: online.map((device: any) => ({ device_id: device.device_id, name: device.name })) }, { status: 409 });
    }
    const device = online[0];
    const approvalReference = "UI-" + Date.now() + "-" + randomUUID().slice(0, 8);
    const queued = await gatewayFetch(url + "/v1/jobs", token, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: device.device_id,
        action: "kali.bridge.request",
        payload: { method, path: bridgePath, ...(body ? { body } : {}) },
        approval_reference: approvalReference,
        operator_approved: true,
      }),
    });
    const jobId = queued.job_id;
    if (typeof jobId !== "string") throw new Error("Relay did not return an execution job ID.");

    const deadline = Date.now() + 52000;
    while (Date.now() < deadline) {
      const jobsData = await gatewayFetch(url + "/v1/jobs?device_id=" + encodeURIComponent(device.device_id) + "&limit=250", token);
      const job = (jobsData.jobs || []).find((item: any) => item.job_id === jobId);
      if (job?.status === "completed") {
        const result = job.result || {};
        const status = Number.isInteger(result.bridge_status) ? result.bridge_status : 502;
        const responseBody = result.bridge_body && typeof result.bridge_body === "object" ? result.bridge_body : { error: "Kali bridge returned an invalid response." };
        return Response.json(responseBody, { status, headers: { "Cache-Control": "no-store", "X-CyberLab-Device": device.device_id } });
      }
      if (job?.status === "failed" || job?.status === "expired") {
        return Response.json({ error: job.error || "Kali companion could not complete the bridge request.", job_id: jobId, status: job.status }, { status: 502 });
      }
      await new Promise(resolve => setTimeout(resolve, 900));
    }
    return Response.json({ error: "Kali task is still running. The companion has the job; refresh its task status before retrying to avoid duplicate execution.", job_id: jobId, device_id: device.device_id, status: "running" }, { status: 504 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Kali bridge request failed.";
    const status = message === "Authentication required." ? 401 : message.includes("not configured") ? 503 : 502;
    return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
  }
}

export async function GET(request: Request, context: RouteContext) {
  return proxy(request, context);
}

export async function POST(request: Request, context: RouteContext) {
  return proxy(request, context);
}
