import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ jobId: string }> }) {
  try {
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(request.url).origin) {
      return Response.json({ error: "Cross-origin relay requests are blocked." }, { status: 403 });
    }
    const supabase = await createClient();
    const { data, error } = await supabase.auth.getUser();
    if (error || !data.user) return Response.json({ error: "Authentication required." }, { status: 401 });
    const { jobId } = await context.params;
    if (!/^[0-9a-f-]{36}$/i.test(jobId)) return Response.json({ error: "Invalid job identifier." }, { status: 400 });
    const url = process.env.CYBERLAB_GATEWAY_URL?.replace(/\/$/, "");
    const token = process.env.CYBERLAB_GATEWAY_OWNER_TOKEN;
    if (!url || !url.startsWith("https://") || !token) {
      return Response.json({ error: "Secure CyberLab gateway is not configured." }, { status: 503 });
    }
    const response = await fetch(url + "/v1/jobs/" + encodeURIComponent(jobId) + "/cancel", {
      method: "POST",
      headers: { Authorization: "Bearer " + token },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    const result = await response.json().catch(() => ({}));
    return Response.json(result, { status: response.status, headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Could not cancel the relay job." }, { status: 503 });
  }
}
