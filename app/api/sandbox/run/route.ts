import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
export const maxDuration = 30;

export async function POST(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return NextResponse.json({ error: "Sign in to use the CyberLab sandbox." }, { status: 401 });

  const endpoint = process.env.CYBERLAB_SANDBOX_URL;
  const token = process.env.CYBERLAB_SANDBOX_TOKEN;
  if (!endpoint || !token) return NextResponse.json({ error: "The independent sandbox service is not connected yet. Configure CYBERLAB_SANDBOX_URL and CYBERLAB_SANDBOX_TOKEN on the CyberLab server." }, { status: 503 });

  let payload: unknown;
  try { payload = await request.json(); } catch { return NextResponse.json({ error: "Invalid JSON request." }, { status: 400 }); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return NextResponse.json({ error: "Request must be an object." }, { status: 400 });
  const data = payload as Record<string, unknown>;
  if (Object.keys(data).some(key => !["language", "source"].includes(key))) return NextResponse.json({ error: "Only language and source are accepted." }, { status: 400 });
  if (!["python", "javascript", "shell"].includes(String(data.language))) return NextResponse.json({ error: "Choose python, javascript or shell." }, { status: 400 });
  if (typeof data.source !== "string" || !data.source.trim() || new TextEncoder().encode(data.source).length > 48 * 1024) return NextResponse.json({ error: "Source must be non-empty text no larger than 48 KB." }, { status: 400 });

  try {
    const upstream = await fetch(new URL("/v1/run", endpoint), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ language: data.language, source: data.source }),
      cache: "no-store",
      signal: AbortSignal.timeout(25000),
    });
    const result = await upstream.json();
    return NextResponse.json(result, { status: upstream.status, headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "The independent sandbox service could not be reached." }, { status: 502 });
  }
}
