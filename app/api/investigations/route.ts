import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const statuses = ["open", "investigating", "contained", "resolved", "closed"] as const;
const severities = ["informational", "low", "medium", "high", "critical"] as const;

async function userClient() {
  const supabase = await createClient();
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return { error: NextResponse.json({ error: "Sign in is required to access persistent investigation cases." }, { status: 401 }) };
  return { supabase, user };
}

export async function GET() {
  try {
    const auth = await userClient();
    if ("error" in auth) return auth.error;
    const { data, error } = await auth.supabase
      .from("investigation_cases")
      .select("id,title,status,severity,summary,scope,tags,created_at,updated_at,investigation_events(id,source,event_type,severity,title,details,occurred_at,created_at)")
      .order("updated_at", { ascending: false })
      .limit(100);
    if (error) return NextResponse.json({ error: error.message, hint: "Apply the investigation_cases Supabase migration first." }, { status: 503 });
    return NextResponse.json({ cases: data || [] }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Persistent case storage is unavailable. Configure Supabase and apply the migration." }, { status: 503 });
  }
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON request." }, { status: 400 }); }
  if (!body || typeof body !== "object") return NextResponse.json({ error: "Invalid case payload." }, { status: 400 });
  const value = body as Record<string, unknown>;
  const title = typeof value.title === "string" ? value.title.trim() : "";
  const summary = typeof value.summary === "string" ? value.summary.trim() : "";
  const scope = typeof value.scope === "string" ? value.scope.trim() : "";
  const severity = typeof value.severity === "string" ? value.severity : "medium";
  if (!title || title.length > 160 || summary.length > 5000 || scope.length > 3000 || !severities.includes(severity as typeof severities[number])) {
    return NextResponse.json({ error: "Check title (1–160 chars), summary (max 5,000), scope (max 3,000) and severity." }, { status: 400 });
  }
  try {
    const auth = await userClient();
    if ("error" in auth) return auth.error;
    const { data, error } = await auth.supabase.from("investigation_cases").insert({
      user_id: auth.user.id, title, summary, scope, severity,
      tags: Array.isArray(value.tags) ? value.tags.filter((x): x is string => typeof x === "string").slice(0, 12) : []
    }).select("id,title,status,severity,summary,scope,tags,created_at,updated_at").single();
    if (error) return NextResponse.json({ error: error.message, hint: "Apply the investigation_cases Supabase migration first." }, { status: 503 });
    return NextResponse.json({ case: data }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Persistent case storage is unavailable. Configure Supabase and apply the migration." }, { status: 503 });
  }
}

export async function PATCH(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON request." }, { status: 400 }); }
  if (!body || typeof body !== "object") return NextResponse.json({ error: "Invalid update." }, { status: 400 });
  const value = body as Record<string, unknown>;
  if (typeof value.id !== "string" || value.id.length > 64) return NextResponse.json({ error: "Case id is required." }, { status: 400 });
  const patch: Record<string, unknown> = {};
  if (typeof value.status === "string" && statuses.includes(value.status as typeof statuses[number])) patch.status = value.status;
  if (typeof value.severity === "string" && severities.includes(value.severity as typeof severities[number])) patch.severity = value.severity;
  if (typeof value.title === "string" && value.title.trim() && value.title.length <= 160) patch.title = value.title.trim();
  if (typeof value.summary === "string" && value.summary.length <= 5000) patch.summary = value.summary;
  if (typeof value.scope === "string" && value.scope.length <= 3000) patch.scope = value.scope;
  if (!Object.keys(patch).length) return NextResponse.json({ error: "No valid fields to update." }, { status: 400 });
  try {
    const auth = await userClient();
    if ("error" in auth) return auth.error;
    const { data, error } = await auth.supabase.from("investigation_cases").update(patch).eq("id", value.id).select("id,title,status,severity,summary,scope,tags,created_at,updated_at").single();
    if (error) return NextResponse.json({ error: error.message }, { status: 400 });
    return NextResponse.json({ case: data });
  } catch {
    return NextResponse.json({ error: "Persistent case storage is unavailable." }, { status: 503 });
  }
}
