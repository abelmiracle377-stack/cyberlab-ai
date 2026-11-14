import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const levels = ["informational", "low", "medium", "high", "critical"] as const;

export async function POST(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid case id." }, { status: 400 });
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON request." }, { status: 400 }); }
  if (!body || typeof body !== "object") return NextResponse.json({ error: "Invalid event payload." }, { status: 400 });
  const value = body as Record<string, unknown>;
  const source = typeof value.source === "string" ? value.source.trim() : "";
  const eventType = typeof value.event_type === "string" ? value.event_type.trim() : "";
  const title = typeof value.title === "string" ? value.title.trim() : "";
  const severity = typeof value.severity === "string" ? value.severity : "informational";
  const details = value.details && typeof value.details === "object" && !Array.isArray(value.details) ? value.details : {};
  if (!source || source.length > 80 || !eventType || eventType.length > 120 || !title || title.length > 200 ||
      !levels.includes(severity as typeof levels[number]) || JSON.stringify(details).length > 12000) {
    return NextResponse.json({ error: "Check event source, type, title, severity and details size." }, { status: 400 });
  }
  try {
    const supabase = await createClient();
    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
    const { data, error } = await supabase.from("investigation_events").insert({
      case_id: id, user_id: user.id, source, event_type: eventType, title, severity, details
    }).select("id,case_id,source,event_type,severity,title,details,occurred_at,created_at").single();
    if (error) return NextResponse.json({ error: error.message }, { status: 400 });
    return NextResponse.json({ event: data }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Persistent case storage is unavailable." }, { status: 503 });
  }
}
