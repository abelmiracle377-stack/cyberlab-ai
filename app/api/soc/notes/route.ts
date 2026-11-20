import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const alertId = request.nextUrl.searchParams.get("alertId") || "";
  if (!alertId) return NextResponse.json({ error: "Provide alertId." }, { status: 400 });
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("soc_notes")
    .select("id,alert_id,body,created_at").eq("owner", auth.user.id).eq("alert_id", alertId)
    .order("created_at", { ascending: true }).limit(500);
  if (error) return dbError(error.message);
  return NextResponse.json({ notes: data ?? [] }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const alertId = typeof value.alertId === "string" ? value.alertId : "";
  const text = typeof value.body === "string" ? value.body.trim() : "";
  if (!alertId || !text) return NextResponse.json({ error: "Provide alertId and a note body." }, { status: 400 });
  if (text.length > 4000) return NextResponse.json({ error: "Note is too long (max 4000)." }, { status: 400 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data: alert } = await auth.supabase.from("soc_alerts")
    .select("id").eq("id", alertId).eq("owner", auth.user.id).maybeSingle();
  if (!alert) return NextResponse.json({ error: "Alert not found." }, { status: 404 });

  const { data, error } = await auth.supabase.from("soc_notes")
    .insert({ owner: auth.user.id, alert_id: alertId, body: text })
    .select("id,alert_id,body,created_at").single();
  if (error) return dbError(error.message);
  return NextResponse.json({ note: data }, { status: 201 });
}
