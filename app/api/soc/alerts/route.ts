import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { normalizeIngestAlert, isAlertStatus, isSeverity } from "@/lib/soc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALERT_COLS = "id,alert_key,rule,title,severity,score,mitre,description,entities," +
  "event_count,first_seen,last_seen,recommended_actions,source,status,created_at,updated_at";

export async function GET(request: NextRequest) {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  let query = auth.supabase.from("soc_alerts").select(ALERT_COLS).eq("owner", auth.user.id);
  const status = request.nextUrl.searchParams.get("status");
  if (status && isAlertStatus(status)) query = query.eq("status", status);
  const severity = request.nextUrl.searchParams.get("severity");
  if (severity && isSeverity(severity)) query = query.eq("severity", severity);
  const { data, error } = await query.order("score", { ascending: false })
    .order("created_at", { ascending: false }).limit(300);
  if (error) return dbError(error.message);
  return NextResponse.json({ alerts: data ?? [] }, { headers: { "Cache-Control": "no-store" } });
}

// Ingest alerts produced by the companion engine/runner (upsert by alert_key).
export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const incoming = Array.isArray(value.alerts) ? value.alerts : [];
  if (incoming.length === 0) return NextResponse.json({ error: "Provide an 'alerts' array." }, { status: 400 });
  if (incoming.length > 1000) return NextResponse.json({ error: "Too many alerts in one request." }, { status: 400 });
  const source = typeof value.source === "string" ? value.source : "companion";

  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  // Omit status so re-ingesting an existing alert keeps its triage state.
  const rows = incoming
    .map((a) => normalizeIngestAlert(a, source))
    .filter((r): r is NonNullable<typeof r> => r !== null)
    .map((r) => ({ ...r, owner: auth.user.id }));
  if (rows.length === 0) return NextResponse.json({ error: "No valid alerts to store." }, { status: 400 });

  const { data, error } = await auth.supabase
    .from("soc_alerts").upsert(rows, { onConflict: "owner,alert_key" }).select("id,alert_key,severity,status");
  if (error) return dbError(error.message);
  return NextResponse.json({ ingested: data?.length ?? 0, alerts: data ?? [] }, { status: 200 });
}

export async function PATCH(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const id = typeof value.id === "string" ? value.id : "";
  const status = value.status;
  if (!id || !isAlertStatus(status)) {
    return NextResponse.json({ error: "Provide an alert id and a valid status." }, { status: 400 });
  }
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("soc_alerts")
    .update({ status }).eq("id", id).eq("owner", auth.user.id).select("id,status").maybeSingle();
  if (error) return dbError(error.message);
  if (!data) return NextResponse.json({ error: "Alert not found." }, { status: 404 });
  return NextResponse.json({ alert: data });
}
