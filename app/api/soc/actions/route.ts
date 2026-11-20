import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { isActionStatus } from "@/lib/soc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ACTION_COLS = "id,alert_id,action,params,status,result,created_at,updated_at";

export async function GET(request: NextRequest) {
  const alertId = request.nextUrl.searchParams.get("alertId") || "";
  if (!alertId) return NextResponse.json({ error: "Provide alertId." }, { status: 400 });
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("soc_actions")
    .select(ACTION_COLS).eq("owner", auth.user.id).eq("alert_id", alertId)
    .order("created_at", { ascending: true });
  if (error) return dbError(error.message);
  return NextResponse.json({ actions: data ?? [] }, { headers: { "Cache-Control": "no-store" } });
}

// Record a response action against an alert (human approval / outcome log).
export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const alertId = typeof value.alertId === "string" ? value.alertId : "";
  const action = typeof value.action === "string" ? value.action.slice(0, 60) : "";
  if (!alertId || !action) return NextResponse.json({ error: "Provide alertId and action." }, { status: 400 });
  const status = isActionStatus(value.status) ? value.status : "approved";
  const params = value.params && typeof value.params === "object" ? value.params : {};

  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  // The alert must belong to this operator.
  const { data: alert } = await auth.supabase.from("soc_alerts")
    .select("id").eq("id", alertId).eq("owner", auth.user.id).maybeSingle();
  if (!alert) return NextResponse.json({ error: "Alert not found." }, { status: 404 });

  const { data, error } = await auth.supabase.from("soc_actions").insert({
    owner: auth.user.id, alert_id: alertId, action, params, status,
    result: value.result && typeof value.result === "object" ? value.result : null,
  }).select(ACTION_COLS).single();
  if (error) return dbError(error.message);
  return NextResponse.json({ action: data }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const id = typeof value.id === "string" ? value.id : "";
  if (!id || !isActionStatus(value.status)) {
    return NextResponse.json({ error: "Provide an action id and a valid status." }, { status: 400 });
  }
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const update: Record<string, unknown> = { status: value.status };
  if (value.result && typeof value.result === "object") update.result = value.result;
  const { data, error } = await auth.supabase.from("soc_actions")
    .update(update).eq("id", id).eq("owner", auth.user.id).select(ACTION_COLS).maybeSingle();
  if (error) return dbError(error.message);
  if (!data) return NextResponse.json({ error: "Action not found." }, { status: 404 });
  return NextResponse.json({ action: data });
}
