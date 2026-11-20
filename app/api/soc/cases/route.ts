import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { isCaseStatus, isSeverity, summarizeCase } from "@/lib/soc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CASE_COLS = "id,title,summary,severity,status,assignee,created_at,updated_at,closed_at";
const MEMBER_COLS = "id,alert_key,rule,title,severity,score,status,mitre,entities,last_seen";

function strField(v: unknown, max: number): string | null {
  const s = typeof v === "string" ? v.trim() : "";
  return s ? s.slice(0, max) : null;
}
function idList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, 500) : [];
}

export async function GET(request: NextRequest) {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const id = request.nextUrl.searchParams.get("id");

  if (id) {
    const { data: kase, error } = await auth.supabase.from("soc_cases")
      .select(CASE_COLS).eq("id", id).eq("owner", auth.user.id).maybeSingle();
    if (error) return dbError(error.message);
    if (!kase) return NextResponse.json({ error: "Case not found." }, { status: 404 });
    const { data: members } = await auth.supabase.from("soc_alerts")
      .select(MEMBER_COLS).eq("owner", auth.user.id).eq("case_id", id).order("score", { ascending: false });
    const memberIds = (members ?? []).map((m) => m.id);
    let timeline: { kind: string; at: string; text: string }[] = [];
    if (memberIds.length) {
      const [{ data: acts }, { data: nts }] = await Promise.all([
        auth.supabase.from("soc_actions").select("action,status,created_at").in("alert_id", memberIds),
        auth.supabase.from("soc_notes").select("body,created_at").in("alert_id", memberIds),
      ]);
      timeline = [
        ...(acts ?? []).map((a) => ({ kind: "action", at: a.created_at as string, text: `${a.action} — ${a.status}` })),
        ...(nts ?? []).map((n) => ({ kind: "note", at: n.created_at as string, text: n.body as string })),
      ].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
    }
    const rollup = summarizeCase(members ?? []);
    return NextResponse.json({ case: kase, members: members ?? [], rollup, timeline },
      { headers: { "Cache-Control": "no-store" } });
  }

  const { data: cases, error } = await auth.supabase.from("soc_cases")
    .select(CASE_COLS).eq("owner", auth.user.id).order("created_at", { ascending: false }).limit(300);
  if (error) return dbError(error.message);
  // Attach member/open counts without an N+1: one pass over member alerts.
  const ids = (cases ?? []).map((c) => c.id);
  const counts = new Map<string, { total: number; open: number }>();
  if (ids.length) {
    const { data: mem } = await auth.supabase.from("soc_alerts")
      .select("case_id,status").eq("owner", auth.user.id).in("case_id", ids);
    const openStatuses = new Set(["new", "acknowledged", "investigating", "contained"]);
    for (const m of mem ?? []) {
      const cur = counts.get(m.case_id) ?? { total: 0, open: 0 };
      cur.total += 1; if (openStatuses.has(m.status)) cur.open += 1;
      counts.set(m.case_id, cur);
    }
  }
  const withCounts = (cases ?? []).map((c) => ({ ...c, member_count: counts.get(c.id)?.total ?? 0, open_count: counts.get(c.id)?.open ?? 0 }));
  return NextResponse.json({ cases: withCounts }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const title = strField(v.title, 300);
  if (!title) return NextResponse.json({ error: "A case needs a title." }, { status: 400 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data: kase, error } = await auth.supabase.from("soc_cases").insert({
    owner: auth.user.id, title,
    summary: strField(v.summary, 4000),
    severity: isSeverity(v.severity) ? v.severity : "medium",
  }).select(CASE_COLS).single();
  if (error) return dbError(error.message);

  const attach = idList(v.alertIds);
  if (attach.length) {
    await auth.supabase.from("soc_alerts").update({ case_id: kase.id })
      .eq("owner", auth.user.id).in("id", attach);
  }
  return NextResponse.json({ case: kase, attached: attach.length }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const id = typeof v.id === "string" ? v.id : "";
  if (!id) return NextResponse.json({ error: "Provide a case id." }, { status: 400 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  const update: Record<string, unknown> = {};
  if (v.status !== undefined) {
    if (!isCaseStatus(v.status)) return NextResponse.json({ error: "Invalid case status." }, { status: 400 });
    update.status = v.status;
    update.closed_at = (v.status === "resolved" || v.status === "closed") ? new Date().toISOString() : null;
  }
  if (v.title !== undefined) { const t = strField(v.title, 300); if (!t) return NextResponse.json({ error: "Title cannot be empty." }, { status: 400 }); update.title = t; }
  if (v.summary !== undefined) update.summary = strField(v.summary, 4000);
  if (v.severity !== undefined && isSeverity(v.severity)) update.severity = v.severity;
  if (v.assignee === "me") update.assignee = auth.user.id;
  if (v.assignee === null) update.assignee = null;

  if (Object.keys(update).length) {
    const { error } = await auth.supabase.from("soc_cases").update(update).eq("id", id).eq("owner", auth.user.id);
    if (error) return dbError(error.message);
  }
  const add = idList(v.addAlerts), remove = idList(v.removeAlerts);
  if (add.length) await auth.supabase.from("soc_alerts").update({ case_id: id }).eq("owner", auth.user.id).in("id", add);
  if (remove.length) await auth.supabase.from("soc_alerts").update({ case_id: null }).eq("owner", auth.user.id).in("id", remove);

  const { data, error } = await auth.supabase.from("soc_cases").select(CASE_COLS).eq("id", id).eq("owner", auth.user.id).maybeSingle();
  if (error) return dbError(error.message);
  if (!data) return NextResponse.json({ error: "Case not found." }, { status: 404 });
  return NextResponse.json({ case: data });
}

export async function DELETE(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id") || "";
  if (!id) return NextResponse.json({ error: "Provide a case id." }, { status: 400 });
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { error } = await auth.supabase.from("soc_cases").delete().eq("id", id).eq("owner", auth.user.id);
  if (error) return dbError(error.message);
  return NextResponse.json({ deleted: true });
}
