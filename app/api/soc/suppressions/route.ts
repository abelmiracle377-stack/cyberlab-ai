import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { isSeverity } from "@/lib/soc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COLS = "id,rule,host,src_ip,match_user,action,max_severity,reason,expires_at,created_at";

export async function GET() {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("soc_suppressions")
    .select(COLS).eq("owner", auth.user.id).order("created_at", { ascending: false }).limit(500);
  if (error) return dbError(error.message);
  return NextResponse.json({ suppressions: data ?? [] }, { headers: { "Cache-Control": "no-store" } });
}

function clean(v: unknown, max = 120): string | null {
  const s = typeof v === "string" ? v.trim() : "";
  return s ? s.slice(0, max) : null;
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const row = {
    rule: clean(v.rule, 80), host: clean(v.host), src_ip: clean(v.src_ip), match_user: clean(v.user),
    action: v.action === "cap" ? "cap" : "drop",
    max_severity: isSeverity(v.max_severity) ? v.max_severity : null,
    reason: clean(v.reason, 500),
    expires_at: typeof v.expires === "string" && v.expires ? v.expires : null,
  };
  if (!row.rule && !row.host && !row.src_ip && !row.match_user) {
    return NextResponse.json({ error: "A suppression must select on a rule, host, source IP or user." }, { status: 400 });
  }
  if (row.action === "cap" && !row.max_severity) {
    return NextResponse.json({ error: "A cap suppression needs a max_severity." }, { status: 400 });
  }
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("soc_suppressions")
    .insert({ ...row, owner: auth.user.id }).select(COLS).single();
  if (error) return dbError(error.message);
  return NextResponse.json({ suppression: data }, { status: 201 });
}

export async function DELETE(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id") || "";
  if (!id) return NextResponse.json({ error: "Provide a suppression id." }, { status: 400 });
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { error } = await auth.supabase.from("soc_suppressions").delete().eq("id", id).eq("owner", auth.user.id);
  if (error) return dbError(error.message);
  return NextResponse.json({ deleted: true });
}
