import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COLS = "id,asset,label,created_at,last_scanned_at";

export async function GET() {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("soc_exposure_assets")
    .select(COLS).eq("owner", auth.user.id).order("created_at", { ascending: false }).limit(500);
  if (error) return dbError(error.message);
  return NextResponse.json({ assets: data ?? [] }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const asset = typeof v.asset === "string" ? v.asset.trim().slice(0, 255) : "";
  const label = typeof v.label === "string" && v.label.trim() ? v.label.trim().slice(0, 120) : null;
  if (!asset) return NextResponse.json({ error: "Provide an asset IP or hostname." }, { status: 400 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("soc_exposure_assets")
    .upsert({ owner: auth.user.id, asset, label }, { onConflict: "owner,asset" }).select(COLS).single();
  if (error) return dbError(error.message);
  return NextResponse.json({ asset: data }, { status: 201 });
}

// PATCH stamps last_scanned_at on the given asset ids (after a sweep).
export async function PATCH(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const ids = Array.isArray(v.ids) ? v.ids.filter((x): x is string => typeof x === "string").slice(0, 500) : [];
  if (ids.length === 0) return NextResponse.json({ error: "Provide asset ids." }, { status: 400 });
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { error } = await auth.supabase.from("soc_exposure_assets")
    .update({ last_scanned_at: new Date().toISOString() }).eq("owner", auth.user.id).in("id", ids);
  if (error) return dbError(error.message);
  return NextResponse.json({ updated: ids.length });
}

export async function DELETE(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id") || "";
  if (!id) return NextResponse.json({ error: "Provide an asset id." }, { status: 400 });
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { error } = await auth.supabase.from("soc_exposure_assets").delete().eq("id", id).eq("owner", auth.user.id);
  if (error) return dbError(error.message);
  return NextResponse.json({ deleted: true });
}
