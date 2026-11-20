import { NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { computeMetrics } from "@/lib/soc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Operational KPIs over the operator's alerts (open load, resolved rate, MTTR).
export async function GET() {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase
    .from("soc_alerts").select("severity,status,created_at,updated_at").eq("owner", auth.user.id).limit(5000);
  if (error) return dbError(error.message);
  return NextResponse.json({ metrics: computeMetrics(data ?? []) }, { headers: { "Cache-Control": "no-store" } });
}
