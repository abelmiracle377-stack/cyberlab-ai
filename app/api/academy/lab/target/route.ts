import { NextRequest, NextResponse } from "next/server";
import { requireUser } from "@/lib/social-auth";
import { handleLabRequest } from "@/lib/academy-lab-target";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Hosts the vulnerable training target inside the app so learners can attack it
// entirely in the browser (no local companion). Returns the target's virtual
// response. Harmless by construction — it only ever returns canned content.
export async function POST(request: NextRequest) {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;

  const method = typeof v.method === "string" ? v.method : "GET";
  const path = typeof v.path === "string" ? v.path.slice(0, 512) : "/";
  const query = typeof v.query === "string" ? v.query.slice(0, 1024) : "";
  const headers: Record<string, string> = {};
  if (v.headers && typeof v.headers === "object") {
    for (const [k, val] of Object.entries(v.headers as Record<string, unknown>)) {
      if (typeof val === "string") headers[k] = val.slice(0, 2048);
    }
  }
  const result = handleLabRequest({ method, path, query, headers });
  return NextResponse.json(result, { headers: { "Cache-Control": "no-store" } });
}
