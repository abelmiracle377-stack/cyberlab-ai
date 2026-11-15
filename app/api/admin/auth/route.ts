import { NextResponse } from "next/server";
import { adminGate } from "@/lib/billing/admin";

export const dynamic = "force-dynamic";

export async function GET() {
  const result = await adminGate();
  if (result.error) {
    if (result.error.status === 401) return NextResponse.json({ error: "Not found" }, { status: 404 });
    if (result.error.status === 404) return NextResponse.json({ error: "Not found" }, { status: 404 });
    return result.error;
  }
  return NextResponse.json({ approved: true }, { headers: { "Cache-Control": "no-store" } });
}
