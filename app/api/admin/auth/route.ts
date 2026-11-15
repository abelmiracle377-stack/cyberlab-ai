import { NextResponse } from "next/server";
import { adminGate } from "@/lib/billing/admin";

export const dynamic = "force-dynamic";

export async function GET() {
  const gate = await adminGate();
  if (gate.error) {
    if (gate.error.status === 404) return NextResponse.json({ error: "Not found" }, { status: 404 });
    return gate.error;
  }
  return NextResponse.json({ approved: true }, { headers: { "Cache-Control": "no-store" } });
}
