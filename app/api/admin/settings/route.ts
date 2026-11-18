import { NextResponse } from "next/server";
import { adminGate } from "@/lib/billing/admin";

export const dynamic = "force-dynamic";

export async function GET() {
  const gate = await adminGate();
  if (gate.error) return gate.error;
  const { data, error } = await gate.db!.from("cyberlab_settings")
    .select("ai_learning_enabled, updated_at")
    .eq("id", true)
    .maybeSingle();
  if (error) return NextResponse.json({ error: "AI Learning settings are unavailable. Apply the latest database migration." }, { status: 503 });
  if (!data) return NextResponse.json({ error: "AI Learning settings are not initialised. Apply the latest database migration." }, { status: 503 });
  return NextResponse.json({ settings: data }, { headers: { "Cache-Control": "no-store" } });
}

export async function PATCH(request: Request) {
  const gate = await adminGate();
  if (gate.error) return gate.error;
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object" || typeof body.ai_learning_enabled !== "boolean") {
    return NextResponse.json({ error: "ai_learning_enabled must be a boolean." }, { status: 400 });
  }
  const { data, error } = await gate.db!.from("cyberlab_settings").upsert({
    id: true,
    ai_learning_enabled: body.ai_learning_enabled,
    updated_at: new Date().toISOString(),
    updated_by: gate.user!.id,
  }, { onConflict: "id" }).select("ai_learning_enabled, updated_at").single();
  if (error) return NextResponse.json({ error: "Could not update AI Learning settings." }, { status: 500 });
  return NextResponse.json({ settings: data }, { headers: { "Cache-Control": "no-store" } });
}
