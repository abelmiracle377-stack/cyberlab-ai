import { NextResponse } from "next/server";
import { z } from "zod";
import { createClient } from "@/lib/supabase/server";
import { adminDb } from "@/lib/billing/admin";
import { runReadOnlyResearch } from "@/lib/read-only-research-tools";

export const runtime = "nodejs";
export const maxDuration = 90;

const schema = z.object({
  model: z.string().min(3).max(180).regex(/^[a-zA-Z0-9._:/-]+$/),
  prompt: z.string().trim().min(1).max(8000),
  history: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(8000) })).max(12).optional().default([]),
});

async function readBody(request: Request): Promise<unknown> {
  const length = request.headers.get("content-length");
  if (length && Number(length) > 40000) throw new Error("Request body is too large.");
  if (!request.body) throw new Error("A JSON request body is required.");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      size += value.byteLength;
      if (size > 40000) { await reader.cancel(); throw new Error("Request body is too large."); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

export async function POST(request: Request) {
  let reservationId: string | null = null;
  let db: ReturnType<typeof adminDb> | null = null;
  let model = "unknown";
  try {
    const parsed = schema.safeParse(await readBody(request));
    if (!parsed.success) return NextResponse.json({ error: "Invalid request. Prompts are limited to 8,000 characters." }, { status: 400 });
    if (parsed.data.history.reduce((sum, item) => sum + item.content.length, 0) > 24000) return NextResponse.json({ error: "Conversation history is too large." }, { status: 413 });
    model = parsed.data.model;
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
    const { data: subscription } = await supabase.from("subscriptions").select("status").eq("user_id", user.id).in("status", ["active", "comped"]).maybeSingle();
    if (!subscription) return NextResponse.json({ error: "An active subscription is required." }, { status: 402 });
    db = adminDb();
    const reserved = await db.rpc("reserve_cyberlab_ai_usage", { p_user_id: user.id, p_estimated_tokens: 60000, p_monthly_limit: 200000 });
    if (reserved.error) return NextResponse.json({ error: "AI usage accounting is unavailable. Try again later." }, { status: 503 });
    const reservation = Array.isArray(reserved.data) ? reserved.data[0] : reserved.data;
    if (!reservation?.allowed || !reservation.reservation_id) return NextResponse.json({ error: "Your monthly AI usage allowance has been reached." }, { status: 429 });
    reservationId = reservation.reservation_id;
    try {
      const result = await runReadOnlyResearch({ model, prompt: parsed.data.prompt, history: parsed.data.history });
      const settled = await db.rpc("settle_cyberlab_ai_usage", { p_reservation_id: reservationId, p_actual_tokens: result.usage.totalTokens, p_provider: result.provider, p_model: model, p_status: "completed" });
      if (settled.error) console.error("Research usage settlement failed:", settled.error.message);
      reservationId = null;
      return NextResponse.json({ text: result.text, evidence: result.evidence, usage: result.usage, toolCalls: result.toolCalls, provenance: { analysis: "model_generated", evidence: "read_only_tool_results" } }, { headers: { "Cache-Control": "private, no-store" } });
    } catch (error) {
      await db.rpc("settle_cyberlab_ai_usage", { p_reservation_id: reservationId, p_actual_tokens: 0, p_provider: "uncensoredllm-compatible-tools", p_model: model, p_status: "failed" });
      reservationId = null;
      throw error;
    }
  } catch (error) {
    if (reservationId && db) await db.rpc("settle_cyberlab_ai_usage", { p_reservation_id: reservationId, p_actual_tokens: 0, p_provider: "uncensoredllm-compatible-tools", p_model: model, p_status: "failed" });
    const message = error instanceof Error ? error.message : "Read-only research failed.";
    const status = /too large/i.test(message) ? 413 : /valid JSON|JSON|body is required/i.test(message) ? 400 : /Authentication/i.test(message) ? 401 : 502;
    console.error("CyberLab read-only research failed:", message);
    return NextResponse.json({ error: message.slice(0, 500) }, { status });
  }
}
