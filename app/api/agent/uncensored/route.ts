import { NextResponse } from "next/server";
import { z } from "zod";
import { createClient } from "@/lib/supabase/server";
import { adminDb } from "@/lib/billing/admin";
import { runUnfilteredCompletion } from "@/lib/ai-gateway";

export const runtime = "nodejs";
export const maxDuration = 90;

const schema = z.object({
  model: z.string().min(3).max(180).regex(/^[a-zA-Z0-9._:/-]+$/),
  prompt: z.string().trim().min(1).max(8000),
  history: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(8000) })).max(12).optional().default([]),
});

async function readBoundedJson(request: Request): Promise<{ ok: true; value: unknown } | { ok: false; status: 400 | 413; error: string }> {
  const header = request.headers.get("content-length");
  if (header !== null) {
    const length = Number(header);
    if (!Number.isFinite(length) || length < 0) return { ok: false, status: 400, error: "Invalid Content-Length header." };
    if (length > 40000) return { ok: false, status: 413, error: "Request body is too large." };
  }
  if (!request.body) return { ok: false, status: 400, error: "A JSON request body is required." };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > 40000) {
        await reader.cancel();
        return { ok: false, status: 413, error: "Request body is too large." };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return { ok: true, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) }; }
  catch { return { ok: false, status: 400, error: "Request body must contain valid JSON." }; }
}

export async function POST(request: Request) {
  let reservationId: string | null = null;
  let db: ReturnType<typeof adminDb> | null = null;
  let modelId = "unknown";
  try {
    const body = await readBoundedJson(request);
    if (!body.ok) return NextResponse.json({ error: body.error }, { status: body.status });
    const parsed = schema.safeParse(body.value);
    if (!parsed.success) return NextResponse.json({ error: "Invalid model or message. Prompts are limited to 8,000 characters." }, { status: 400 });
    if (parsed.data.history.reduce((sum, item) => sum + item.content.length, 0) > 24000) return NextResponse.json({ error: "Conversation history is too large." }, { status: 413 });
    modelId = parsed.data.model;

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
    const { data: subscription } = await supabase.from("subscriptions").select("status").eq("user_id", user.id).in("status", ["active", "comped"]).maybeSingle();
    if (!subscription) return NextResponse.json({ error: "An active subscription is required." }, { status: 402 });

    db = adminDb();
    const reserved = await db.rpc("reserve_cyberlab_ai_usage", { p_user_id: user.id, p_estimated_tokens: 4096, p_monthly_limit: 200000 });
    if (reserved.error) {
      console.error("AI usage reservation failed:", reserved.error.message);
      return NextResponse.json({ error: "AI usage accounting is unavailable. Try again later." }, { status: 503 });
    }
    const reservation = Array.isArray(reserved.data) ? reserved.data[0] : reserved.data;
    if (!reservation?.allowed || !reservation.reservation_id) return NextResponse.json({ error: "Your monthly AI usage allowance has been reached." }, { status: 429 });
    reservationId = reservation.reservation_id;

    try {
      const result = await runUnfilteredCompletion({ model: modelId, messages: [...parsed.data.history, { role: "user", content: parsed.data.prompt }], maxTokens: 1800 });
      const settlement = await db.rpc("settle_cyberlab_ai_usage", {
        p_reservation_id: reservationId,
        p_actual_tokens: Math.min(result.usage.totalTokens, 10000),
        p_provider: result.provider,
        p_model: result.model,
        p_status: "completed",
      });
      if (settlement.error) console.error("AI usage settlement failed:", settlement.error.message);
      reservationId = null;
      return new Response(result.text, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-CyberLab-Model": result.model, "X-CyberLab-Usage-Tokens": String(result.usage.totalTokens) } });
    } catch (error) {
      await db.rpc("settle_cyberlab_ai_usage", { p_reservation_id: reservationId, p_actual_tokens: 0, p_provider: "uncensoredllm-compatible", p_model: modelId, p_status: "failed" });
      reservationId = null;
      throw error;
    }
  } catch (error) {
    if (reservationId && db) await db.rpc("settle_cyberlab_ai_usage", { p_reservation_id: reservationId, p_actual_tokens: 0, p_provider: "uncensoredllm-compatible", p_model: modelId, p_status: "failed" });
    if (error instanceof SyntaxError) return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
    const message = error instanceof Error ? error.message : "Unfiltered model request failed.";
    console.error("CyberLab unfiltered inference failed:", message);
    return NextResponse.json({ error: message.slice(0, 500) }, { status: 502 });
  }
}
