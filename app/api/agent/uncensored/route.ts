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
  history: z.array(z.object({
    role: z.enum(["user", "assistant"]),
    content: z.string().max(8000),
  })).max(12).optional().default([]),
});

export async function POST(request: Request) {
  try {
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > 40000) return NextResponse.json({ error: "Request body is too large." }, { status: 413 });
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 40000) return NextResponse.json({ error: "Request body is too large." }, { status: 413 });
    const requestBody = JSON.parse(rawBody);
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });

    const { data: subscription } = await supabase.from("subscriptions")
      .select("status").eq("user_id", user.id).in("status", ["active", "comped"]).maybeSingle();
    if (!subscription) return NextResponse.json({ error: "An active subscription is required." }, { status: 402 });

    const parsed = schema.safeParse(requestBody);
    if (!parsed.success) return NextResponse.json({ error: "Invalid model or message. Prompts are limited to 8,000 characters." }, { status: 400 });

    const historyChars = parsed.data.history.reduce((total, item) => total + item.content.length, 0);
    if (historyChars > 24000) return NextResponse.json({ error: "Conversation history is too large." }, { status: 413 });

    const db = adminDb();
    const reservation = await db.rpc("reserve_cyberlab_ai_usage", {
      p_user_id: user.id,
      p_estimated_tokens: 4096,
      p_monthly_limit: 200000,
    });
    if (reservation.error) {
      console.error("AI usage reservation failed:", reservation.error.message);
      return NextResponse.json({ error: "AI usage accounting is unavailable. Try again later." }, { status: 503 });
    }
    const usageReservation = Array.isArray(reservation.data) ? reservation.data[0] : reservation.data;
    if (!usageReservation?.allowed || !usageReservation.reservation_id) {
      return NextResponse.json({ error: "Your monthly AI usage allowance has been reached. Contact the workspace administrator for a higher allowance." }, { status: 429 });
    }

    try {
      const result = await runUnfilteredCompletion({
        model: parsed.data.model,
        messages: [...parsed.data.history, { role: "user", content: parsed.data.prompt }],
        maxTokens: 1800,
      });
      await db.rpc("settle_cyberlab_ai_usage", {
        p_reservation_id: usageReservation.reservation_id,
        p_actual_tokens: Math.min(result.usage.totalTokens, 10000),
        p_provider: result.provider,
        p_model: result.model,
        p_status: "completed",
      });
      return new Response(result.text, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-CyberLab-Model": result.model,
          "X-CyberLab-Usage-Tokens": String(result.usage.totalTokens),
        },
      });
    } catch (error) {
      await db.rpc("settle_cyberlab_ai_usage", {
        p_reservation_id: usageReservation.reservation_id,
        p_actual_tokens: 0,
        p_provider: "uncensoredllm-compatible",
        p_model: parsed.data.model,
        p_status: "failed",
      });
      throw error;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unfiltered model request failed.";
    console.error("CyberLab unfiltered inference failed:", message);
    return NextResponse.json({ error: message.slice(0, 500) }, { status: 502 });
  }
}
