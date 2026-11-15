import { createHmac, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { adminDb } from "@/lib/billing/admin";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const EXPECTED_AMOUNT = 1000;
const EXPECTED_CURRENCY = "USD";

export async function POST(req: Request) {
  const secret = process.env.PAYSTACK_SECRET_KEY;
  if (!secret) return NextResponse.json({ error: "Webhook unavailable." }, { status: 503 });

  const declaredLength = Number(req.headers.get("content-length") || 0);
  if (declaredLength > 1024 * 1024) return NextResponse.json({ error: "Webhook payload too large." }, { status: 413 });
  const raw = await req.text();
  if (Buffer.byteLength(raw, "utf8") > 1024 * 1024) return NextResponse.json({ error: "Webhook payload too large." }, { status: 413 });

  const signature = req.headers.get("x-paystack-signature") || "";
  const expected = createHmac("sha512", secret).update(raw).digest("hex");
  const suppliedBytes = Buffer.from(signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) {
    return NextResponse.json({ error: "Invalid signature." }, { status: 401 });
  }

  let event: unknown;
  try { event = JSON.parse(raw); }
  catch { return NextResponse.json({ error: "Malformed webhook JSON." }, { status: 400 }); }
  if (!event || typeof event !== "object" || !("event" in event) || !("data" in event) ||
      typeof (event as any).event !== "string" || !(event as any).data || typeof (event as any).data !== "object") {
    return NextResponse.json({ error: "Invalid webhook event." }, { status: 400 });
  }

  const eventName = (event as any).event as string;
  const data = (event as any).data as Record<string, any>;
  const db = adminDb();

  if (eventName === "charge.success") {
    const reference = typeof data.reference === "string" ? data.reference : "";
    if (!reference || data.status !== "success" || data.currency !== EXPECTED_CURRENCY || Number(data.amount) !== EXPECTED_AMOUNT) {
      return NextResponse.json({ error: "Payment does not match the configured subscription amount." }, { status: 400 });
    }

    const { data: payment, error: paymentLookupError } = await db
      .from("payments")
      .select("id,user_id,status,amount,currency,provider")
      .eq("provider_reference", reference)
      .eq("provider", "paystack")
      .maybeSingle();
    if (paymentLookupError) return NextResponse.json({ error: "Payment record could not be verified." }, { status: 503 });
    if (!payment) return NextResponse.json({ error: "No matching checkout record exists for this payment." }, { status: 404 });
    if (payment.amount !== EXPECTED_AMOUNT || payment.currency !== EXPECTED_CURRENCY ||
        (data.metadata?.user_id && data.metadata.user_id !== payment.user_id)) {
      return NextResponse.json({ error: "Payment metadata does not match the original checkout." }, { status: 400 });
    }
    if (payment.status === "success") return NextResponse.json({ received: true, duplicate: true });

    const paidAt = typeof data.paid_at === "string" ? data.paid_at : new Date().toISOString();
    const { error: paymentUpdateError } = await db.from("payments")
      .update({
        status: "success",
        provider_transaction_id: String(data.id || ""),
        paid_at: paidAt,
        raw_event: event,
      })
      .eq("id", payment.id)
      .eq("status", "pending");
    if (paymentUpdateError) return NextResponse.json({ error: "Payment status could not be recorded." }, { status: 503 });

    const start = new Date(paidAt);
    const end = new Date(start);
    end.setMonth(end.getMonth() + 1);
    const { error: subscriptionError } = await db.from("subscriptions").upsert({
      user_id: payment.user_id,
      provider: "paystack",
      provider_subscription_code: data.subscription?.subscription_code || null,
      provider_customer_code: data.customer?.customer_code || null,
      plan_code: process.env.PAYSTACK_PLAN_CODE || "",
      status: "active",
      amount: EXPECTED_AMOUNT,
      currency: EXPECTED_CURRENCY,
      interval: "monthly",
      current_period_start: start.toISOString(),
      current_period_end: end.toISOString(),
    }, { onConflict: "user_id" });
    if (subscriptionError) {
      await db.from("payments").update({ status: "pending" }).eq("id", payment.id).eq("status", "success");
      return NextResponse.json({ error: "Payment was verified but subscription activation failed. Retry webhook delivery." }, { status: 503 });
    }
  }

  if (eventName === "invoice.payment_failed" || eventName === "subscription.disable") {
    const userId = typeof data.metadata?.user_id === "string" ? data.metadata.user_id : "";
    if (userId && /^[0-9a-f-]{36}$/i.test(userId)) {
      await db.from("subscriptions")
        .update({ status: eventName === "invoice.payment_failed" ? "past_due" : "cancelled" })
        .eq("user_id", userId)
        .eq("provider", "paystack");
    }
  }

  return NextResponse.json({ received: true });
}
