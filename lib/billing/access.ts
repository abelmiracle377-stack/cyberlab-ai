import { adminDb } from "@/lib/billing/admin";

export const TRIAL_DAYS = 2;

// Billing is enforced only when CYBERLAB_BILLING_ENFORCED is exactly "true".
// Until then every signed-in user has open access (used while Paystack is being fixed).
export function billingEnforced() {
  return process.env.CYBERLAB_BILLING_ENFORCED === "true";
}

export type AccessDecision = { allowed: boolean; reason: string };

export async function accessFor(userId: string): Promise<AccessDecision> {
  if (!billingEnforced()) return { allowed: true, reason: "open-access" };

  let db;
  try {
    db = adminDb();
  } catch {
    return { allowed: false, reason: "unavailable" };
  }

  const { data: sub, error } = await db
    .from("subscriptions")
    .select("status,trial_ends_at")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) return { allowed: false, reason: "unavailable" };

  if (!sub) {
    // First enforced request for this user: start the free trial. ignoreDuplicates
    // keeps concurrent first requests from overwriting each other.
    const trialEnd = new Date(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const { error: insertError } = await db.from("subscriptions").upsert(
      {
        user_id: userId,
        plan_code: "trial",
        status: "trial",
        amount: 1000,
        currency: "USD",
        interval: "monthly",
        trial_ends_at: trialEnd,
      },
      { onConflict: "user_id", ignoreDuplicates: true },
    );
    if (insertError) return { allowed: false, reason: "unavailable" };
    return { allowed: true, reason: "trial-started" };
  }

  if (sub.status === "active" || sub.status === "comped") return { allowed: true, reason: sub.status };
  if (sub.status === "trial" && sub.trial_ends_at && new Date(sub.trial_ends_at).getTime() > Date.now()) {
    return { allowed: true, reason: "trial" };
  }
  return { allowed: false, reason: "billing-required" };
}
