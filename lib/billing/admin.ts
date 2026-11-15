import { createClient as createSupabaseClient } from "@supabase/supabase-js";
import { createClient } from "@/lib/supabase/server";
import { NextResponse } from "next/server";

export function adminDb() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("Supabase service configuration missing.");
  return createSupabaseClient(url, key, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { "X-Client-Info": "cyberlab-ai-admin" } },
  });
}

export async function adminGate() {
  try {
    const supabase = await createClient();
    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      return { db: null, user: null, error: NextResponse.json({ error: "Sign in required." }, { status: 401 }) };
    }
    const db = adminDb();
    const { data: profile, error: profileError } = await db
      .from("user_profiles")
      .select("role")
      .eq("user_id", user.id)
      .maybeSingle();
    if (profileError) {
      return { db: null, user, error: NextResponse.json({ error: "Administrator access could not be verified. Try again later." }, { status: 503 }) };
    }
    if (profile?.role !== "admin") {
      return { db: null, user, error: new Response(null, { status: 404 }) };
    }
    return { db, user, error: null };
  } catch {
    return { db: null, user: null, error: NextResponse.json({ error: "Administrative services are temporarily unavailable." }, { status: 503 }) };
  }
}
