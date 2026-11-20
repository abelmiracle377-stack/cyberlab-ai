import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import type { SupabaseClient, User } from "@supabase/supabase-js";

export type Authed = { supabase: SupabaseClient; user: User };

// Resolve the signed-in user, or an error response to return directly.
export async function requireUser(): Promise<Authed | { error: NextResponse }> {
  try {
    const supabase = await createClient();
    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) {
      return { error: NextResponse.json({ error: "Sign in to use CyberLab chat." }, { status: 401 }) };
    }
    return { supabase, user };
  } catch {
    return { error: NextResponse.json({ error: "Chat is unavailable: configure Supabase and apply the social_chat migration." }, { status: 503 }) };
  }
}

export function dbError(message: string): NextResponse {
  return NextResponse.json(
    { error: message, hint: "Apply the 202611200001_social_chat Supabase migration if the tables are missing." },
    { status: 503 },
  );
}
