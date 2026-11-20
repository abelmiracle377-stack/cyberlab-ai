import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { validateUsername, validateDisplayName, validateBio } from "@/lib/social";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const PROFILE_COLS = "user_id,username,display_name,avatar_url,bio,created_at,updated_at";

export async function GET() {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase
    .from("profiles").select(PROFILE_COLS).eq("user_id", auth.user.id).maybeSingle();
  if (error) return dbError(error.message);
  return NextResponse.json({ profile: data ?? null }, { headers: { "Cache-Control": "no-store" } });
}

export async function PUT(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;

  const username = validateUsername(value.username);
  if (!username.ok) return NextResponse.json({ error: username.error }, { status: 400 });
  const displayName = validateDisplayName(value.display_name);
  if (!displayName.ok) return NextResponse.json({ error: displayName.error }, { status: 400 });
  const bio = validateBio(value.bio);
  if (!bio.ok) return NextResponse.json({ error: bio.error }, { status: 400 });
  const avatarUrl = typeof value.avatar_url === "string" && value.avatar_url.length <= 500 ? value.avatar_url : null;

  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  const { data, error } = await auth.supabase.from("profiles").upsert({
    user_id: auth.user.id,
    username: username.value,
    display_name: displayName.value,
    bio: bio.value,
    avatar_url: avatarUrl,
  }, { onConflict: "user_id" }).select(PROFILE_COLS).single();

  if (error) {
    if (error.code === "23505") return NextResponse.json({ error: "That username is already taken." }, { status: 409 });
    return dbError(error.message);
  }
  return NextResponse.json({ profile: data }, { status: 200 });
}
