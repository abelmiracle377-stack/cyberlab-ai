import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { normalizeUsername } from "@/lib/social";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Search profiles by username to send friend requests. Annotates each result
// with the viewer's friendship status, if any.
export async function GET(request: NextRequest) {
  const q = normalizeUsername(request.nextUrl.searchParams.get("q") || "");
  if (q.length < 2) return NextResponse.json({ users: [] });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  const like = q.replace(/[%_\\]/g, "\\$&");
  const { data: users, error } = await auth.supabase
    .from("profiles")
    .select("user_id,username,display_name,avatar_url,bio,public_key")
    .ilike("username", `%${like}%`)
    .neq("user_id", auth.user.id)
    .order("username")
    .limit(20);
  if (error) return dbError(error.message);

  const ids = (users ?? []).map((u) => u.user_id as string);
  const friendByUser = new Map<string, { id: string; status: string; role: "requester" | "addressee" }>();
  if (ids.length) {
    const { data: edges } = await auth.supabase
      .from("friendships")
      .select("id,requester_id,addressee_id,status")
      .or(`requester_id.eq.${auth.user.id},addressee_id.eq.${auth.user.id}`);
    for (const e of edges ?? []) {
      const other = e.requester_id === auth.user.id ? e.addressee_id : e.requester_id;
      if (ids.includes(other)) {
        friendByUser.set(other, {
          id: e.id, status: e.status,
          role: e.requester_id === auth.user.id ? "requester" : "addressee",
        });
      }
    }
  }

  return NextResponse.json({
    users: (users ?? []).map((u) => ({ ...u, friendship: friendByUser.get(u.user_id as string) ?? null })),
  }, { headers: { "Cache-Control": "no-store" } });
}
