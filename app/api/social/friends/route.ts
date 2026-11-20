import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError, type Authed } from "@/lib/social-auth";
import { normalizeUsername, canTransitionFriendship, type FriendStatus } from "@/lib/social";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Edge = { id: string; requester_id: string; addressee_id: string; status: FriendStatus; created_at: string };

async function profilesFor(auth: Authed, ids: string[]) {
  const map = new Map<string, Record<string, unknown>>();
  if (!ids.length) return map;
  const { data } = await auth.supabase
    .from("profiles").select("user_id,username,display_name,avatar_url,bio").in("user_id", ids);
  for (const p of data ?? []) map.set(p.user_id as string, p);
  return map;
}

export async function GET() {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const me = auth.user.id;
  const { data: edges, error } = await auth.supabase
    .from("friendships").select("id,requester_id,addressee_id,status,created_at")
    .or(`requester_id.eq.${me},addressee_id.eq.${me}`)
    .order("updated_at", { ascending: false });
  if (error) return dbError(error.message);

  const list = (edges ?? []) as Edge[];
  const others = list.map((e) => (e.requester_id === me ? e.addressee_id : e.requester_id));
  const profiles = await profilesFor(auth, others);
  const shape = (e: Edge) => {
    const otherId = e.requester_id === me ? e.addressee_id : e.requester_id;
    return { id: e.id, status: e.status, created_at: e.created_at,
             role: e.requester_id === me ? "requester" : "addressee",
             user: profiles.get(otherId) ?? { user_id: otherId } };
  };
  return NextResponse.json({
    friends: list.filter((e) => e.status === "accepted").map(shape),
    incoming: list.filter((e) => e.status === "pending" && e.addressee_id === me).map(shape),
    outgoing: list.filter((e) => e.status === "pending" && e.requester_id === me).map(shape),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;

  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const me = auth.user.id;

  // Resolve the target by username or user id.
  let targetId = typeof value.userId === "string" ? value.userId : "";
  if (!targetId) {
    const username = normalizeUsername(value.username);
    if (!username) return NextResponse.json({ error: "Provide a username to add." }, { status: 400 });
    const { data: profile, error } = await auth.supabase
      .from("profiles").select("user_id").eq("username", username).maybeSingle();
    if (error) return dbError(error.message);
    if (!profile) return NextResponse.json({ error: "No user with that username." }, { status: 404 });
    targetId = profile.user_id as string;
  }
  if (targetId === me) return NextResponse.json({ error: "You cannot add yourself." }, { status: 400 });

  // Any existing edge in either direction?
  const { data: existing } = await auth.supabase
    .from("friendships").select("id,requester_id,addressee_id,status")
    .or(`and(requester_id.eq.${me},addressee_id.eq.${targetId}),and(requester_id.eq.${targetId},addressee_id.eq.${me})`)
    .maybeSingle();

  if (existing) {
    const edge = existing as Edge;
    if (edge.status === "accepted") return NextResponse.json({ status: "already_friends" });
    if (edge.status === "blocked") return NextResponse.json({ error: "This friendship is blocked." }, { status: 409 });
    // They already requested you -> accept it.
    if (edge.status === "pending" && edge.addressee_id === me) {
      const { error } = await auth.supabase.from("friendships").update({ status: "accepted" }).eq("id", edge.id);
      if (error) return dbError(error.message);
      return NextResponse.json({ status: "accepted" });
    }
    if (edge.status === "pending") return NextResponse.json({ status: "already_requested" });
    // Previously declined -> re-open as a fresh pending request from me.
    const { error } = await auth.supabase.from("friendships")
      .update({ requester_id: me, addressee_id: targetId, status: "pending" }).eq("id", edge.id);
    if (error) return dbError(error.message);
    return NextResponse.json({ status: "requested" });
  }

  const { error } = await auth.supabase.from("friendships")
    .insert({ requester_id: me, addressee_id: targetId, status: "pending" });
  if (error) return dbError(error.message);
  return NextResponse.json({ status: "requested" }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const id = typeof value.id === "string" ? value.id : "";
  const action = typeof value.action === "string" ? value.action : "";
  const target: Record<string, FriendStatus> = { accept: "accepted", decline: "declined", block: "blocked" };
  const nextStatus = target[action];
  if (!id || !nextStatus) return NextResponse.json({ error: "Provide a friendship id and action (accept/decline/block)." }, { status: 400 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  const { data: edge, error: readError } = await auth.supabase
    .from("friendships").select("id,requester_id,addressee_id,status").eq("id", id).maybeSingle();
  if (readError) return dbError(readError.message);
  if (!edge) return NextResponse.json({ error: "Friend request not found." }, { status: 404 });
  const role = edge.requester_id === auth.user.id ? "requester" : "addressee";
  if (!canTransitionFriendship(edge.status as FriendStatus, nextStatus, role)) {
    return NextResponse.json({ error: "That action is not allowed for this request." }, { status: 403 });
  }
  const { error } = await auth.supabase.from("friendships").update({ status: nextStatus }).eq("id", id);
  if (error) return dbError(error.message);
  return NextResponse.json({ status: nextStatus });
}

export async function DELETE(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id") || "";
  if (!id) return NextResponse.json({ error: "Provide the friendship id to remove." }, { status: 400 });
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { error } = await auth.supabase.from("friendships").delete().eq("id", id);
  if (error) return dbError(error.message);
  return NextResponse.json({ status: "removed" });
}
