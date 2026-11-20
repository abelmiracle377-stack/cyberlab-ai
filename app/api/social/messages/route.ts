import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { validateMessageBody } from "@/lib/social";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MSG_COLS = "id,sender_id,recipient_id,body,media_url,media_type,encrypted,body_iv,media_iv,created_at,read_at";

// Conversation history with one friend. Marks the friend's messages read.
export async function GET(request: NextRequest) {
  const withUser = request.nextUrl.searchParams.get("with") || "";
  if (!withUser) return NextResponse.json({ error: "Provide the other user's id in 'with'." }, { status: 400 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const me = auth.user.id;

  const { data, error } = await auth.supabase
    .from("messages").select(MSG_COLS)
    .or(`and(sender_id.eq.${me},recipient_id.eq.${withUser}),and(sender_id.eq.${withUser},recipient_id.eq.${me})`)
    .order("created_at", { ascending: true })
    .limit(200);
  if (error) return dbError(error.message);

  // Best-effort read receipts for the friend's messages to me.
  await auth.supabase.from("messages").update({ read_at: new Date().toISOString() })
    .eq("sender_id", withUser).eq("recipient_id", me).is("read_at", null);

  return NextResponse.json({ messages: data ?? [] }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const value = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;

  const recipientId = typeof value.recipientId === "string" ? value.recipientId : "";
  if (!recipientId) return NextResponse.json({ error: "Provide recipientId." }, { status: 400 });

  const encrypted = value.encrypted === true;
  const bodyIv = typeof value.bodyIv === "string" && value.bodyIv.length <= 64 ? value.bodyIv : null;
  const mediaIv = typeof value.mediaIv === "string" && value.mediaIv.length <= 64 ? value.mediaIv : null;

  // Encrypted bodies are opaque base64 ciphertext; only bound their size.
  // Plaintext bodies are validated/trimmed as before.
  let bodyValue = "";
  if (encrypted) {
    const raw = typeof value.body === "string" ? value.body : "";
    if (raw.length > 20000) return NextResponse.json({ error: "Encrypted message is too large." }, { status: 400 });
    bodyValue = raw;
  } else {
    const text = validateMessageBody(value.body);
    if (!text.ok) return NextResponse.json({ error: text.error }, { status: 400 });
    bodyValue = text.value;
  }

  const mediaType = value.mediaType === "image" || value.mediaType === "voice" ? value.mediaType : null;
  const mediaPath = typeof value.mediaPath === "string" ? value.mediaPath : "";

  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const me = auth.user.id;

  if (mediaPath) {
    if (!mediaType) return NextResponse.json({ error: "mediaType (image/voice) is required with mediaPath." }, { status: 400 });
    // The upload RLS already restricts the prefix; re-check here for a clear error.
    if (!mediaPath.startsWith(`${me}/`) || mediaPath.length > 256) {
      return NextResponse.json({ error: "Media must be uploaded to your own folder first." }, { status: 400 });
    }
  }
  if (!bodyValue && !mediaPath) {
    return NextResponse.json({ error: "Send some text or an attachment." }, { status: 400 });
  }

  const { data, error } = await auth.supabase.from("messages").insert({
    sender_id: me, recipient_id: recipientId,
    body: bodyValue, media_url: mediaPath || null, media_type: mediaPath ? mediaType : null,
    encrypted, body_iv: encrypted ? bodyIv : null, media_iv: encrypted ? mediaIv : null,
  }).select(MSG_COLS).single();

  if (error) {
    // RLS insert check fails when the two users are not accepted friends.
    if (error.code === "42501") return NextResponse.json({ error: "You can only message accepted friends." }, { status: 403 });
    return dbError(error.message);
  }
  return NextResponse.json({ message: data }, { status: 201 });
}
