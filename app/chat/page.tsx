"use client";

import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import Link from "next/link";
import { Send, UserPlus, Check, X, Mic, Square, ImagePlus, Loader2, MessageCircle } from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import { extensionForMime, validateMedia, MESSAGE_MAX } from "@/lib/social";

type Profile = { user_id: string; username: string; display_name?: string; avatar_url?: string | null; bio?: string };
type UserResult = Profile & { friendship: { id: string; status: string; role: string } | null };
type FriendEdge = { id: string; status: string; created_at: string; role: string; user: Profile };
type Message = {
  id: string; sender_id: string; recipient_id: string; body: string;
  media_url: string | null; media_type: "image" | "voice" | null; created_at: string; read_at: string | null;
};

async function api(path: string, init?: RequestInit) {
  const res = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}

export default function ChatPage() {
  // Create the Supabase client lazily so it is only constructed in the browser
  // (inside effects/handlers), never during the server prerender where the
  // public env vars are absent.
  const supabaseRef = useRef<ReturnType<typeof createClient> | null>(null);
  const getSupabase = () => (supabaseRef.current ??= createClient());
  const [me, setMe] = useState<string | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [friends, setFriends] = useState<FriendEdge[]>([]);
  const [incoming, setIncoming] = useState<FriendEdge[]>([]);
  const [outgoing, setOutgoing] = useState<FriendEdge[]>([]);
  const [active, setActive] = useState<FriendEdge | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [mediaUrls, setMediaUrls] = useState<Record<string, string>>({});
  const [search, setSearch] = useState("");
  const [results, setResults] = useState<UserResult[]>([]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  // Profile setup form
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [bio, setBio] = useState("");

  const threadRef = useRef<HTMLDivElement>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<BlobPart[]>([]);
  const [recording, setRecording] = useState(false);

  // --- bootstrap: who am I, my profile, my friends ---
  useEffect(() => {
    (async () => {
      const { data: { user } } = await getSupabase().auth.getUser();
      setMe(user?.id ?? null);
      setAuthChecked(true);
      if (!user) return;
      try {
        const p = await api("/api/social/profile");
        setProfile(p.profile);
      } catch { /* profile not set yet */ }
      await loadFriends();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadFriends = useCallback(async () => {
    try {
      const data = await api("/api/social/friends");
      setFriends(data.friends || []);
      setIncoming(data.incoming || []);
      setOutgoing(data.outgoing || []);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load friends."); }
  }, []);

  // --- realtime: new messages addressed to me ---
  useEffect(() => {
    if (!me) return;
    const channel = getSupabase()
      .channel("chat-" + me)
      .on("postgres_changes",
        { event: "INSERT", schema: "public", table: "messages", filter: `recipient_id=eq.${me}` },
        (payload) => {
          const msg = payload.new as Message;
          setMessages((prev) => (active && msg.sender_id === active.user.user_id ? [...prev, msg] : prev));
        })
      .subscribe();
    return () => { void getSupabase().removeChannel(channel); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me, active]);

  useEffect(() => { threadRef.current?.scrollTo(0, threadRef.current.scrollHeight); }, [messages]);

  // Resolve signed URLs for any media messages we haven't resolved yet.
  useEffect(() => {
    (async () => {
      for (const m of messages) {
        if (m.media_url && !mediaUrls[m.media_url]) {
          const { data } = await getSupabase().storage.from("chat-media").createSignedUrl(m.media_url, 3600);
          if (data?.signedUrl) setMediaUrls((prev) => ({ ...prev, [m.media_url as string]: data.signedUrl }));
        }
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messages]);

  async function saveProfile() {
    setError(""); setBusy("profile");
    try {
      const data = await api("/api/social/profile", {
        method: "PUT", body: JSON.stringify({ username, display_name: displayName, bio }),
      });
      setProfile(data.profile);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save profile."); }
    finally { setBusy(""); }
  }

  async function runSearch() {
    setError("");
    if (search.trim().length < 2) { setResults([]); return; }
    try {
      const data = await api("/api/social/users?q=" + encodeURIComponent(search.trim()));
      setResults(data.users || []);
    } catch (e) { setError(e instanceof Error ? e.message : "Search failed."); }
  }

  async function addFriend(username: string) {
    setError(""); setBusy("add-" + username);
    try {
      await api("/api/social/friends", { method: "POST", body: JSON.stringify({ username }) });
      await loadFriends(); await runSearch();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not send request."); }
    finally { setBusy(""); }
  }

  async function respond(id: string, action: "accept" | "decline") {
    setError("");
    try {
      await api("/api/social/friends", { method: "PATCH", body: JSON.stringify({ id, action }) });
      await loadFriends();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not update request."); }
  }

  async function openConversation(edge: FriendEdge) {
    setActive(edge); setMessages([]); setError("");
    try {
      const data = await api("/api/social/messages?with=" + encodeURIComponent(edge.user.user_id));
      setMessages(data.messages || []);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load messages."); }
  }

  async function sendMessage(mediaPath?: string, mediaType?: "image" | "voice") {
    if (!active) return;
    if (!mediaPath && !draft.trim()) return;
    setBusy("send");
    try {
      const data = await api("/api/social/messages", {
        method: "POST",
        body: JSON.stringify({ recipientId: active.user.user_id, body: draft, mediaPath, mediaType }),
      });
      setMessages((prev) => [...prev, data.message]);
      setDraft("");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not send."); }
    finally { setBusy(""); }
  }

  async function uploadAndSend(file: Blob, mime: string) {
    if (!me) return;
    const check = validateMedia(mime, file.size);
    if (!check.ok) { setError(check.error); return; }
    setBusy("send");
    try {
      const ext = extensionForMime(mime) || "bin";
      const path = `${me}/${crypto.randomUUID()}.${ext}`;
      const { error: upErr } = await getSupabase().storage.from("chat-media").upload(path, file, { contentType: mime, upsert: false });
      if (upErr) throw new Error(upErr.message);
      await sendMessage(path, check.value.kind);
    } catch (e) { setError(e instanceof Error ? e.message : "Upload failed."); }
    finally { setBusy(""); }
  }

  function onPickImage(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) void uploadAndSend(file, file.type || "image/png");
    e.target.value = "";
  }

  async function toggleRecording() {
    if (recording) {
      recorderRef.current?.stop();
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      chunksRef.current = [];
      recorder.ondataavailable = (ev) => { if (ev.data.size) chunksRef.current.push(ev.data); };
      recorder.onstop = () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(chunksRef.current, { type: recorder.mimeType || "audio/webm" });
        void uploadAndSend(blob, recorder.mimeType || "audio/webm");
        setRecording(false);
      };
      recorderRef.current = recorder;
      recorder.start();
      setRecording(true);
    } catch { setError("Microphone access was denied."); }
  }

  if (!authChecked) return <main className="chat-shell"><Loader2 className="spin" /> Loading chat…</main>;
  if (!me) return (
    <main className="chat-shell">
      <div className="chat-card"><MessageCircle size={28} />
        <h1>CyberLab Chat</h1>
        <p>Sign in to set a username and chat with other members.</p>
        <Link className="network-run" href="/login">Sign in</Link>
      </div>
    </main>
  );

  if (!profile) return (
    <main className="chat-shell">
      <div className="chat-card">
        <h1>Pick your username</h1>
        <p>Other members find you by this handle to send a friend request.</p>
        <label className="vault-field"><span>Username (3–20: a–z, 0–9, _)</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="neo_trace" /></label>
        <label className="vault-field"><span>Display name (optional)</span>
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Neo" /></label>
        <label className="vault-field"><span>Bio (optional)</span>
          <input value={bio} onChange={(e) => setBio(e.target.value)} placeholder="Red-team · Lagos" /></label>
        {error && <div className="chat-error">{error}</div>}
        <button className="network-run" disabled={busy === "profile"} onClick={saveProfile}>
          {busy === "profile" ? "Saving…" : "Create profile"}</button>
      </div>
    </main>
  );

  return (
    <main className="chat-layout">
      <aside className="chat-sidebar">
        <div className="chat-me">@{profile.username}{profile.display_name ? " · " + profile.display_name : ""}</div>

        <div className="chat-search">
          <input value={search} placeholder="Find people by username"
            onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => e.key === "Enter" && runSearch()} />
          <button className="icon-button" onClick={runSearch} aria-label="Search"><UserPlus size={15} /></button>
        </div>
        {results.map((u) => (
          <div className="chat-user-row" key={u.user_id}>
            <span>@{u.username}</span>
            {u.friendship?.status === "accepted" ? <span className="chat-tag">friend</span>
              : u.friendship?.status === "pending" ? <span className="chat-tag">pending</span>
              : <button className="chat-mini" disabled={busy === "add-" + u.username} onClick={() => addFriend(u.username)}>Add</button>}
          </div>
        ))}

        {incoming.length > 0 && <div className="chat-section">Friend requests</div>}
        {incoming.map((r) => (
          <div className="chat-user-row" key={r.id}>
            <span>@{r.user.username}</span>
            <span style={{ display: "flex", gap: 4 }}>
              <button className="chat-mini" onClick={() => respond(r.id, "accept")} aria-label="Accept"><Check size={13} /></button>
              <button className="chat-mini ghost" onClick={() => respond(r.id, "decline")} aria-label="Decline"><X size={13} /></button>
            </span>
          </div>
        ))}

        <div className="chat-section">Friends</div>
        {friends.length === 0 && <div className="chat-empty">No friends yet. Search a username above.</div>}
        {friends.map((f) => (
          <button key={f.id} className={"chat-friend" + (active?.id === f.id ? " active" : "")} onClick={() => openConversation(f)}>
            @{f.user.username}
          </button>
        ))}
        {outgoing.length > 0 && <>
          <div className="chat-section">Sent requests</div>
          {outgoing.map((o) => <div className="chat-user-row" key={o.id}><span>@{o.user.username}</span><span className="chat-tag">pending</span></div>)}
        </>}
      </aside>

      <section className="chat-main">
        {!active ? (
          <div className="chat-empty-main"><MessageCircle size={30} /><p>Select a friend to start chatting.</p></div>
        ) : (
          <>
            <header className="chat-header">@{active.user.username}</header>
            <div className="chat-thread" ref={threadRef}>
              {messages.map((m) => (
                <div key={m.id} className={"chat-bubble " + (m.sender_id === me ? "mine" : "theirs")}>
                  {m.body && <div>{m.body}</div>}
                  {m.media_type === "image" && m.media_url && mediaUrls[m.media_url] &&
                    <img src={mediaUrls[m.media_url]} alt="attachment" className="chat-image" />}
                  {m.media_type === "voice" && m.media_url && mediaUrls[m.media_url] &&
                    <audio controls src={mediaUrls[m.media_url]} />}
                  <time>{new Date(m.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time>
                </div>
              ))}
            </div>
            {error && <div className="chat-error">{error}</div>}
            <div className="chat-compose">
              <label className="icon-button" aria-label="Send image">
                <ImagePlus size={17} />
                <input type="file" accept="image/*" hidden onChange={onPickImage} />
              </label>
              <button className={"icon-button" + (recording ? " recording" : "")} onClick={toggleRecording}
                aria-label={recording ? "Stop recording" : "Record voice"}>
                {recording ? <Square size={16} /> : <Mic size={17} />}
              </button>
              <input value={draft} maxLength={MESSAGE_MAX} placeholder={recording ? "Recording…" : "Message"}
                onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && sendMessage()} />
              <button className="icon-button send" disabled={busy === "send"} onClick={() => sendMessage()} aria-label="Send">
                {busy === "send" ? <Loader2 size={16} className="spin" /> : <Send size={17} />}
              </button>
            </div>
          </>
        )}
      </section>
    </main>
  );
}
