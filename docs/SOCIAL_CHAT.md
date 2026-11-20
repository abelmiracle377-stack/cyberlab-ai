# CyberLab AI — Community Chat

A member-to-member social layer: usernames, friend requests, and 1:1 direct
messaging with text, pictures and voice notes. Built on the project's existing
Supabase auth, Postgres, Realtime and Storage.

## Setup

Apply the migration in the linked Supabase project's SQL Editor:

```
supabase/migrations/202611200001_social_chat.sql
```

It creates the `profiles`, `friendships` and `messages` tables (with Row-Level
Security), enables Realtime on `messages`, and creates a **private**
`chat-media` storage bucket with owner-upload / participant-read policies. No new
environment variables are required beyond the Supabase keys the app already uses.

## Data model

- **profiles** — one row per auth user. Unique `username` (`^[a-z0-9_]{3,20}$`),
  optional `display_name`, `avatar_url`, `bio`. Any signed-in user can read
  profiles (to find people); only the owner can write their own.
- **friendships** — a requester → addressee edge with `status`
  (`pending` / `accepted` / `declined` / `blocked`). Only the two parties can
  read it; the requester creates it; the addressee accepts/declines; either side
  can block or remove.
- **messages** — `sender_id`, `recipient_id`, `body`, optional `media_url` +
  `media_type` (`image` / `voice`), `read_at`. Participants can read; a sender
  can insert **only to an accepted friend** (enforced in the RLS insert check);
  the recipient marks messages read.

## Media privacy

Pictures and voice notes go to the private `chat-media` bucket under the
uploader's `user_id/` folder (enforced by the storage insert policy). The read
policy only grants access to the sender or recipient of a message that
references the object, and the client fetches **signed URLs** (1-hour expiry) to
display media. Media is never world-readable.

## API

All routes are auth-gated (`/api/social/*`, Node runtime) and validate input via
the pure helpers in `lib/social.ts` (unit-tested in `tests/social.test.ts`):

- `GET/PUT /api/social/profile` — read or set your username/display name/bio.
- `GET /api/social/users?q=` — search people by username; annotates friendship status.
- `GET/POST/PATCH/DELETE /api/social/friends` — list, request, accept/decline/block, remove.
- `GET/POST /api/social/messages?with=<id>` — conversation history and sending.

## End-to-end encryption

Direct messages are end-to-end encrypted in the browser (`lib/e2ee.ts`, WebCrypto):

- Each member holds an **ECDH P-256** key pair. The private key is generated on
  the device and stored only in that browser's `localStorage` (exported JWK); it
  is never sent to the server. The public key is published to `profiles.public_key`.
- For a conversation, both sides derive the **same** AES-GCM key from
  ECDH(their private key, the other's public key). Message text is encrypted with
  AES-256-GCM; the server stores only base64 ciphertext plus the IV
  (`messages.body`, `body_iv`, `encrypted = true`).
- **Media is encrypted too**: picture/voice bytes are AES-GCM encrypted in the
  browser before upload, so the private bucket holds ciphertext; the recipient
  downloads and decrypts it client-side (`media_iv`).
- The conversation header shows a lock when the other party has published a key.
  If a brand-new friend hasn't opened chat yet (no key), messages fall back to
  server-stored (RLS-protected) delivery until their key appears.

Apply `supabase/migrations/202611200002_social_chat_e2ee.sql` for the
`public_key` / IV columns.

**Honest limits.** This is baseline E2EE (static ECDH keys + AES-GCM): it keeps
message content and media out of the server's reach, and AES-GCM authentication
rejects tampering. It does **not** provide per-message forward secrecy (no Signal
double ratchet), and because the private key lives on one device, clearing site
data or switching devices creates a new key — older messages encrypted to the
old key can't be read on the new device (no key-escrow/backup yet). Conversation
metadata (who messages whom, and when) remains visible to the server, as with
any mainstream messenger.

## UI

`/chat` (linked under **Community** in the sidebar): pick a username, search and
add friends, accept incoming requests, and chat. The composer supports text, an
image picker, and in-browser voice recording (`MediaRecorder`). New incoming
messages arrive live over a Supabase Realtime subscription.
