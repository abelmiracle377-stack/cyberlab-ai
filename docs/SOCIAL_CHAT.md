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

## UI

`/chat` (linked under **Community** in the sidebar): pick a username, search and
add friends, accept incoming requests, and chat. The composer supports text, an
image picker, and in-browser voice recording (`MediaRecorder`). New incoming
messages arrive live over a Supabase Realtime subscription.
