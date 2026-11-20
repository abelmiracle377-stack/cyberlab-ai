-- CyberLab AI social chat: profiles, friendships and direct messages.
-- Run this migration in the linked Supabase project's SQL Editor.

-- Public profiles (one per auth user), with a unique handle for discovery.
create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9_]{3,20}$'),
  display_name text not null default '' check (char_length(display_name) <= 60),
  avatar_url text,
  bio text not null default '' check (char_length(bio) <= 280),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Friendship edges. One row per requester->addressee pair.
create table if not exists public.friendships (
  id uuid primary key default gen_random_uuid(),
  requester_id uuid not null references auth.users(id) on delete cascade,
  addressee_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted','declined','blocked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint friendship_not_self check (requester_id <> addressee_id),
  constraint friendship_unique_pair unique (requester_id, addressee_id)
);

-- Direct messages: text and/or a media attachment (image or voice).
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  body text not null default '' check (char_length(body) <= 4000),
  media_url text,
  media_type text check (media_type in ('image','voice')),
  created_at timestamptz not null default now(),
  read_at timestamptz,
  constraint message_has_content check (char_length(body) > 0 or media_url is not null),
  constraint message_not_self check (sender_id <> recipient_id)
);

create index if not exists profiles_username_idx on public.profiles(username);
create index if not exists friendships_requester_idx on public.friendships(requester_id, status);
create index if not exists friendships_addressee_idx on public.friendships(addressee_id, status);
create index if not exists messages_pair_idx on public.messages(sender_id, recipient_id, created_at desc);
create index if not exists messages_recipient_idx on public.messages(recipient_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.friendships enable row level security;
alter table public.messages enable row level security;

-- Profiles: any signed-in user can read handles (to find friends); owner writes own.
drop policy if exists "Authenticated can read profiles" on public.profiles;
create policy "Authenticated can read profiles" on public.profiles
  for select using (auth.uid() is not null);
drop policy if exists "Users insert their own profile" on public.profiles;
create policy "Users insert their own profile" on public.profiles
  for insert with check (auth.uid() = user_id);
drop policy if exists "Users update their own profile" on public.profiles;
create policy "Users update their own profile" on public.profiles
  for update using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Friendships: either party sees the edge; requester creates; either side updates/removes.
drop policy if exists "Friendship parties can read" on public.friendships;
create policy "Friendship parties can read" on public.friendships
  for select using (auth.uid() in (requester_id, addressee_id));
drop policy if exists "Requester can create friendship" on public.friendships;
create policy "Requester can create friendship" on public.friendships
  for insert with check (auth.uid() = requester_id and requester_id <> addressee_id);
drop policy if exists "Either party can update friendship" on public.friendships;
create policy "Either party can update friendship" on public.friendships
  for update using (auth.uid() in (requester_id, addressee_id))
  with check (auth.uid() in (requester_id, addressee_id));
drop policy if exists "Either party can remove friendship" on public.friendships;
create policy "Either party can remove friendship" on public.friendships
  for delete using (auth.uid() in (requester_id, addressee_id));

-- Messages: sender or recipient reads; sender writes only to an accepted friend; recipient marks read.
drop policy if exists "Participants read messages" on public.messages;
create policy "Participants read messages" on public.messages
  for select using (auth.uid() in (sender_id, recipient_id));
drop policy if exists "Sender writes to accepted friends" on public.messages;
create policy "Sender writes to accepted friends" on public.messages
  for insert with check (
    auth.uid() = sender_id and exists (
      select 1 from public.friendships f
      where f.status = 'accepted'
        and ((f.requester_id = sender_id and f.addressee_id = recipient_id)
          or (f.addressee_id = sender_id and f.requester_id = recipient_id))
    )
  );
drop policy if exists "Recipient marks messages read" on public.messages;
create policy "Recipient marks messages read" on public.messages
  for update using (auth.uid() = recipient_id) with check (auth.uid() = recipient_id);

-- Keep updated_at fresh on profiles and friendships.
create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_touch_updated_at on public.profiles;
create trigger profiles_touch_updated_at before update on public.profiles
  for each row execute function public.touch_updated_at();
drop trigger if exists friendships_touch_updated_at on public.friendships;
create trigger friendships_touch_updated_at before update on public.friendships
  for each row execute function public.touch_updated_at();

-- Live message delivery via Supabase Realtime.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;

-- Private media bucket for chat pictures and voice notes.
insert into storage.buckets (id, name, public)
  values ('chat-media', 'chat-media', false)
  on conflict (id) do nothing;

-- Owner uploads only into their own uid-prefixed folder.
drop policy if exists "Users upload own chat media" on storage.objects;
create policy "Users upload own chat media" on storage.objects
  for insert to authenticated with check (
    bucket_id = 'chat-media' and (storage.foldername(name))[1] = auth.uid()::text
  );
-- Only the sender or recipient of a message that references the object may read it.
drop policy if exists "Participants read chat media" on storage.objects;
create policy "Participants read chat media" on storage.objects
  for select to authenticated using (
    bucket_id = 'chat-media' and exists (
      select 1 from public.messages m
      where m.media_url = name and auth.uid() in (m.sender_id, m.recipient_id)
    )
  );
-- Owner may delete their own uploads.
drop policy if exists "Users delete own chat media" on storage.objects;
create policy "Users delete own chat media" on storage.objects
  for delete to authenticated using (
    bucket_id = 'chat-media' and (storage.foldername(name))[1] = auth.uid()::text
  );
