-- CyberSOC: detection tuning — operator suppression rules (noise reduction).
-- Run after 202611200004_cybersoc_notes.sql in the linked Supabase SQL Editor.

create table if not exists public.soc_suppressions (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  rule text,
  host text,
  src_ip text,
  match_user text,
  action text not null default 'drop' check (action in ('drop','cap')),
  max_severity text check (max_severity in ('informational','low','medium','high','critical')),
  reason text check (reason is null or char_length(reason) <= 500),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  -- A suppression must select on at least one field, or it would mute everything.
  constraint soc_suppressions_has_selector check (
    rule is not null or host is not null or src_ip is not null or match_user is not null
  )
);

create index if not exists soc_suppressions_owner_idx on public.soc_suppressions(owner, created_at desc);

alter table public.soc_suppressions enable row level security;

drop policy if exists "Owner manages soc_suppressions" on public.soc_suppressions;
create policy "Owner manages soc_suppressions" on public.soc_suppressions
  for all using (auth.uid() = owner) with check (auth.uid() = owner);
