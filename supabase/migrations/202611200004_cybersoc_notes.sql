-- CyberSOC: analyst workflow — alert assignment and investigation notes.
-- Run after 202611200003_cybersoc.sql in the linked Supabase SQL Editor.

alter table public.soc_alerts add column if not exists assignee uuid references auth.users(id) on delete set null;

create table if not exists public.soc_notes (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  alert_id uuid not null references public.soc_alerts(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);

create index if not exists soc_notes_alert_idx on public.soc_notes(alert_id, created_at);

alter table public.soc_notes enable row level security;

drop policy if exists "Owner manages soc_notes" on public.soc_notes;
create policy "Owner manages soc_notes" on public.soc_notes
  for all using (auth.uid() = owner) with check (auth.uid() = owner);
