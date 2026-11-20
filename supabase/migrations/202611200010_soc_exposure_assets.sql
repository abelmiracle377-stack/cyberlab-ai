-- CyberSOC: monitored external assets for recurring exposure sweeps.
-- Run after 202611200009_academy_scoreboard.sql in the linked Supabase SQL Editor.

create table if not exists public.soc_exposure_assets (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  asset text not null check (char_length(asset) between 1 and 255),
  label text check (label is null or char_length(label) <= 120),
  created_at timestamptz not null default now(),
  last_scanned_at timestamptz,
  unique(owner, asset)
);

create index if not exists soc_exposure_assets_owner_idx on public.soc_exposure_assets(owner, created_at desc);

alter table public.soc_exposure_assets enable row level security;

drop policy if exists "Owner manages soc_exposure_assets" on public.soc_exposure_assets;
create policy "Owner manages soc_exposure_assets" on public.soc_exposure_assets
  for all using (auth.uid() = owner) with check (auth.uid() = owner);
