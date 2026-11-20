-- CyberLab Academy — learner progress and issued certifications.
-- Run after 202611200006_cybersoc_cases.sql in the linked Supabase SQL Editor.

create table if not exists public.academy_progress (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  task_id text not null check (char_length(task_id) between 1 and 120),
  created_at timestamptz not null default now(),
  unique(owner, task_id)
);
create index if not exists academy_progress_owner_idx on public.academy_progress(owner);

create table if not exists public.academy_certificates (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  track_id text not null,
  code text not null,
  serial text not null unique,
  percent int not null check (percent between 0 and 100),
  issued_at timestamptz not null default now(),
  unique(owner, track_id)
);
create index if not exists academy_certificates_owner_idx on public.academy_certificates(owner);

alter table public.academy_progress enable row level security;
alter table public.academy_certificates enable row level security;

drop policy if exists "Owner manages academy_progress" on public.academy_progress;
create policy "Owner manages academy_progress" on public.academy_progress
  for all using (auth.uid() = owner) with check (auth.uid() = owner);

drop policy if exists "Owner manages academy_certificates" on public.academy_certificates;
create policy "Owner manages academy_certificates" on public.academy_certificates
  for all using (auth.uid() = owner) with check (auth.uid() = owner);
