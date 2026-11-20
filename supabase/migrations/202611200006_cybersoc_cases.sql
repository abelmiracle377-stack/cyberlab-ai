-- CyberSOC: case management — group alerts into one investigation.
-- Run after 202611200005_cybersoc_tuning.sql in the linked Supabase SQL Editor.

create table if not exists public.soc_cases (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 300),
  summary text check (summary is null or char_length(summary) <= 4000),
  severity text not null default 'medium'
    check (severity in ('informational','low','medium','high','critical')),
  status text not null default 'open'
    check (status in ('open','investigating','contained','resolved','closed')),
  assignee uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz
);

create index if not exists soc_cases_owner_idx on public.soc_cases(owner, created_at desc);

-- An alert belongs to at most one case; clearing the case leaves the alert.
alter table public.soc_alerts add column if not exists case_id uuid
  references public.soc_cases(id) on delete set null;
create index if not exists soc_alerts_case_idx on public.soc_alerts(case_id);

alter table public.soc_cases enable row level security;

drop policy if exists "Owner manages soc_cases" on public.soc_cases;
create policy "Owner manages soc_cases" on public.soc_cases
  for all using (auth.uid() = owner) with check (auth.uid() = owner);

drop trigger if exists soc_cases_touch on public.soc_cases;
create trigger soc_cases_touch before update on public.soc_cases
  for each row execute function public.touch_updated_at();
