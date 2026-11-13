-- CyberLab AI investigation cases
-- Run this migration in the linked Supabase project's SQL Editor.

create table if not exists public.investigation_cases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 160),
  status text not null default 'open' check (status in ('open','investigating','contained','resolved','closed')),
  severity text not null default 'medium' check (severity in ('informational','low','medium','high','critical')),
  summary text not null default '',
  scope text not null default '',
  tags text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.investigation_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.investigation_cases(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  source text not null check (char_length(source) between 1 and 80),
  event_type text not null check (char_length(event_type) between 1 and 120),
  severity text not null default 'informational' check (severity in ('informational','low','medium','high','critical')),
  title text not null check (char_length(title) between 1 and 200),
  details jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create index if not exists investigation_cases_user_updated_idx on public.investigation_cases(user_id, updated_at desc);
create index if not exists investigation_events_case_time_idx on public.investigation_events(case_id, occurred_at desc);
create index if not exists investigation_events_user_idx on public.investigation_events(user_id);

alter table public.investigation_cases enable row level security;
alter table public.investigation_events enable row level security;

drop policy if exists "Users manage their investigation cases" on public.investigation_cases;
create policy "Users manage their investigation cases" on public.investigation_cases
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "Users manage their investigation events" on public.investigation_events;
create policy "Users manage their investigation events" on public.investigation_events
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

create or replace function public.touch_investigation_case_updated_at()
returns trigger language plpgsql as $$
begin
  update public.investigation_cases set updated_at = now() where id = new.case_id;
  return new;
end;
$$;

drop trigger if exists investigation_event_touches_case on public.investigation_events;
create trigger investigation_event_touches_case
  after insert or update or delete on public.investigation_events
  for each row execute function public.touch_investigation_case_updated_at();
