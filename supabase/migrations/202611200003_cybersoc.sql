-- CyberSOC: persisted alerts and response actions for the web dashboard.
-- Run after the earlier migrations in the linked Supabase SQL Editor.

create table if not exists public.soc_alerts (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  alert_key text not null,
  rule text not null,
  title text not null,
  severity text not null default 'medium'
    check (severity in ('informational','low','medium','high','critical')),
  score int not null default 0 check (score between 0 and 100),
  mitre jsonb not null default '{}'::jsonb,
  description text not null default '',
  entities jsonb not null default '{}'::jsonb,
  event_count int not null default 0,
  first_seen text not null default '',
  last_seen text not null default '',
  recommended_actions jsonb not null default '[]'::jsonb,
  source text not null default 'companion',
  status text not null default 'new'
    check (status in ('new','acknowledged','investigating','contained','resolved','false_positive')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint soc_alert_unique_key unique (owner, alert_key)
);

create table if not exists public.soc_actions (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  alert_id uuid not null references public.soc_alerts(id) on delete cascade,
  action text not null,
  params jsonb not null default '{}'::jsonb,
  status text not null default 'pending'
    check (status in ('pending','approved','executed','failed','declined')),
  result jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists soc_alerts_owner_idx on public.soc_alerts(owner, status, severity);
create index if not exists soc_actions_alert_idx on public.soc_actions(alert_id);

alter table public.soc_alerts enable row level security;
alter table public.soc_actions enable row level security;

-- Each operator sees and manages only their own SOC data.
drop policy if exists "Owner manages soc_alerts" on public.soc_alerts;
create policy "Owner manages soc_alerts" on public.soc_alerts
  for all using (auth.uid() = owner) with check (auth.uid() = owner);
drop policy if exists "Owner manages soc_actions" on public.soc_actions;
create policy "Owner manages soc_actions" on public.soc_actions
  for all using (auth.uid() = owner) with check (auth.uid() = owner);

-- Reuse the shared updated_at trigger function if present; define if not.
create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists soc_alerts_touch on public.soc_alerts;
create trigger soc_alerts_touch before update on public.soc_alerts
  for each row execute function public.touch_updated_at();
drop trigger if exists soc_actions_touch on public.soc_actions;
create trigger soc_actions_touch before update on public.soc_actions
  for each row execute function public.touch_updated_at();

-- Live alert updates on the dashboard.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'soc_alerts'
  ) then
    alter publication supabase_realtime add table public.soc_alerts;
  end if;
end $$;
