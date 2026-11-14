create table if not exists public.ai_usage_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  reserved_tokens integer not null default 0 check (reserved_tokens >= 0),
  actual_tokens integer not null default 0 check (actual_tokens >= 0),
  provider text,
  model text,
  status text not null default 'reserved' check (status in ('reserved','completed','failed')),
  created_at timestamptz not null default now(),
  settled_at timestamptz
);

create index if not exists ai_usage_events_user_created_idx
  on public.ai_usage_events(user_id, created_at desc);

alter table public.ai_usage_events enable row level security;
drop policy if exists "users read own AI usage" on public.ai_usage_events;
create policy "users read own AI usage" on public.ai_usage_events
  for select using (auth.uid() = user_id);

create or replace function public.reserve_cyberlab_ai_usage(
  p_user_id uuid,
  p_estimated_tokens integer,
  p_monthly_limit integer default 200000
) returns table(allowed boolean, reservation_id uuid, used_tokens bigint, monthly_limit integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_used bigint;
  v_id uuid;
begin
  if p_user_id is null or p_estimated_tokens < 1 or p_estimated_tokens > 10000
     or p_monthly_limit < 1000 or p_monthly_limit > 2000000 then
    raise exception 'Invalid AI usage reservation.';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text || date_trunc('month', now())::text, 0));

  select coalesce(sum(
    case when status = 'reserved' then reserved_tokens
         when status = 'completed' then actual_tokens
         else 0 end
  ), 0)
  into v_used
  from public.ai_usage_events
  where user_id = p_user_id
    and created_at >= date_trunc('month', now());

  if v_used + p_estimated_tokens > p_monthly_limit then
    return query select false, null::uuid, v_used, p_monthly_limit;
    return;
  end if;

  insert into public.ai_usage_events(user_id, reserved_tokens, status)
  values (p_user_id, p_estimated_tokens, 'reserved')
  returning id into v_id;

  return query select true, v_id, v_used + p_estimated_tokens, p_monthly_limit;
end;
$$;

create or replace function public.settle_cyberlab_ai_usage(
  p_reservation_id uuid,
  p_actual_tokens integer,
  p_provider text,
  p_model text,
  p_status text
) returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_actual_tokens < 0 or p_actual_tokens > 10000
     or p_status not in ('completed','failed') then
    raise exception 'Invalid AI usage settlement.';
  end if;

  update public.ai_usage_events
  set actual_tokens = case when p_status = 'completed' then p_actual_tokens else 0 end,
      provider = left(coalesce(p_provider,''),120),
      model = left(coalesce(p_model,''),180),
      status = p_status,
      settled_at = now()
  where id = p_reservation_id and status = 'reserved';

  return found;
end;
$$;

revoke all on function public.reserve_cyberlab_ai_usage(uuid,integer,integer) from public, anon, authenticated;
revoke all on function public.settle_cyberlab_ai_usage(uuid,integer,text,text,text) from public, anon, authenticated;
grant execute on function public.reserve_cyberlab_ai_usage(uuid,integer,integer) to service_role;
grant execute on function public.settle_cyberlab_ai_usage(uuid,integer,text,text,text) to service_role;

comment on table public.ai_usage_events is 'Server-side AI usage reservations and settlements. User-visible rows are owner-scoped by RLS.';
