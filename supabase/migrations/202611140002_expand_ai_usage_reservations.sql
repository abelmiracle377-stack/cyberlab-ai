-- Expand the per-request token ceiling without changing RPC signatures or existing rows.
-- The monthly allowance remains controlled by each caller's p_monthly_limit.
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
  if p_user_id is null or p_estimated_tokens < 1 or p_estimated_tokens > 60000
     or p_monthly_limit < 1000 or p_monthly_limit > 2000000 then
    raise exception 'Invalid AI usage reservation.';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text || date_trunc('month', now())::text, 0));

  update public.ai_usage_events
  set status = 'failed', actual_tokens = 0, settled_at = now()
  where user_id = p_user_id
    and status = 'reserved'
    and created_at < now() - interval '20 minutes';

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
  if p_actual_tokens < 0 or p_actual_tokens > 60000
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
