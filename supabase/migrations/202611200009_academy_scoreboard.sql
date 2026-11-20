-- CyberLab Academy — CTF scoreboard (cross-user ranking by flags captured).
-- Run after 202611200008_academy_verify.sql in the linked Supabase SQL Editor.
--
-- academy_progress is owner-scoped under RLS, so a ranking across users needs a
-- SECURITY DEFINER aggregate. It exposes only a public handle (the chat username
-- if the player set one, else 'anonymous') and the flag count — never the owner
-- id or which flags. Each (owner, task_id) is unique, so count = flags captured.

create or replace function public.ctf_scoreboard(p_limit int default 50)
returns table (display_name text, flags int, last_capture timestamptz)
language sql
security definer
set search_path = public
as $$
  select coalesce(p.username, 'anonymous') as display_name,
         count(*)::int as flags,
         max(ap.created_at) as last_capture
  from public.academy_progress ap
  left join public.profiles p on p.user_id = ap.owner
  where ap.task_id like 'ctf-%'
  group by ap.owner, p.username
  order by flags desc, last_capture asc
  limit greatest(1, least(p_limit, 200));
$$;

revoke all on function public.ctf_scoreboard(int) from public;
grant execute on function public.ctf_scoreboard(int) to anon, authenticated;
