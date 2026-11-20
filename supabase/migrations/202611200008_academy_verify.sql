-- CyberLab Academy — public certificate verification by serial.
-- Run after 202611200007_academy.sql in the linked Supabase SQL Editor.
--
-- academy_certificates is owner-scoped under RLS, so anonymous verifiers cannot
-- read it directly. This SECURITY DEFINER function returns only the public,
-- non-identifying fields for a single serial, so an employer can confirm a
-- certificate without any access to the owner or the rest of the table.

create or replace function public.verify_certificate(p_serial text)
returns table (code text, track_id text, percent int, issued_at timestamptz, serial text)
language sql
security definer
set search_path = public
as $$
  select code, track_id, percent, issued_at, serial
  from public.academy_certificates
  where serial = p_serial
  limit 1;
$$;

revoke all on function public.verify_certificate(text) from public;
grant execute on function public.verify_certificate(text) to anon, authenticated;
