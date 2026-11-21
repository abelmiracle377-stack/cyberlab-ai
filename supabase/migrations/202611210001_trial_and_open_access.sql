-- Adds a 2-day free trial state to subscriptions.
alter table public.subscriptions drop constraint if exists subscriptions_status_check;
alter table public.subscriptions add constraint subscriptions_status_check
  check (status in ('pending','trial','active','past_due','cancelled','suspended','expired','comped'));
alter table public.subscriptions add column if not exists trial_ends_at timestamptz;
