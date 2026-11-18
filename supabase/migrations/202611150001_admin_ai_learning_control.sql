create table if not exists public.cyberlab_settings (
  id boolean primary key default true check (id = true),
  ai_learning_enabled boolean not null default true,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);
alter table public.cyberlab_settings enable row level security;
insert into public.cyberlab_settings (id, ai_learning_enabled)
values (true, true)
on conflict (id) do nothing;
