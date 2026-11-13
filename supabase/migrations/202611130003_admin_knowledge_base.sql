create table if not exists public.knowledge_items (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 200),
  category text not null default 'Other',
  source text not null default 'Analyst note',
  tags text not null default '',
  content text not null check (char_length(content) between 1 and 30000),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists knowledge_items_status_created_idx on public.knowledge_items(status, created_at desc);
alter table public.knowledge_items enable row level security;
-- No end-user policies: access is mediated by server routes using the service-role key and adminGate().
