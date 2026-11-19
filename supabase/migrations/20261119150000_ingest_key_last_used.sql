alter table public.ingest_keys
    add column if not exists last_used_at timestamptz;
