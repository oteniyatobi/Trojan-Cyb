-- Per-business ingest keys and a review status on alerts.
--
-- 1. ingest_keys: each business gets its own ingest key. The backend
--    hashes the bearer token (SHA-256, hex) and looks it up here to find
--    the business, so one backend serves many businesses and the caller
--    can't choose the business itself. Only the hash is stored.
-- 2. alerts.review_status / reviewed_at: the backend stores an alert first
--    and reviews it second, so an alert is never lost when Groq fails, and
--    the hourly Groq limit per business can count recent reviews.

create table public.ingest_keys (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations (id) on delete cascade,
    key_hash text not null unique check (key_hash ~ '^[0-9a-f]{64}$'),
    label text not null default '',
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);

create index ingest_keys_organization_id_idx
    on public.ingest_keys (organization_id);

-- Only the backend (service_role) reads keys. Browsers never see them.
alter table public.ingest_keys enable row level security;
revoke all on public.ingest_keys from public, anon, authenticated;
grant all on public.ingest_keys to service_role;

alter table public.alerts
    add column review_status text not null default 'pending'
        check (review_status in ('pending', 'done', 'unavailable', 'rate_limited')),
    add column reviewed_at timestamptz;

-- Alerts stored before this migration already carry their review.
update public.alerts
set review_status = case
        when ai_review ->> 'status' = 'done' then 'done'
        when ai_review = '{}'::jsonb then 'pending'
        else 'unavailable'
    end,
    reviewed_at = case when ai_review ->> 'status' = 'done' then created_at end;

-- The hourly limit counts done reviews per business in the last hour.
create index alerts_organization_reviewed_at_idx
    on public.alerts (organization_id, reviewed_at)
    where review_status = 'done';
