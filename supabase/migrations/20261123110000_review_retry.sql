-- Scheduled retry of alert reviews that didn't finish.
--
-- .github/workflows/review-retry.yml calls POST /v1/worker/reviews/retry
-- every 15 minutes. It re-reviews rate_limited alerts, unavailable alerts
-- with fewer than 5 failed retries, and pending alerts stuck for over 10
-- minutes, least recently updated first.
--
-- review_attempts counts failed retries, so a review that always fails
-- (for example Groq keeps returning an unusable answer) stops after 5
-- instead of costing a Groq call every 15 minutes forever.

alter table public.alerts
    add column if not exists review_attempts integer not null default 0;

create index if not exists alerts_review_retry_idx
    on public.alerts (updated_at)
    where review_status in ('pending', 'unavailable', 'rate_limited');
