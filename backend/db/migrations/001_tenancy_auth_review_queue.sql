-- backend/db/migrations/001_tenancy_auth_review_queue.sql
--
-- Run once, as the table owner, after schema.sql:
--   psql "$OWNER_DATABASE_URL" -v ON_ERROR_STOP=1 -f backend/db/migrations/001_tenancy_auth_review_queue.sql
-- Safe to run again: every statement checks before it changes anything.
--
-- 1. Review-queue columns on alerts.
-- 2. wazuh_id unique per business, not globally.
-- 3. Findings columns the scanners now return.
-- 4. RLS on organizations and incident_alerts.
-- 5. trojan_lookup role + SECURITY DEFINER lookups for auth, key lookup, and
--    the review worker's due-alerts sweep.
-- 6. Remove the seeded 'changeme' key.

BEGIN;

-- 1. Review-queue columns ----------------------------------------------------
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS review_attempts   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS review_started_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS next_review_at    TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS review_error      TEXT;

CREATE INDEX IF NOT EXISTS idx_alerts_review_due
    ON alerts (review_status, next_review_at)
    WHERE review_status IN ('pending', 'rate_limited', 'reviewing');

-- 2. wazuh_id unique per business --------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'alerts_wazuh_id_key' AND conrelid = 'alerts'::regclass) THEN
        ALTER TABLE alerts DROP CONSTRAINT alerts_wazuh_id_key;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'alerts_org_wazuh_key' AND conrelid = 'alerts'::regclass) THEN
        ALTER TABLE alerts ADD CONSTRAINT alerts_org_wazuh_key UNIQUE (org_id, wazuh_id);
    END IF;
END$$;

-- 3. Findings columns --------------------------------------------------------
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence       TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS raw_output_ref TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS found_at       TIMESTAMPTZ DEFAULT NOW();

-- 4. RLS on organizations and incident_alerts --------------------------------
ALTER TABLE organizations   ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations   FORCE  ROW LEVEL SECURITY;
ALTER TABLE incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_alerts FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS org_isolation_organizations ON organizations;
CREATE POLICY org_isolation_organizations ON organizations
    USING (id = current_setting('app.org_id', true)::uuid);

DROP POLICY IF EXISTS org_isolation_incident_alerts ON incident_alerts;
CREATE POLICY org_isolation_incident_alerts ON incident_alerts
    USING (EXISTS (
        SELECT 1 FROM incidents i
        WHERE i.id = incident_id
          AND i.org_id = current_setting('app.org_id', true)::uuid
    ));

-- 5. trojan_lookup role + SECURITY DEFINER functions -------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trojan_lookup') THEN
        CREATE ROLE trojan_lookup NOLOGIN;
    END IF;
END$$;

GRANT USAGE ON SCHEMA public TO trojan_lookup;
GRANT SELECT ON api_keys, users, alerts TO trojan_lookup;

CREATE OR REPLACE FUNCTION trojan_org_for_key(p_key_hash text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
    AS $$ SELECT org_id FROM api_keys WHERE key_hash = p_key_hash $$;

CREATE OR REPLACE FUNCTION trojan_user_for_login(p_email text)
    RETURNS TABLE (id uuid, org_id uuid, password_hash text, role text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
    AS $$ SELECT u.id, u.org_id, u.password_hash, u.role
          FROM users u WHERE lower(u.email) = lower(p_email) $$;

CREATE OR REPLACE FUNCTION trojan_due_reviews(p_limit integer)
    RETURNS TABLE (id integer, org_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
    AS $$ SELECT a.id, a.org_id FROM alerts a
          WHERE (a.review_status IN ('pending', 'rate_limited')
                 AND (a.next_review_at IS NULL OR a.next_review_at <= now()))
             OR (a.review_status = 'reviewing'
                 AND a.review_started_at < now() - interval '10 minutes')
          ORDER BY a.id
          LIMIT p_limit $$;

ALTER FUNCTION trojan_org_for_key(text)    OWNER TO trojan_lookup;
ALTER FUNCTION trojan_user_for_login(text) OWNER TO trojan_lookup;
ALTER FUNCTION trojan_due_reviews(integer) OWNER TO trojan_lookup;

REVOKE ALL ON FUNCTION trojan_org_for_key(text)    FROM PUBLIC;
REVOKE ALL ON FUNCTION trojan_user_for_login(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION trojan_due_reviews(integer) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rls') THEN
        GRANT EXECUTE ON FUNCTION trojan_org_for_key(text)    TO app_rls;
        GRANT EXECUTE ON FUNCTION trojan_user_for_login(text) TO app_rls;
        GRANT EXECUTE ON FUNCTION trojan_due_reviews(integer) TO app_rls;
    END IF;
END$$;

-- 6. Remove the seeded test key ----------------------------------------------
DELETE FROM api_keys WHERE key_hash = encode(sha256('changeme'::bytea), 'hex');

COMMIT;