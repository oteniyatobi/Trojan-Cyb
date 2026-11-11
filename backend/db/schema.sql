CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    wazuh_id TEXT UNIQUE NOT NULL,
    received_at TIMESTAMPTZ DEFAULT NOW(),
    event_time TIMESTAMPTZ,
    rule_id TEXT,
    rule_level INTEGER,
    rule_groups JSONB,
    signature_id TEXT,
    signature_name TEXT,
    suricata_sev INTEGER,
    fired_times INTEGER DEFAULT 1,
    description TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    agent_id TEXT,
    agent_name TEXT,
    manager_name TEXT,
    decoder_name TEXT,
    location TEXT,
    raw JSONB,
    status TEXT DEFAULT 'new',
    review_status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    attack_type TEXT,
    severity TEXT,
    headline TEXT,
    what_happened TEXT,
    why_it_matters TEXT,
    steps JSONB,
    when_to_escalate TEXT,
    model TEXT,
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    target TEXT NOT NULL,
    tools JSONB,
    requested_by TEXT,
    approved BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    target TEXT,
    finding_type TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    cve_id TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'new'
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    is_secret BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    who TEXT,
    action TEXT,
    object TEXT,
    at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO organizations (id, name) VALUES
    ('00000000-0000-0000-0000-000000000001', 'default'),
    ('00000000-0000-0000-0000-000000000002', 'demo-org-b')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS computers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    wazuh_agent_id TEXT,
    hostname TEXT,
    ip TEXT,
    last_seen TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT,
    status TEXT DEFAULT 'open',
    severity TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

-- Give reviews, settings and audit_log an owner org like the other tables.
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE settings ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);

-- Backfill rows that existed before org_id was added to the default org.
UPDATE reviews SET org_id = '00000000-0000-0000-0000-000000000001' WHERE org_id IS NULL;
UPDATE settings SET org_id = '00000000-0000-0000-0000-000000000001' WHERE org_id IS NULL;
UPDATE audit_log SET org_id = '00000000-0000-0000-0000-000000000001' WHERE org_id IS NULL;

ALTER TABLE reviews ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE settings ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE audit_log ALTER COLUMN org_id SET NOT NULL;

-- settings was keyed on key alone, so two orgs could not hold the same
-- setting. Re-key it on (org_id, key). Runs only while the old one-column
-- key is still in place, so re-running this file does nothing. Placed after
-- the backfill because a primary key cannot contain NULLs.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'settings_pkey'
          AND conrelid = 'settings'::regclass
          AND array_length(conkey, 1) = 1
    ) THEN
        ALTER TABLE settings DROP CONSTRAINT settings_pkey;
        ALTER TABLE settings ADD PRIMARY KEY (org_id, key);
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(org_id);
CREATE INDEX IF NOT EXISTS idx_alerts_received ON alerts(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_signature ON alerts(signature_id);
CREATE INDEX IF NOT EXISTS idx_alerts_event_time ON alerts(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id);
CREATE INDEX IF NOT EXISTS idx_reviews_alert ON reviews(alert_id);