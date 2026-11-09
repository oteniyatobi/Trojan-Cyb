CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    wazuh_id TEXT UNIQUE NOT NULL,
    received_at TIMESTAMPTZ DEFAULT NOW(),
    rule_id TEXT,
    rule_level INTEGER,
    description TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    agent_name TEXT,
    raw JSONB,
    status TEXT DEFAULT 'new',
    review_status TEXT DEFAULT 'pending'
);

CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
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

CREATE TABLE scans (
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

CREATE TABLE findings (
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

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    is_secret BOOLEAN DEFAULT FALSE
);

CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    who TEXT,
    action TEXT,
    object TEXT,
    at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_alerts_org ON alerts(org_id);
CREATE INDEX idx_alerts_received ON alerts(received_at DESC);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_org ON findings(org_id);
CREATE INDEX idx_reviews_alert ON reviews(alert_id);
