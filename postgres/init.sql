CREATE TABLE IF NOT EXISTS request_logs (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(64) NOT NULL,
    method VARCHAR(16) NOT NULL,
    path VARCHAR(512) NOT NULL,
    status_code INTEGER NOT NULL,
    user_agent TEXT,
    response_time_ms INTEGER,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs (timestamp DESC);

CREATE TABLE IF NOT EXISTS threat_events (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(64) NOT NULL,
    source_key VARCHAR(128),
    event_type VARCHAR(64) NOT NULL,
    rule_score INTEGER NOT NULL DEFAULT 0,
    anomaly_score INTEGER NOT NULL DEFAULT 0,
    anomaly_score_norm DOUBLE PRECISION,
    final_score INTEGER NOT NULL,
    severity VARCHAR(16) NOT NULL,
    reasons TEXT NOT NULL,
    severity_reason TEXT,
    features JSONB,
    triggered_rules JSONB,
    contributing_features JSONB,
    flagged BOOLEAN NOT NULL DEFAULT FALSE,
    detection_metadata JSONB,
    ai_advisory_score INTEGER,
    ai_recommendations TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_events_created_at ON threat_events (created_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    threat_event_id INTEGER NOT NULL REFERENCES threat_events(id) ON DELETE CASCADE,
    severity VARCHAR(16) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_active_ip ON blocked_ips (ip_address, active, expires_at DESC);

CREATE TABLE IF NOT EXISTS port_scans (
    id SERIAL PRIMARY KEY,
    target VARCHAR(256) NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_port_scans_scanned_at ON port_scans (scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_port_scans_target ON port_scans (target);

CREATE TABLE IF NOT EXISTS port_scan_results (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES port_scans(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
    state VARCHAR(16) NOT NULL,
    service VARCHAR(64),
    risk_level VARCHAR(16) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_port_scan_results_scan ON port_scan_results (scan_id);
