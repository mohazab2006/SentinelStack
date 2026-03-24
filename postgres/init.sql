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
    event_type VARCHAR(64) NOT NULL,
    rule_score INTEGER NOT NULL DEFAULT 0,
    anomaly_score INTEGER NOT NULL DEFAULT 0,
    final_score INTEGER NOT NULL,
    severity VARCHAR(16) NOT NULL,
    reasons TEXT NOT NULL,
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
