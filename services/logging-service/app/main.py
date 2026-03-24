from datetime import datetime, timezone
from typing import List

from fastapi import FastAPI, Query

from .db import close_pool, get_pool
from .schemas import Alert, IngestRequest, RequestLog, ThreatEvent

app = FastAPI(title="SentinelStack Logging Service")


@app.on_event("startup")
async def startup() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
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
            """
        )
        await conn.execute(
            """
            ALTER TABLE request_logs
            ADD COLUMN IF NOT EXISTS response_time_ms INTEGER;
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp
            ON request_logs (timestamp DESC);
            """
        )
        await conn.execute(
            """
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
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_threat_events_created_at
            ON threat_events (created_at DESC);
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                threat_event_id INTEGER NOT NULL REFERENCES threat_events(id) ON DELETE CASCADE,
                severity VARCHAR(16) NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                acknowledged BOOLEAN NOT NULL DEFAULT FALSE
            );
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_created_at
            ON alerts (created_at DESC);
            """
        )


@app.on_event("shutdown")
async def shutdown() -> None:
    await close_pool()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ingest-request")
async def ingest_request(payload: IngestRequest) -> dict[str, str]:
    pool = await get_pool()
    timestamp = payload.timestamp or datetime.now(timezone.utc)
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(
            """
            INSERT INTO request_logs (ip_address, method, path, status_code, user_agent, response_time_ms, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            payload.ip_address,
            payload.method,
            payload.path,
            payload.status_code,
            payload.user_agent,
            payload.response_time_ms,
            timestamp,
        )
        rule_score, reasons, event_type = await evaluate_rules(conn, payload.ip_address)
        if rule_score > 0:
            severity = score_to_severity(rule_score)
            # Avoid alert storms by suppressing duplicates for the same rule/IP over 2 minutes.
            duplicate = await conn.fetchval(
                """
                SELECT id FROM threat_events
                WHERE ip_address = $1
                  AND event_type = $2
                  AND created_at >= NOW() - INTERVAL '2 minutes'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                payload.ip_address,
                event_type,
            )
            if duplicate is None:
                event_id = await conn.fetchval(
                    """
                    INSERT INTO threat_events (ip_address, event_type, rule_score, anomaly_score, final_score, severity, reasons)
                    VALUES ($1, $2, $3, 0, $3, $4, $5)
                    RETURNING id
                    """,
                    payload.ip_address,
                    event_type,
                    rule_score,
                    severity,
                    ", ".join(reasons),
                )
                if severity in {"MEDIUM", "HIGH", "CRITICAL"}:
                    message = f"{severity} threat from {payload.ip_address}: " + "; ".join(reasons)
                    await conn.execute(
                        """
                        INSERT INTO alerts (threat_event_id, severity, message)
                        VALUES ($1, $2, $3)
                        """,
                        event_id,
                        severity,
                        message,
                    )
    return {"status": "logged"}


@app.get("/logs", response_model=List[RequestLog])
async def get_logs(limit: int = Query(default=50, ge=1, le=500)) -> List[RequestLog]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, ip_address, method, path, status_code, user_agent, response_time_ms, timestamp
            FROM request_logs
            ORDER BY timestamp DESC
            LIMIT $1
            """,
            limit,
        )
    return [RequestLog(**dict(row)) for row in rows]


@app.get("/events", response_model=List[ThreatEvent])
async def get_events(limit: int = Query(default=50, ge=1, le=500)) -> List[ThreatEvent]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, ip_address, event_type, rule_score, anomaly_score, final_score, severity, reasons, created_at
            FROM threat_events
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return [ThreatEvent(**dict(row)) for row in rows]


@app.get("/alerts", response_model=List[Alert])
async def get_alerts(limit: int = Query(default=50, ge=1, le=500)) -> List[Alert]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, threat_event_id, severity, message, created_at, acknowledged
            FROM alerts
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return [Alert(**dict(row)) for row in rows]


def score_to_severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


async def evaluate_rules(conn, ip_address: str) -> tuple[int, list[str], str]:
    score = 0
    reasons: list[str] = []
    event_type = "suspicious_activity"

    failed_logins = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM request_logs
        WHERE ip_address = $1
          AND path = '/login'
          AND method = 'POST'
          AND status_code = 401
          AND timestamp >= NOW() - INTERVAL '5 minutes'
        """,
        ip_address,
    )
    if failed_logins >= 5:
        score += 35
        reasons.append(f"failed login burst ({failed_logins} in 5m)")
        event_type = "brute_force"

    repeated_404 = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM request_logs
        WHERE ip_address = $1
          AND status_code = 404
          AND timestamp >= NOW() - INTERVAL '5 minutes'
        """,
        ip_address,
    )
    if repeated_404 >= 8:
        score += 20
        reasons.append(f"repeated 404 probing ({repeated_404} in 5m)")
        if event_type == "suspicious_activity":
            event_type = "recon_404_probe"

    request_spike = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM request_logs
        WHERE ip_address = $1
          AND timestamp >= NOW() - INTERVAL '1 minute'
        """,
        ip_address,
    )
    if request_spike >= 30:
        score += 30
        reasons.append(f"request spike ({request_spike} in 1m)")
        if event_type == "suspicious_activity":
            event_type = "request_spike"

    sensitive_unauthorized = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM request_logs
        WHERE ip_address = $1
          AND path IN ('/admin', '/config')
          AND status_code = 401
          AND timestamp >= NOW() - INTERVAL '5 minutes'
        """,
        ip_address,
    )
    if sensitive_unauthorized >= 3:
        score += 25
        reasons.append(f"sensitive route probing ({sensitive_unauthorized} unauthorized attempts)")
        if event_type == "suspicious_activity":
            event_type = "sensitive_route_probe"

    if score > 100:
        score = 100
    return score, reasons, event_type
