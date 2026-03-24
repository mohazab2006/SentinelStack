import os
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query

from .db import close_pool, get_pool
from .schemas import Alert, BlockedIp, BlockIpRequest, IngestRequest, RequestLog, ThreatEvent

app = FastAPI(title="SentinelStack Logging Service")


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


FAILED_LOGIN_THRESHOLD = env_int("FAILED_LOGIN_THRESHOLD", 5)
FAILED_LOGIN_SCORE = env_int("FAILED_LOGIN_SCORE", 35)
REQUEST_SPIKE_THRESHOLD = env_int("REQUEST_SPIKE_THRESHOLD", 30)
REQUEST_SPIKE_SCORE = env_int("REQUEST_SPIKE_SCORE", 30)
REPEATED_404_THRESHOLD = env_int("REPEATED_404_THRESHOLD", 8)
REPEATED_404_SCORE = env_int("REPEATED_404_SCORE", 20)
SENSITIVE_PROBE_THRESHOLD = env_int("SENSITIVE_PROBE_THRESHOLD", 3)
SENSITIVE_PROBE_SCORE = env_int("SENSITIVE_PROBE_SCORE", 25)
LOW_MAX = env_int("LOW_MAX", 29)
MEDIUM_MAX = env_int("MEDIUM_MAX", 59)
HIGH_MAX = env_int("HIGH_MAX", 79)
AUTO_BLOCK_MINUTES = env_int("AUTO_BLOCK_MINUTES", 60)


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
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(64) NOT NULL,
                reason TEXT NOT NULL,
                blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ,
                active BOOLEAN NOT NULL DEFAULT TRUE
            );
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocked_ips_active_ip
            ON blocked_ips (ip_address, active, expires_at DESC);
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
                  AND final_score >= $3
                  AND created_at >= NOW() - INTERVAL '2 minutes'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                payload.ip_address,
                event_type,
                rule_score,
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
                if severity == "CRITICAL":
                    await block_ip_in_db(
                        conn=conn,
                        ip_address=payload.ip_address,
                        reason=f"auto-block: {'; '.join(reasons)}",
                        duration_minutes=AUTO_BLOCK_MINUTES,
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


@app.get("/blocked-ips", response_model=List[BlockedIp])
async def get_blocked_ips(limit: int = Query(default=100, ge=1, le=1000)) -> List[BlockedIp]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await deactivate_expired_blocks(conn)
        rows = await conn.fetch(
            """
            SELECT id, ip_address, reason, blocked_at, expires_at, active
            FROM blocked_ips
            WHERE active = TRUE
            ORDER BY blocked_at DESC
            LIMIT $1
            """,
            limit,
        )
    return [BlockedIp(**dict(row)) for row in rows]


@app.get("/is-blocked")
async def is_ip_blocked(ip: str = Query(..., min_length=1, max_length=64)) -> dict[str, bool]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        blocked = await is_blocked(conn, ip)
    return {"blocked": blocked}


@app.post("/block-ip", response_model=BlockedIp)
async def block_ip(payload: BlockIpRequest) -> BlockedIp:
    pool = await get_pool()
    async with pool.acquire() as conn, conn.transaction():
        blocked = await block_ip_in_db(
            conn=conn,
            ip_address=payload.ip_address,
            reason=payload.reason,
            duration_minutes=payload.duration_minutes,
        )
    return blocked


@app.post("/unblock-ip")
async def unblock_ip(ip: str = Query(..., min_length=1, max_length=64)) -> dict[str, str]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        updated = await conn.execute(
            """
            UPDATE blocked_ips
            SET active = FALSE
            WHERE ip_address = $1
              AND active = TRUE
            """,
            ip,
        )
    if updated == "UPDATE 0":
        raise HTTPException(status_code=404, detail="No active block found for IP")
    return {"status": "unblocked"}


@app.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int) -> dict[str, str]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        updated = await conn.execute(
            """
            UPDATE alerts
            SET acknowledged = TRUE
            WHERE id = $1
            """,
            alert_id,
        )
    if updated == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged"}


@app.get("/metrics/overview")
async def get_overview_metrics() -> dict[str, int]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await deactivate_expired_blocks(conn)
        total_requests = await conn.fetchval("SELECT COUNT(*) FROM request_logs")
        total_events = await conn.fetchval("SELECT COUNT(*) FROM threat_events")
        open_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE acknowledged = FALSE")
        active_blocks = await conn.fetchval("SELECT COUNT(*) FROM blocked_ips WHERE active = TRUE")
    return {
        "total_requests": int(total_requests or 0),
        "total_events": int(total_events or 0),
        "open_alerts": int(open_alerts or 0),
        "active_blocks": int(active_blocks or 0),
    }


@app.get("/metrics/severity")
async def get_severity_metrics() -> dict[str, int]:
    pool = await get_pool()
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT severity, COUNT(*) AS count
            FROM threat_events
            GROUP BY severity
            """
        )
    for row in rows:
        severity = row["severity"]
        if severity in counts:
            counts[severity] = int(row["count"])
    return counts


def score_to_severity(score: int) -> str:
    if score > HIGH_MAX:
        return "CRITICAL"
    if score > MEDIUM_MAX:
        return "HIGH"
    if score > LOW_MAX:
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
    if failed_logins >= FAILED_LOGIN_THRESHOLD:
        score += FAILED_LOGIN_SCORE
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
    if repeated_404 >= REPEATED_404_THRESHOLD:
        score += REPEATED_404_SCORE
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
    if request_spike >= REQUEST_SPIKE_THRESHOLD:
        score += REQUEST_SPIKE_SCORE
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
    if sensitive_unauthorized >= SENSITIVE_PROBE_THRESHOLD:
        score += SENSITIVE_PROBE_SCORE
        reasons.append(f"sensitive route probing ({sensitive_unauthorized} unauthorized attempts)")
        if event_type == "suspicious_activity":
            event_type = "sensitive_route_probe"

    if score > 100:
        score = 100
    return score, reasons, event_type


async def deactivate_expired_blocks(conn) -> None:
    await conn.execute(
        """
        UPDATE blocked_ips
        SET active = FALSE
        WHERE active = TRUE
          AND expires_at IS NOT NULL
          AND expires_at <= NOW()
        """
    )


async def is_blocked(conn, ip_address: str) -> bool:
    await deactivate_expired_blocks(conn)
    blocked_id = await conn.fetchval(
        """
        SELECT id
        FROM blocked_ips
        WHERE ip_address = $1
          AND active = TRUE
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY blocked_at DESC
        LIMIT 1
        """,
        ip_address,
    )
    return blocked_id is not None


async def block_ip_in_db(
    conn, ip_address: str, reason: str, duration_minutes: Optional[int]
) -> BlockedIp:
    already_blocked = await is_blocked(conn, ip_address)
    if already_blocked:
        row = await conn.fetchrow(
            """
            SELECT id, ip_address, reason, blocked_at, expires_at, active
            FROM blocked_ips
            WHERE ip_address = $1
              AND active = TRUE
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY blocked_at DESC
            LIMIT 1
            """,
            ip_address,
        )
        return BlockedIp(**dict(row))

    row = await conn.fetchrow(
        """
        INSERT INTO blocked_ips (ip_address, reason, expires_at, active)
        VALUES (
            $1,
            $2,
            CASE WHEN $3::INT IS NULL THEN NULL ELSE NOW() + ($3::TEXT || ' minutes')::INTERVAL END,
            TRUE
        )
        RETURNING id, ip_address, reason, blocked_at, expires_at, active
        """,
        ip_address,
        reason,
        duration_minutes,
    )
    return BlockedIp(**dict(row))
