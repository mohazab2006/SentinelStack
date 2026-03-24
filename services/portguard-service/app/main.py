import asyncio
import json
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException

from app.db import close_pool, get_pool
from app.schemas import (
    PortResult,
    PortScanDetail,
    PortScanSummary,
    ScanRequest,
    ScheduleStatus,
    ScheduleUpdateRequest,
)

logger = logging.getLogger("uvicorn.error")

_scheduler: Optional[AsyncIOScheduler] = None
_schedule_minutes: int = 60
_schedule_targets_override: Optional[List[str]] = None


def _coerce_open_ports(raw: object) -> List[dict]:
    """asyncpg often returns JSON/JSONB aggregates as str; Pydantic needs list[dict]."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        if not raw.strip():
            return []
        return json.loads(raw)
    return []


# Known services / risk hints (lab-oriented; HIGH = sensitive if exposed broadly)
PORT_RISK: Dict[int, Tuple[str, str]] = {
    22: ("ssh", "HIGH"),
    23: ("telnet", "CRITICAL"),
    25: ("smtp", "MEDIUM"),
    53: ("dns", "MEDIUM"),
    80: ("http", "LOW"),
    110: ("pop3", "MEDIUM"),
    143: ("imap", "MEDIUM"),
    443: ("https", "LOW"),
    445: ("smb", "HIGH"),
    1433: ("mssql", "HIGH"),
    3000: ("http-alt", "LOW"),
    3306: ("mysql", "HIGH"),
    3389: ("rdp", "CRITICAL"),
    5432: ("postgres", "HIGH"),
    6379: ("redis", "HIGH"),
    8000: ("http-alt", "LOW"),
    8080: ("http-proxy", "LOW"),
    8443: ("https-alt", "LOW"),
    9200: ("elasticsearch", "HIGH"),
    27017: ("mongodb", "HIGH"),
}

DEFAULT_PORTS = [
    22,
    23,
    80,
    443,
    445,
    3000,
    3306,
    3389,
    5432,
    6379,
    8000,
    8080,
    27017,
]


def _allowed_targets() -> Set[str]:
    raw = os.environ.get("PORTGUARD_ALLOWED_TARGETS", "demo-app,nginx,postgres,logging-service")
    return {t.strip().lower() for t in raw.split(",") if t.strip()}


def _scan_ports() -> List[int]:
    raw = os.environ.get("PORTGUARD_PORTS", "")
    if raw.strip():
        ports: List[int] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ports.append(int(part))
            except ValueError:
                continue
        return sorted(set(ports)) if ports else DEFAULT_PORTS
    return DEFAULT_PORTS


def _default_target() -> str:
    return os.environ.get("PORTGUARD_DEFAULT_TARGET", "demo-app").strip().lower()


def _connect_timeout() -> float:
    try:
        return float(os.environ.get("PORTGUARD_CONNECT_TIMEOUT", "1.0"))
    except ValueError:
        return 1.0


async def _probe_port(host: str, port: int, timeout: float) -> bool:
    loop = asyncio.get_event_loop()

    def sync_probe() -> bool:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False
        for family, _, _, _, sockaddr in infos:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect(sockaddr)
                return True
            except OSError:
                continue
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        return False

    return await loop.run_in_executor(None, sync_probe)


MIGRATION_SQL = """
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
"""


async def migrate() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(MIGRATION_SQL)


app = FastAPI(title="SentinelStack Port Guard", version="0.1.0")


def _schedule_targets() -> List[str]:
    global _schedule_targets_override
    if _schedule_targets_override is not None:
        return list(_schedule_targets_override)
    raw = os.environ.get("PORTGUARD_SCHEDULE_TARGETS", "").strip()
    allowed = _allowed_targets()
    if not raw:
        return sorted(allowed)
    out: List[str] = []
    for part in raw.split(","):
        t = part.strip().lower()
        if t in allowed:
            out.append(t)
    return out


async def _notify_logging_new_ports(
    target: str, scan_id: int, new_port_nums: List[int], results: List[PortResult]
) -> None:
    if not new_port_nums:
        return
    items: List[dict] = []
    new_set = set(new_port_nums)
    for r in results:
        if r.state == "open" and r.port in new_set:
            items.append(
                {
                    "port": r.port,
                    "service": r.service,
                    "risk_level": r.risk_level,
                }
            )
    if not items:
        return
    base = os.getenv("LOGGING_SERVICE_URL", "http://logging-service:8000").rstrip("/")
    secret = os.getenv("PORTGUARD_WEBHOOK_SECRET", "").strip()
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Portguard-Token"] = secret
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{base}/ingest-portguard",
                json={"target": target, "scan_id": scan_id, "new_ports": items},
                headers=headers,
            )
            if resp.status_code >= 400:
                logger.warning("ingest-portguard failed: %s %s", resp.status_code, resp.text[:500])
    except Exception:
        logger.exception("ingest-portguard request error for target=%s scan_id=%s", target, scan_id)


async def perform_scan(target: str) -> PortScanDetail:
    """Run a full scan for an allowlisted target; persist results and optionally notify logging-service."""
    allowed = _allowed_targets()
    target = target.strip().lower()
    if target not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Target not allowed. Use one of: {sorted(allowed)}",
        )

    ports = _scan_ports()
    timeout = _connect_timeout()
    open_ports: List[int] = []
    for port in ports:
        is_open = await _probe_port(target, port, timeout)
        if is_open:
            open_ports.append(port)

    pool = await get_pool()
    async with pool.acquire() as conn:
        scan_id = await conn.fetchval(
            "INSERT INTO port_scans (target, scanned_at) VALUES ($1, $2) RETURNING id",
            target,
            datetime.now(timezone.utc),
        )
        for port in ports:
            is_open = port in open_ports
            state = "open" if is_open else "closed"
            if port in PORT_RISK:
                service, risk = PORT_RISK[port]
            else:
                service = None
                risk = "HIGH" if is_open else "LOW"
            await conn.execute(
                """
                INSERT INTO port_scan_results (scan_id, port, protocol, state, service, risk_level)
                VALUES ($1, $2, 'tcp', $3, $4, $5)
                """,
                scan_id,
                port,
                state,
                service,
                risk if is_open else "LOW",
            )

        prev_row = await conn.fetchrow(
            """
            SELECT id FROM port_scans
            WHERE target = $1 AND id <> $2
            ORDER BY scanned_at DESC
            LIMIT 1
            """,
            target,
            scan_id,
        )
        new_open: List[int] = []
        if prev_row:
            prev_id = prev_row["id"]
            prev_open = await conn.fetch(
                "SELECT port FROM port_scan_results WHERE scan_id = $1 AND state = 'open'",
                prev_id,
            )
            prev_set = {r["port"] for r in prev_open}
            new_open = sorted(p for p in open_ports if p not in prev_set)

        scan_row = await conn.fetchrow(
            "SELECT id, target, scanned_at FROM port_scans WHERE id = $1",
            scan_id,
        )
        if scan_row is None:
            raise HTTPException(status_code=500, detail="Scan record missing after insert")
        rrows = await conn.fetch(
            """
            SELECT id, scan_id, port, protocol, state, service, risk_level
            FROM port_scan_results WHERE scan_id = $1 ORDER BY port
            """,
            scan_id,
        )

    results = [
        PortResult(
            id=r["id"],
            scan_id=r["scan_id"],
            port=r["port"],
            protocol=r["protocol"],
            state=r["state"],
            service=r["service"],
            risk_level=r["risk_level"],
        )
        for r in rrows
    ]
    detail = PortScanDetail(
        id=scan_row["id"],
        target=scan_row["target"],
        scanned_at=scan_row["scanned_at"],
        results=results,
        new_open_ports=new_open,
    )

    if new_open and os.getenv("PORTGUARD_ALERTS_ENABLED", "true").lower() in ("1", "true", "yes"):
        await _notify_logging_new_ports(target, scan_id, new_open, results)

    return detail


async def _scheduled_sweep() -> None:
    for t in _schedule_targets():
        try:
            await perform_scan(t)
        except HTTPException:
            logger.warning("scheduled scan skipped invalid target %s", t)
        except Exception:
            logger.exception("scheduled scan failed for %s", t)


def _parse_schedule_minutes(raw_minutes: Optional[str] = None) -> int:
    try:
        minutes = int(raw_minutes if raw_minutes is not None else os.getenv("PORTGUARD_SCHEDULE_MINUTES", "60"))
    except (TypeError, ValueError):
        minutes = 60
    return max(1, min(minutes, 1440))


def _scheduler_enabled() -> bool:
    return _scheduler is not None and _scheduler.running


def _start_scheduler(minutes: int) -> None:
    global _scheduler, _schedule_minutes
    _schedule_minutes = max(1, min(minutes, 1440))
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(_scheduled_sweep, "interval", minutes=_schedule_minutes, id="portguard_scheduled")
    _scheduler.start()
    logger.info(
        "Port Guard scheduler: every %s min, targets=%s",
        _schedule_minutes,
        _schedule_targets() or "(none)",
    )


def _stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
    logger.info("Port Guard scheduler stopped")


def _normalize_schedule_targets(targets: List[str]) -> List[str]:
    allowed = _allowed_targets()
    normalized = []
    for t in targets:
        item = t.strip().lower()
        if item in allowed and item not in normalized:
            normalized.append(item)
    return normalized


@app.on_event("startup")
async def startup() -> None:
    global _schedule_minutes
    await migrate()
    _schedule_minutes = _parse_schedule_minutes()
    raw = os.getenv("PORTGUARD_SCHEDULE_ENABLED", "").lower()
    if raw in ("1", "true", "yes"):
        _start_scheduler(_schedule_minutes)


@app.on_event("shutdown")
async def shutdown() -> None:
    _stop_scheduler()
    await close_pool()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "portguard"}


@app.post("/scan", response_model=PortScanDetail)
async def run_scan(body: ScanRequest) -> PortScanDetail:
    target = (body.target or _default_target()).strip().lower()
    return await perform_scan(target)


@app.get("/schedule", response_model=ScheduleStatus)
async def get_schedule() -> ScheduleStatus:
    return ScheduleStatus(
        enabled=_scheduler_enabled(),
        minutes=_schedule_minutes,
        targets=_schedule_targets(),
        allowed_targets=sorted(_allowed_targets()),
    )


@app.put("/schedule", response_model=ScheduleStatus)
async def update_schedule(body: ScheduleUpdateRequest) -> ScheduleStatus:
    global _schedule_minutes, _schedule_targets_override
    if body.minutes is not None:
        _schedule_minutes = max(1, min(body.minutes, 1440))
    if body.targets is not None:
        normalized_targets = _normalize_schedule_targets(body.targets)
        if not normalized_targets:
            raise HTTPException(status_code=400, detail="Choose at least one valid schedule target")
        _schedule_targets_override = normalized_targets

    if body.enabled is True:
        _start_scheduler(_schedule_minutes)
    elif body.enabled is False:
        _stop_scheduler()
    elif _scheduler_enabled():
        # Apply minute changes immediately when running.
        _start_scheduler(_schedule_minutes)

    return ScheduleStatus(
        enabled=_scheduler_enabled(),
        minutes=_schedule_minutes,
        targets=_schedule_targets(),
        allowed_targets=sorted(_allowed_targets()),
    )


async def _fetch_results_for_scan(scan_id: int) -> List[PortResult]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        scan = await conn.fetchrow("SELECT id, target, scanned_at FROM port_scans WHERE id = $1", scan_id)
        if not scan:
            return []
        rrows = await conn.fetch(
            """
            SELECT id, scan_id, port, protocol, state, service, risk_level
            FROM port_scan_results WHERE scan_id = $1 ORDER BY port
            """,
            scan_id,
        )
    return [
        PortResult(
            id=r["id"],
            scan_id=r["scan_id"],
            port=r["port"],
            protocol=r["protocol"],
            state=r["state"],
            service=r["service"],
            risk_level=r["risk_level"],
        )
        for r in rrows
    ]


@app.get("/scans", response_model=List[PortScanSummary])
async def list_scans(limit: int = 20) -> List[PortScanSummary]:
    limit = max(1, min(limit, 100))
    pool = await get_pool()
    async with pool.acquire() as conn:
        scans = await conn.fetch(
            """
            SELECT s.id, s.target, s.scanned_at,
                   COUNT(*) FILTER (WHERE r.state = 'open') AS open_count,
                   COUNT(*) FILTER (WHERE r.state = 'open' AND r.risk_level IN ('HIGH','CRITICAL')) AS high_risk_count,
                   COALESCE(
                       (
                           SELECT json_agg(
                                      json_build_object(
                                          'port', r2.port,
                                          'service', r2.service,
                                          'risk_level', r2.risk_level
                                      )
                                      ORDER BY r2.port
                                  )
                           FROM port_scan_results r2
                           WHERE r2.scan_id = s.id
                             AND r2.state = 'open'
                       ),
                       '[]'::json
                   ) AS open_ports
            FROM port_scans s
            LEFT JOIN port_scan_results r ON r.scan_id = s.id
            GROUP BY s.id, s.target, s.scanned_at
            ORDER BY s.scanned_at DESC
            LIMIT $1
            """,
            limit,
        )
    return [
        PortScanSummary(
            id=s["id"],
            target=s["target"],
            scanned_at=s["scanned_at"],
            open_count=s["open_count"] or 0,
            high_risk_count=s["high_risk_count"] or 0,
            open_ports=_coerce_open_ports(s["open_ports"]),
        )
        for s in scans
    ]


@app.get("/scans/{scan_id}", response_model=PortScanDetail)
async def get_scan(scan_id: int) -> PortScanDetail:
    pool = await get_pool()
    async with pool.acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT id, target, scanned_at FROM port_scans WHERE id = $1",
            scan_id,
        )
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        prev_row = await conn.fetchrow(
            """
            SELECT id FROM port_scans
            WHERE target = $1 AND id <> $2
            ORDER BY scanned_at DESC
            LIMIT 1
            """,
            scan["target"],
            scan_id,
        )
        new_open: List[int] = []
        if prev_row:
            prev_open = await conn.fetch(
                "SELECT port FROM port_scan_results WHERE scan_id = $1 AND state = 'open'",
                prev_row["id"],
            )
            prev_set = {r["port"] for r in prev_open}
            cur_open = await conn.fetch(
                "SELECT port FROM port_scan_results WHERE scan_id = $1 AND state = 'open'",
                scan_id,
            )
            cur_set = {r["port"] for r in cur_open}
            new_open = sorted(p for p in cur_set if p not in prev_set)

    results = await _fetch_results_for_scan(scan_id)
    return PortScanDetail(
        id=scan["id"],
        target=scan["target"],
        scanned_at=scan["scanned_at"],
        results=results,
        new_open_ports=new_open,
    )
