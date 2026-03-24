"""Behavioral anomaly signals (Milestone 6) layered on top of rule scores."""

import os
from typing import List, Tuple


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


PATH_DIVERSITY_THRESHOLD = _env_int("ANOMALY_PATH_DIVERSITY_THRESHOLD", 12)
PATH_DIVERSITY_SCORE = _env_int("ANOMALY_PATH_DIVERSITY_SCORE", 12)

STATUS_MIX_THRESHOLD = _env_int("ANOMALY_STATUS_MIX_THRESHOLD", 5)
STATUS_MIX_SCORE = _env_int("ANOMALY_STATUS_MIX_SCORE", 10)

VELOCITY_RATIO = _env_int("ANOMALY_VELOCITY_RATIO", 3)
VELOCITY_MIN_RECENT = _env_int("ANOMALY_VELOCITY_MIN_RECENT", 8)
VELOCITY_SCORE = _env_int("ANOMALY_VELOCITY_SCORE", 14)

ANOMALY_SCORE_CAP = _env_int("ANOMALY_SCORE_CAP", 30)


async def compute_anomaly(conn, ip_address: str) -> Tuple[int, List[str]]:
    """
    Compute anomaly_score 0..ANOMALY_SCORE_CAP and human-readable reason fragments.
    Uses recent request_logs only; no external AI call (keeps ingest fast and reliable).
    """
    score = 0
    reasons: List[str] = []

    distinct_paths = await conn.fetchval(
        """
        SELECT COUNT(DISTINCT path)
        FROM request_logs
        WHERE ip_address = $1
          AND timestamp >= NOW() - INTERVAL '5 minutes'
        """,
        ip_address,
    )
    n_paths = int(distinct_paths or 0)
    if n_paths >= PATH_DIVERSITY_THRESHOLD:
        score += PATH_DIVERSITY_SCORE
        reasons.append(f"unusual path diversity ({n_paths} unique paths in 5m)")

    distinct_status = await conn.fetchval(
        """
        SELECT COUNT(DISTINCT status_code)
        FROM request_logs
        WHERE ip_address = $1
          AND timestamp >= NOW() - INTERVAL '5 minutes'
        """,
        ip_address,
    )
    n_status = int(distinct_status or 0)
    if n_status >= STATUS_MIX_THRESHOLD:
        score += STATUS_MIX_SCORE
        reasons.append(f"unusual status mix ({n_status} distinct codes in 5m)")

    recent = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM request_logs
        WHERE ip_address = $1
          AND timestamp >= NOW() - INTERVAL '1 minute'
        """,
        ip_address,
    )
    prev = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM request_logs
        WHERE ip_address = $1
          AND timestamp >= NOW() - INTERVAL '2 minutes'
          AND timestamp < NOW() - INTERVAL '1 minute'
        """,
        ip_address,
    )
    rc = int(recent or 0)
    pv = int(prev or 0)
    if pv > 0 and rc >= VELOCITY_MIN_RECENT and rc >= pv * VELOCITY_RATIO:
        score += VELOCITY_SCORE
        reasons.append(f"traffic velocity jump ({rc} in latest 1m vs {pv} prior 1m)")

    score = min(score, ANOMALY_SCORE_CAP)
    return score, reasons
