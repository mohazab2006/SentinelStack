"""Rolling-window behavioral features per source (IP in Phase 1)."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from statistics import mean, pvariance
from typing import Any, Optional

# Paths treated as auth/sensitive surface (extensible).
AUTH_PATH_PREFIXES: tuple[str, ...] = ("/login", "/admin", "/config")

# SQLi / XSS-ish patterns matched against path (and query if present in path).
_SUSPICIOUS_PATTERNS = (
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"or\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r";\s*drop\b", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\.\./", re.IGNORECASE),
)


@dataclass
class FeatureRow:
    method: str
    path: str
    status_code: int
    timestamp: datetime


@dataclass
class FeatureSnapshot:
    """Serializable feature vector for storage and anomaly scoring."""

    window_minutes: float
    sample_count: int
    requests_per_minute: float
    failed_auth_ratio: float
    unique_endpoints: int
    pct_4xx: float
    pct_5xx: float
    avg_inter_request_seconds: Optional[float]
    inter_request_variance: float
    path_entropy: float
    suspicious_payload_rate: float
    auth_endpoint_concentration: float
    insufficient_sample: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "window_minutes": self.window_minutes,
            "sample_count": self.sample_count,
            "requests_per_minute": round(self.requests_per_minute, 4),
            "failed_auth_ratio": round(self.failed_auth_ratio, 4),
            "unique_endpoints": self.unique_endpoints,
            "pct_4xx": round(self.pct_4xx, 4),
            "pct_5xx": round(self.pct_5xx, 4),
            "avg_inter_request_seconds": (
                round(self.avg_inter_request_seconds, 4) if self.avg_inter_request_seconds is not None else None
            ),
            "inter_request_variance": round(self.inter_request_variance, 6),
            "path_entropy": round(self.path_entropy, 4),
            "suspicious_payload_rate": round(self.suspicious_payload_rate, 4),
            "auth_endpoint_concentration": round(self.auth_endpoint_concentration, 4),
            "insufficient_sample": self.insufficient_sample,
            **self.extra,
        }


def _path_entropy(paths: list[str]) -> float:
    if not paths:
        return 0.0
    counts = Counter(paths)
    n = len(paths)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _suspicious_hits(path: str) -> int:
    return sum(1 for p in _SUSPICIOUS_PATTERNS if p.search(path))


def _is_auth_path(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") or path.startswith(p + "?") for p in AUTH_PATH_PREFIXES)


def compute_features(rows: list[FeatureRow], window_minutes: float, min_sample: int) -> FeatureSnapshot:
    """Compute features from ordered rows for one source in the window."""
    n = len(rows)
    if n < min_sample:
        return FeatureSnapshot(
            window_minutes=window_minutes,
            sample_count=n,
            requests_per_minute=0.0,
            failed_auth_ratio=0.0,
            unique_endpoints=0,
            pct_4xx=0.0,
            pct_5xx=0.0,
            avg_inter_request_seconds=None,
            inter_request_variance=0.0,
            path_entropy=0.0,
            suspicious_payload_rate=0.0,
            auth_endpoint_concentration=0.0,
            insufficient_sample=True,
        )

    wm = max(window_minutes, 1e-6)
    rpm = n / wm

    paths = [r.path for r in rows]
    unique_endpoints = len(set(paths))

    n_4xx = sum(1 for r in rows if 400 <= r.status_code < 500)
    n_5xx = sum(1 for r in rows if 500 <= r.status_code < 600)
    pct_4xx = n_4xx / n
    pct_5xx = n_5xx / n

    post_login = [r for r in rows if r.method.upper() == "POST" and r.path.rstrip("/").split("?")[0] == "/login"]
    n_post_login = len(post_login)
    failed_login = sum(1 for r in post_login if r.status_code == 401)
    failed_auth_ratio = (failed_login / n_post_login) if n_post_login > 0 else 0.0

    timestamps = [r.timestamp for r in rows]
    if len(timestamps) >= 2:
        deltas: list[float] = []
        for i in range(1, len(timestamps)):
            d = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if d >= 0:
                deltas.append(d)
        if deltas:
            avg_gap = float(mean(deltas))
            var_gap = float(pvariance(deltas)) if len(deltas) >= 2 else 0.0
        else:
            avg_gap = 0.0
            var_gap = 0.0
    else:
        avg_gap = None
        var_gap = 0.0

    path_ent = _path_entropy(paths)
    suspicious = sum(_suspicious_hits(p) for p in paths)
    suspicious_rate = suspicious / n
    auth_hits = sum(1 for p in paths if _is_auth_path(p))
    auth_conc = auth_hits / n

    return FeatureSnapshot(
        window_minutes=window_minutes,
        sample_count=n,
        requests_per_minute=rpm,
        failed_auth_ratio=failed_auth_ratio,
        unique_endpoints=unique_endpoints,
        pct_4xx=pct_4xx,
        pct_5xx=pct_5xx,
        avg_inter_request_seconds=avg_gap,
        inter_request_variance=var_gap,
        path_entropy=path_ent,
        suspicious_payload_rate=suspicious_rate,
        auth_endpoint_concentration=auth_conc,
        insufficient_sample=False,
    )


def feature_dict_for_z(snapshot: FeatureSnapshot) -> dict[str, float]:
    """Scalar map aligned with cohort keys for z-scoring."""
    avg_irs = snapshot.avg_inter_request_seconds
    return {
        "requests_per_minute": snapshot.requests_per_minute,
        "failed_auth_ratio": snapshot.failed_auth_ratio,
        "unique_endpoints": float(snapshot.unique_endpoints),
        "pct_4xx": snapshot.pct_4xx,
        "pct_5xx": snapshot.pct_5xx,
        "avg_inter_request_seconds": float(avg_irs) if avg_irs is not None else 0.0,
        "inter_request_variance": snapshot.inter_request_variance,
        "path_entropy": snapshot.path_entropy,
        "suspicious_payload_rate": snapshot.suspicious_payload_rate,
        "auth_endpoint_concentration": snapshot.auth_endpoint_concentration,
    }


async def fetch_window_rows(conn, window_minutes: int) -> list[Any]:
    return await conn.fetch(
        """
        SELECT ip_address, method, path, status_code, timestamp
        FROM request_logs
        WHERE timestamp >= NOW() - (($1::TEXT || ' minutes')::interval)
        ORDER BY ip_address ASC, timestamp ASC
        """,
        str(window_minutes),
    )


def group_rows_by_ip(records: list[Any]) -> dict[str, list[FeatureRow]]:
    buckets: dict[str, list[FeatureRow]] = {}
    for r in records:
        ip = str(r["ip_address"])
        buckets.setdefault(ip, []).append(
            FeatureRow(
                method=str(r["method"]),
                path=str(r["path"]),
                status_code=int(r["status_code"]),
                timestamp=r["timestamp"],
            )
        )
    return buckets


def build_cohort_snapshots(
    grouped: dict[str, list[FeatureRow]],
    window_minutes: float,
    min_sample: int,
) -> dict[str, FeatureSnapshot]:
    return {ip: compute_features(rows, window_minutes, min_sample) for ip, rows in grouped.items()}
