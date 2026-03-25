"""Isolation Forest layer: non-linear behavioral outlier score per IP in the current window."""

from __future__ import annotations

import os
import numpy as np

from .features import FeatureSnapshot, feature_dict_for_z

# Must match key order in features.feature_dict_for_z.
_FEATURE_ORDER = (
    "requests_per_minute",
    "failed_auth_ratio",
    "unique_endpoints",
    "pct_4xx",
    "pct_5xx",
    "avg_inter_request_seconds",
    "inter_request_variance",
    "path_entropy",
    "suspicious_payload_rate",
    "auth_endpoint_concentration",
)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def iforest_enabled() -> bool:
    return os.getenv("ANOMALY_IFOREST_ENABLED", "true").lower() in ("1", "true", "yes")


def iforest_min_samples() -> int:
    return _env_int("ANOMALY_IFOREST_MIN_SAMPLES", 5)


def isolation_forest_norms_by_ip(
    cohort_by_ip: dict[str, FeatureSnapshot],
) -> dict[str, float]:
    """
    Fit IsolationForest on all IPs with valid snapshots in the window.
    decision_function: higher = more normal. Map lower scores to higher anomaly in [0,1].
    """
    if not iforest_enabled():
        return {}

    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return {}

    rows: list[list[float]] = []
    ips: list[str] = []
    for ip, snap in cohort_by_ip.items():
        if snap.insufficient_sample:
            continue
        d = feature_dict_for_z(snap)
        rows.append([float(d[k]) for k in _FEATURE_ORDER])
        ips.append(ip)

    if len(rows) < iforest_min_samples():
        return {}

    x = np.asarray(rows, dtype=np.float64)
    if x.size == 0:
        return {}

    # Reduce pathological constant dimensions for stability.
    x = np.nan_to_num(x, nan=0.0, posinf=1e12, neginf=-1e12)

    n = x.shape[0]
    n_est = min(200, max(50, _env_int("ANOMALY_IFOREST_ESTIMATORS", 120)))
    max_samples = min(256, n)
    contamination = min(0.12, max(0.02, 2.0 / max(n, 3)))

    clf = IsolationForest(
        n_estimators=n_est,
        max_samples=max_samples,
        contamination=contamination,
        random_state=42,
        n_jobs=1,
    )
    clf.fit(x)
    dec = clf.decision_function(x)
    d_min = float(dec.min())
    d_max = float(dec.max())
    span = d_max - d_min
    if span < 1e-9:
        return {ip: 0.0 for ip in ips}

    out: dict[str, float] = {}
    for i, ip in enumerate(ips):
        # More abnormal => lower decision_function => higher norm
        raw = (d_max - float(dec[i])) / span
        out[ip] = float(np.clip(raw, 0.0, 1.0))
    return out
