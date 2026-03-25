"""Cohort z-score anomaly scoring (0.0–1.0), explainable — no ML infra."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any

from .features import (
    FeatureRow,
    FeatureSnapshot,
    build_cohort_snapshots,
    compute_features,
    feature_dict_for_z,
    fetch_window_rows,
    group_rows_by_ip,
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


# Minimum distinct cohort IPs with valid samples required to z-score.
MIN_COHORT_IPS = _env_int("ANOMALY_MIN_COHORT_IPS", 3)
EPSILON = _env_float("ANOMALY_STDDEV_EPSILON", 1e-6)


def _cohort_fallback_enabled() -> bool:
    raw = os.getenv("ANOMALY_COHORT_FALLBACK", "true").lower()
    return raw in ("1", "true", "yes")


# Deterministic soft caps when cohort is too small (e.g. lab / single visible IP).
_FALLBACK_CAPS: dict[str, float] = {
    "requests_per_minute": 80.0,
    "failed_auth_ratio": 0.85,
    "unique_endpoints": 18.0,
    "pct_4xx": 0.75,
    "pct_5xx": 0.35,
    "avg_inter_request_seconds": 15.0,
    "inter_request_variance": 120.0,
    "path_entropy": 4.0,
    "suspicious_payload_rate": 0.08,
    "auth_endpoint_concentration": 0.65,
}
# Per-feature tanh scale; larger k => need larger |z| to saturate.
Z_SCALE = _env_float("ANOMALY_Z_SCALE", 2.0)
TOP_CONTRIBUTORS = _env_int("ANOMALY_TOP_FEATURES", 5)

# Weights (sum need not be 1; normalized internally).
_DEFAULT_WEIGHTS: dict[str, float] = {
    "requests_per_minute": 1.0,
    "failed_auth_ratio": 1.2,
    "unique_endpoints": 0.9,
    "pct_4xx": 0.85,
    "pct_5xx": 1.1,
    "avg_inter_request_seconds": 0.6,
    "inter_request_variance": 0.95,
    "path_entropy": 1.0,
    "suspicious_payload_rate": 1.4,
    "auth_endpoint_concentration": 0.75,
}


def _parse_weights_from_env() -> dict[str, float]:
    raw = os.getenv("ANOMALY_FEATURE_WEIGHTS", "").strip()
    if not raw:
        return dict(_DEFAULT_WEIGHTS)
    out = dict(_DEFAULT_WEIGHTS)
    for part in raw.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        try:
            out[k] = float(v.strip())
        except ValueError:
            continue
    return out


_FEATURE_WEIGHTS = _parse_weights_from_env()


@dataclass
class AnomalyResult:
    anomaly_score_norm: float
    contributing_features: list[dict[str, Any]]


def _fallback_subject_anomaly(subject: FeatureSnapshot) -> AnomalyResult:
    """Magnitude-vs-cap scoring when peer cohort is unavailable; still deterministic."""
    sub = feature_dict_for_z(subject)
    contributors: list[tuple[str, float, float, float]] = []
    weighted_parts: list[float] = []
    w_sum = 0.0
    for key, w in _FEATURE_WEIGHTS.items():
        cap = max(_FALLBACK_CAPS.get(key, 1.0), EPSILON)
        v = sub[key]
        ratio = min(1.0, max(0.0, v / cap))
        local = math.tanh(2.2 * ratio)
        weighted_parts.append(local * w)
        w_sum += w
        pseudo_z = (v - cap * 0.25) / max(cap * 0.35, EPSILON)
        contributors.append((key, v, pseudo_z, local * w))
    norm = min(1.0, max(0.0, sum(weighted_parts) / w_sum)) if w_sum > 0 else 0.0
    contributors.sort(key=lambda t: t[3], reverse=True)
    top: list[dict[str, Any]] = []
    for name, value, z, weighted in contributors[:TOP_CONTRIBUTORS]:
        if weighted <= 0:
            continue
        top.append(
            {
                "name": name,
                "value": round(value, 6),
                "z": round(z, 4),
                "mode": "cohort_fallback",
                "weight": round(_FEATURE_WEIGHTS.get(name, 1.0), 4),
                "contribution": round(weighted, 6),
            }
        )
    return AnomalyResult(norm, top)


def _cohort_mean_std(
    cohort_values: list[dict[str, float]],
) -> tuple[dict[str, float], dict[str, float]]:
    keys = list(_FEATURE_WEIGHTS.keys())
    mus: dict[str, float] = {}
    sigmas: dict[str, float] = {}
    for k in keys:
        vals = [d[k] for d in cohort_values]
        if not vals:
            mus[k] = 0.0
            sigmas[k] = EPSILON
            continue
        mus[k] = mean(vals)
        if len(vals) < 2:
            sigmas[k] = EPSILON
        else:
            s = pstdev(vals)
            sigmas[k] = max(s, EPSILON)
    return mus, sigmas


def score_subject_vs_cohort(
    subject: FeatureSnapshot,
    cohort_by_ip: dict[str, FeatureSnapshot],
    subject_ip: str,
) -> AnomalyResult:
    """
    Compare subject feature vector to cohort distribution (other IPs with sufficient sample).
    Returns anomaly_score_norm in [0, 1] and ranked contributing features.
    """
    if subject.insufficient_sample:
        return AnomalyResult(0.0, [])

    cohort_ips = [
        ip
        for ip, snap in cohort_by_ip.items()
        if ip != subject_ip and not snap.insufficient_sample
    ]
    if len(cohort_ips) < MIN_COHORT_IPS:
        if _cohort_fallback_enabled():
            return _fallback_subject_anomaly(subject)
        return AnomalyResult(0.0, [])

    cohort_dicts = [feature_dict_for_z(cohort_by_ip[ip]) for ip in cohort_ips]
    mus, sigmas = _cohort_mean_std(cohort_dicts)
    sub = feature_dict_for_z(subject)

    contributors: list[tuple[str, float, float, float]] = []
    weighted_parts: list[float] = []
    w_sum = 0.0

    for key, w in _FEATURE_WEIGHTS.items():
        v = sub[key]
        mu = mus[key]
        sigma = sigmas[key]
        z = (v - mu) / sigma
        mag = abs(z)
        # Saturation curve: 0 at z=0, approaches 1 for large |z|
        contrib = math.tanh(mag / max(Z_SCALE, 1e-6))
        weighted_parts.append(contrib * w)
        w_sum += w
        contributors.append((key, v, z, contrib * w))

    if w_sum <= 0:
        norm = 0.0
    else:
        norm = min(1.0, max(0.0, sum(weighted_parts) / w_sum))

    contributors.sort(key=lambda t: t[3], reverse=True)
    top: list[dict[str, Any]] = []
    for name, value, z, weighted in contributors[:TOP_CONTRIBUTORS]:
        if weighted <= 0:
            continue
        top.append(
            {
                "name": name,
                "value": round(value, 6),
                "z": round(z, 4),
                "mode": "cohort_z",
                "weight": round(_FEATURE_WEIGHTS.get(name, 1.0), 4),
                "contribution": round(weighted, 6),
            }
        )

    return AnomalyResult(norm, top)


async def compute_behavioral_anomaly(
    conn,
    subject_ip: str,
    window_minutes: int,
    min_sample: int,
) -> tuple[FeatureSnapshot, AnomalyResult]:
    records = await fetch_window_rows(conn, window_minutes)
    grouped = group_rows_by_ip(list(records))
    cohort = build_cohort_snapshots(grouped, float(window_minutes), min_sample)
    subject_rows = grouped.get(subject_ip, [])
    subject_snap = compute_features_for_rows(subject_rows, float(window_minutes), min_sample)
    result = score_subject_vs_cohort(subject_snap, cohort, subject_ip)
    return subject_snap, result


def compute_features_for_rows(
    rows: list[FeatureRow],
    window_minutes: float,
    min_sample: int,
) -> FeatureSnapshot:
    return compute_features(rows, window_minutes, min_sample)
