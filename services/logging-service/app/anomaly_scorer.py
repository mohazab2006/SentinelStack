"""
Behavioral anomaly pipeline (0.0–1.0):

1) Statistical cohort z-scores (or single-IP fallback caps)
2) IsolationForest on the same window’s per-IP feature vectors (optional)
3) Optional OpenAI advisory score (gated by signal; blended, not sole driver)

CRITICAL auto-block still requires rule_score floor in fusion — see fusion.py.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Any, Optional

from .ai_insights import anomaly_llm_enabled, fetch_llm_anomaly_assessment
from .anomaly_ml import isolation_forest_norms_by_ip
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


MIN_COHORT_IPS = _env_int("ANOMALY_MIN_COHORT_IPS", 3)
EPSILON = _env_float("ANOMALY_STDDEV_EPSILON", 1e-6)

_Z_SCALE = _env_float("ANOMALY_Z_SCALE", 2.0)
TOP_CONTRIBUTORS = _env_int("ANOMALY_TOP_FEATURES", 5)

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


def _cohort_fallback_enabled() -> bool:
    return os.getenv("ANOMALY_COHORT_FALLBACK", "true").lower() in ("1", "true", "yes")


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


@dataclass
class AnomalyResult:
    anomaly_score_norm: float
    contributing_features: list[dict[str, Any]]
    layer_scores: dict[str, float] = field(default_factory=dict)
    blend_weights: dict[str, float] = field(default_factory=dict)
    llm_anomaly_note: Optional[str] = None


def blend_anomaly_layers(
    statistical: float,
    iforest: Optional[float],
    llm: Optional[float],
) -> tuple[float, dict[str, float], dict[str, float]]:
    """Weighted blend; missing layers drop out and weights renormalize."""
    w_s = _env_float("ANOMALY_BLEND_STAT_WEIGHT", 0.45)
    w_i = _env_float("ANOMALY_BLEND_IFOREST_WEIGHT", 0.30)
    w_l = _env_float("ANOMALY_BLEND_LLM_WEIGHT", 0.25)

    use_i = iforest is not None
    use_l = llm is not None
    den = w_s + (w_i if use_i else 0.0) + (w_l if use_l else 0.0)
    if den <= 0:
        return float(statistical), {"statistical": statistical}, {}

    num = w_s * statistical
    if use_i:
        num += w_i * float(iforest)
    if use_l:
        num += w_l * float(llm)

    blended = max(0.0, min(1.0, num / den))
    layers = {"statistical": float(statistical)}
    if use_i:
        layers["isolation_forest"] = float(iforest)
    if use_l:
        layers["llm"] = float(llm)
    layers["blended"] = blended

    weights_active = {"statistical": w_s}
    if use_i:
        weights_active["isolation_forest"] = w_i
    if use_l:
        weights_active["llm"] = w_l
    weights_used = {k: v / den for k, v in weights_active.items()}
    return blended, layers, weights_used


def _llm_worth_call(
    rule_score: int,
    statistical: float,
    iforest: Optional[float],
) -> bool:
    if not anomaly_llm_enabled():
        return False
    if os.getenv("ANOMALY_LLM_ALWAYS", "false").lower() in ("1", "true", "yes"):
        return True
    if rule_score > 0:
        return True
    gate_s = _env_float("ANOMALY_LLM_STAT_GATE", 0.15)
    gate_i = _env_float("ANOMALY_LLM_IFOREST_GATE", 0.2)
    if statistical >= gate_s:
        return True
    if iforest is not None and iforest >= gate_i:
        return True
    return False


def _fallback_subject_anomaly(subject: FeatureSnapshot) -> AnomalyResult:
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
    return AnomalyResult(
        norm,
        top,
        layer_scores={"statistical": norm, "blended": norm},
        blend_weights={"statistical": 1.0},
    )


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
    if subject.insufficient_sample:
        return AnomalyResult(
            0.0,
            [],
            layer_scores={"statistical": 0.0, "blended": 0.0},
            blend_weights={"statistical": 1.0},
        )

    cohort_ips = [
        ip
        for ip, snap in cohort_by_ip.items()
        if ip != subject_ip and not snap.insufficient_sample
    ]
    if len(cohort_ips) < MIN_COHORT_IPS:
        if _cohort_fallback_enabled():
            return _fallback_subject_anomaly(subject)
        return AnomalyResult(
            0.0,
            [],
            layer_scores={"statistical": 0.0, "blended": 0.0},
            blend_weights={"statistical": 1.0},
        )

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
        contrib = math.tanh(mag / max(_Z_SCALE, 1e-6))
        weighted_parts.append(contrib * w)
        w_sum += w
        contributors.append((key, v, z, contrib * w))

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
                "mode": "cohort_z",
                "weight": round(_FEATURE_WEIGHTS.get(name, 1.0), 4),
                "contribution": round(weighted, 6),
            }
        )
    return AnomalyResult(
        norm,
        top,
        layer_scores={"statistical": norm, "blended": norm},
        blend_weights={"statistical": 1.0},
    )


async def compute_behavioral_anomaly(
    conn,
    subject_ip: str,
    window_minutes: int,
    min_sample: int,
    rule_score: int = 0,
) -> tuple[FeatureSnapshot, AnomalyResult]:
    records = await fetch_window_rows(conn, window_minutes)
    grouped = group_rows_by_ip(list(records))
    cohort = build_cohort_snapshots(grouped, float(window_minutes), min_sample)
    subject_rows = grouped.get(subject_ip, [])
    subject_snap = compute_features_for_rows(subject_rows, float(window_minutes), min_sample)

    stat_block = score_subject_vs_cohort(subject_snap, cohort, subject_ip)
    stat_norm = stat_block.anomaly_score_norm
    contrib = list(stat_block.contributing_features)

    if_map = isolation_forest_norms_by_ip(cohort)
    if_n = if_map.get(subject_ip)

    llm_n: Optional[float] = None
    llm_note: Optional[str] = None
    feats_for_llm = subject_snap.to_json_dict() if not subject_snap.insufficient_sample else {}
    if _llm_worth_call(rule_score, stat_norm, if_n):
        llm_n, llm_note = await fetch_llm_anomaly_assessment(
            subject_ip=subject_ip,
            features=feats_for_llm,
            statistical_norm=stat_norm,
            iforest_norm=if_n,
        )

    blended, layer_scores, weights_used = blend_anomaly_layers(stat_norm, if_n, llm_n)

    meta = {
        "name": "_anomaly_layers",
        "statistical": round(stat_norm, 4),
        "isolation_forest": round(if_n, 4) if if_n is not None else None,
        "llm": round(llm_n, 4) if llm_n is not None else None,
        "blended": round(blended, 4),
        "blend_weights_used": {k: round(v, 4) for k, v in weights_used.items()},
        "llm_note": llm_note,
    }
    contrib.insert(0, meta)

    return subject_snap, AnomalyResult(
        anomaly_score_norm=blended,
        contributing_features=contrib,
        layer_scores=layer_scores,
        blend_weights=weights_used,
        llm_anomaly_note=llm_note,
    )


def compute_features_for_rows(
    rows: list[FeatureRow],
    window_minutes: float,
    min_sample: int,
) -> FeatureSnapshot:
    return compute_features(rows, window_minutes, min_sample)
