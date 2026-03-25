"""Deterministic fusion of rule_score and behavioral anomaly into severity and flags."""

from __future__ import annotations

import os
from dataclasses import dataclass


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


LOW_MAX = _env_int("LOW_MAX", 29)
MEDIUM_MAX = _env_int("MEDIUM_MAX", 59)
HIGH_MAX = _env_int("HIGH_MAX", 79)
ANOMALY_POINTS_MAX = _env_int("ANOMALY_POINTS_MAX", 35)
CRITICAL_RULE_FLOOR = _env_int("CRITICAL_RULE_FLOOR", 50)
ANOMALY_EVENT_THRESHOLD = _env_float("ANOMALY_EVENT_THRESHOLD", 0.72)


def score_to_band(score: int) -> str:
    if score > HIGH_MAX:
        return "CRITICAL"
    if score > MEDIUM_MAX:
        return "HIGH"
    if score > LOW_MAX:
        return "MEDIUM"
    return "LOW"


def legacy_anomaly_integer(anomaly_score_norm: float) -> int:
    """Backward-compatible integer for API/DB: scaled 0–100 from normalized anomaly."""
    return max(0, min(100, int(round(anomaly_score_norm * 100))))


@dataclass
class FusionOutcome:
    fused_score: int
    severity: str
    flagged: bool
    anomaly_points: int
    severity_reason: str
    capped_from_critical: bool


def fuse_scores(rule_score: int, anomaly_score_norm: float) -> FusionOutcome:
    """
    Combine rule and anomaly into a capped integer score and severity.
    CRITICAL is not allowed unless rule_score >= CRITICAL_RULE_FLOOR (anomaly cannot unlock auto-block alone).
    """
    ap = int(round(max(0.0, min(1.0, anomaly_score_norm)) * ANOMALY_POINTS_MAX))
    raw_fused = min(100, max(0, rule_score) + ap)
    band = score_to_band(raw_fused)
    capped = False
    severity = band
    if band == "CRITICAL" and rule_score < CRITICAL_RULE_FLOOR:
        severity = "HIGH"
        capped = True

    flagged = severity in {"HIGH", "CRITICAL"}

    if capped:
        reason = (
            f"fused_score={raw_fused} mapped to HIGH because rule_score={rule_score} "
            f"is below critical floor ({CRITICAL_RULE_FLOOR}); anomaly_norm={anomaly_score_norm:.3f}"
        )
    else:
        reason = (
            f"severity={severity} from fused_score={raw_fused} "
            f"(rule_score={rule_score}, anomaly_points={ap}, anomaly_norm={anomaly_score_norm:.3f})"
        )

    fused_for_storage = raw_fused
    if capped:
        fused_for_storage = min(raw_fused, HIGH_MAX)

    return FusionOutcome(
        fused_score=int(fused_for_storage),
        severity=severity,
        flagged=flagged,
        anomaly_points=ap,
        severity_reason=reason,
        capped_from_critical=capped,
    )


def should_create_event(rule_score: int, anomaly_score_norm: float) -> bool:
    if rule_score > 0:
        return True
    return anomaly_score_norm >= ANOMALY_EVENT_THRESHOLD
