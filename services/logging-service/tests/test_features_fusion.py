"""Pure unit tests for feature extraction and score fusion."""

from datetime import datetime, timedelta, timezone

import pytest

from app.features import FeatureRow, compute_features, feature_dict_for_z
from app.fusion import fuse_scores, legacy_anomaly_integer, score_to_band, should_create_event


def test_compute_features_basic():
    base = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        FeatureRow("GET", "/a", 200, base),
        FeatureRow("GET", "/b", 404, base + timedelta(seconds=2)),
        FeatureRow("POST", "/login", 401, base + timedelta(seconds=4)),
        FeatureRow("POST", "/login", 200, base + timedelta(seconds=6)),
    ]
    snap = compute_features(rows, window_minutes=5.0, min_sample=3)
    assert not snap.insufficient_sample
    assert snap.unique_endpoints == 3
    assert snap.failed_auth_ratio == pytest.approx(0.5)
    assert snap.pct_4xx == pytest.approx(0.5)
    assert snap.sample_count == 4
    d = feature_dict_for_z(snap)
    assert "path_entropy" in d


def test_fuse_scores_caps_critical_without_rule_floor():
    # 49 + 35 anomaly points => raw fused in CRITICAL band, but rule floor blocks CRITICAL.
    out = fuse_scores(rule_score=49, anomaly_score_norm=1.0)
    assert out.severity == "HIGH"
    assert out.capped_from_critical is True
    assert out.fused_score <= 79


def test_fuse_scores_allows_critical_with_rule_floor():
    out = fuse_scores(rule_score=55, anomaly_score_norm=1.0)
    assert out.severity == "CRITICAL"
    assert out.capped_from_critical is False
    assert out.flagged is True


def test_legacy_anomaly_integer():
    assert legacy_anomaly_integer(0.0) == 0
    assert legacy_anomaly_integer(1.0) == 100
    assert legacy_anomaly_integer(0.505) in (50, 51)


def test_should_create_event():
    assert should_create_event(1, 0.0) is True
    assert should_create_event(0, 0.71) is False
    assert should_create_event(0, 0.72) is True


def test_score_to_band():
    assert score_to_band(10) == "LOW"
    assert score_to_band(45) == "MEDIUM"
    assert score_to_band(70) == "HIGH"
    assert score_to_band(90) == "CRITICAL"
