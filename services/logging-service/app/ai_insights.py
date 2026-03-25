"""OpenAI: triage bundle after detection + optional LLM behavioral risk assessment (advisory)."""

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

import httpx

logger = logging.getLogger("uvicorn.error")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()


def _flag(name: str, default: bool = True) -> bool:
    raw = os.getenv(name, "true" if default else "false").lower()
    return raw in ("1", "true", "yes")


AI_ALERT_EXPLAIN_ENABLED = _flag("AI_ALERT_EXPLAIN_ENABLED", True)
AI_THREAT_SCORING_ENABLED = _flag("AI_THREAT_SCORING_ENABLED", True)
AI_RECOMMENDATIONS_ENABLED = _flag("AI_RECOMMENDATIONS_ENABLED", True)
ANOMALY_LLM_ENABLED = _flag("ANOMALY_LLM_ENABLED", True)


@dataclass
class AlertAiBundle:
    explanation: Optional[str]
    advisory_score: Optional[int]
    recommendations: Optional[str]


def ai_insights_configured() -> bool:
    return bool(OPENAI_API_KEY) and (
        AI_ALERT_EXPLAIN_ENABLED
        or AI_THREAT_SCORING_ENABLED
        or AI_RECOMMENDATIONS_ENABLED
    )


def anomaly_llm_enabled() -> bool:
    return bool(OPENAI_API_KEY) and ANOMALY_LLM_ENABLED


def _parse_json_blob(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json|JSON)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)
    return json.loads(text)


async def fetch_llm_anomaly_assessment(
    *,
    subject_ip: str,
    features: dict[str, Any],
    statistical_norm: float,
    iforest_norm: Optional[float] = None,
) -> tuple[Optional[float], Optional[str]]:
    """
    LLM advisory 0–1 behavioral risk from structured features (does not replace deterministic engine).
    Blended with statistical / Isolation Forest scores upstream when enabled.
    """
    if not anomaly_llm_enabled():
        return None, None

    payload_if = "null" if iforest_norm is None else f"{iforest_norm:.4f}"
    user = (
        f"Source IP: {subject_ip}\n"
        f"Engine statistical anomaly (0-1): {statistical_norm:.4f}\n"
        f"Isolation Forest anomaly (0-1): {payload_if}\n"
        f"Feature JSON (rolling window): {json.dumps(features, default=str)[:3500]}\n\n"
        'Return ONLY one JSON object: {"behavioral_risk_0_1": number 0-1, "one_line_rationale": string or null}. '
        "behavioral_risk_0_1 must reflect unusual attack-like or automated behavior vs benign traffic given features only. "
        "Do not copy the engine numbers; form an independent view. No markdown."
    )

    try:
        async with httpx.AsyncClient(timeout=14.0) as client:
            payload: dict[str, Any] = {
                "model": OPENAI_MODEL,
                "temperature": 0.08,
                "max_tokens": 220,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You assess HTTP request-sequence behavior for security monitoring. "
                            "Output JSON only. Never invent IPs, paths, or volumes not implied by input."
                        ),
                    },
                    {"role": "user", "content": user},
                ],
            }
            if OPENAI_MODEL.startswith("gpt-4") or OPENAI_MODEL.startswith("gpt-3.5-turbo"):
                payload["response_format"] = {"type": "json_object"}

            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code >= 400:
                logger.warning("OpenAI anomaly assessment failed: %s %s", resp.status_code, resp.text[:200])
                return None, None
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                return None, None
            content = (choices[0].get("message") or {}).get("content") or ""
            obj = _parse_json_blob(content)
    except Exception:
        logger.exception("OpenAI anomaly assessment error")
        return None, None

    risk: Optional[float] = None
    raw_r = obj.get("behavioral_risk_0_1")
    if isinstance(raw_r, (int, float)):
        risk = max(0.0, min(1.0, float(raw_r)))
    elif isinstance(raw_r, str):
        try:
            risk = max(0.0, min(1.0, float(raw_r.strip())))
        except ValueError:
            pass

    note: Optional[str] = None
    ln = obj.get("one_line_rationale")
    if isinstance(ln, str):
        note = ln.strip().replace("\n", " ")
        if len(note) > 280:
            note = note[:277] + "..."

    return risk, note


def _format_context_block(
    *,
    triggered_rules: Optional[list] = None,
    contributing_features: Optional[list] = None,
    severity_reason: Optional[str] = None,
    anomaly_score_norm: Optional[float] = None,
    feature_snapshot: Optional[dict[str, Any]] = None,
    layer_scores: Optional[dict[str, Any]] = None,
) -> str:
    parts: list[str] = []
    if severity_reason:
        parts.append(f"Severity_reason: {severity_reason}")
    if anomaly_score_norm is not None:
        parts.append(f"Blended_anomaly_norm: {anomaly_score_norm:.4f}")
    if layer_scores:
        parts.append(f"Anomaly_layers: {json.dumps(layer_scores, default=str)}")
    if triggered_rules:
        parts.append(f"Triggered_rules: {json.dumps(triggered_rules, default=str)[:2000]}")
    if contributing_features:
        parts.append(f"Contributing_features: {json.dumps(contributing_features, default=str)[:2000]}")
    if feature_snapshot:
        parts.append(f"Features_snapshot: {json.dumps(feature_snapshot, default=str)[:1500]}")
    return "\n".join(parts) if parts else ""


async def fetch_alert_ai_bundle(
    *,
    subject: str,
    event_type: str,
    severity: str,
    reasons_text: str,
    rule_score: int,
    anomaly_score: int,
    final_score: int,
    triggered_rules: Optional[list] = None,
    contributing_features: Optional[list] = None,
    severity_reason: Optional[str] = None,
    anomaly_score_norm: Optional[float] = None,
    feature_snapshot: Optional[dict[str, Any]] = None,
    layer_scores: Optional[dict[str, Any]] = None,
) -> Optional[AlertAiBundle]:
    if not ai_insights_configured():
        return None

    want_explain = AI_ALERT_EXPLAIN_ENABLED
    want_score = AI_THREAT_SCORING_ENABLED
    want_recs = AI_RECOMMENDATIONS_ENABLED

    key_parts: list[str] = []
    if want_explain:
        key_parts.append(
            '"explanation": string or null (one or two sentences for a junior SOC analyst)',
        )
    if want_score:
        key_parts.append(
            '"advisory_score": integer 0-100, your independent risk estimate from the signals only '
            "(do not mirror final_score; deterministic automation remains authoritative for blocking)",
        )
    if want_recs:
        key_parts.append(
            '"recommendations": string or null (two short imperative items, separated by " | ")',
        )

    ctx = _format_context_block(
        triggered_rules=triggered_rules,
        contributing_features=contributing_features,
        severity_reason=severity_reason,
        anomaly_score_norm=anomaly_score_norm,
        feature_snapshot=feature_snapshot,
        layer_scores=layer_scores,
    )

    prompt = (
        f"Subject: {subject}\n"
        f"Type: {event_type}\n"
        f"Severity (stack): {severity}\n"
        f"Scores: rule={rule_score} anomaly_legacy_int={anomaly_score} final={final_score}\n"
        f"Signals summary: {reasons_text}\n"
    )
    if ctx:
        prompt += f"\nStructured detection context:\n{ctx}\n"

    prompt += (
        "\nReturn ONLY one JSON object with exactly these keys: "
        + ", ".join(key_parts)
        + ". Use null for any field you cannot justify from the signals. No markdown, no extra text."
    )

    try:
        async with httpx.AsyncClient(timeout=22.0) as client:
            payload: dict[str, Any] = {
                "model": OPENAI_MODEL,
                "temperature": 0.12,
                "max_tokens": 550,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You assist SOC triage for SentinelStack. Respond with JSON only. "
                            "Use rule scores, anomaly layers, and feature snapshots when present. "
                            "Do not invent hosts, users, URLs, or traffic not implied by the signals."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            }
            if OPENAI_MODEL.startswith("gpt-4") or OPENAI_MODEL.startswith("gpt-3.5-turbo"):
                payload["response_format"] = {"type": "json_object"}

            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code >= 400:
                logger.warning("OpenAI insights failed: %s %s", resp.status_code, resp.text[:200])
                return None
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                return None
            content = (choices[0].get("message") or {}).get("content") or ""
            obj = _parse_json_blob(content)
    except Exception:
        logger.exception("OpenAI insights request error")
        return None

    explanation: Optional[str] = None
    if want_explain:
        ex = obj.get("explanation")
        if isinstance(ex, str):
            explanation = ex.strip().replace("\n", " ")
            if len(explanation) > 450:
                explanation = explanation[:447] + "..."

    advisory_score: Optional[int] = None
    if want_score:
        raw_s = obj.get("advisory_score")
        if isinstance(raw_s, (int, float)):
            advisory_score = max(0, min(100, int(raw_s)))
        elif isinstance(raw_s, str):
            try:
                advisory_score = max(0, min(100, int(raw_s.strip())))
            except ValueError:
                pass

    recommendations: Optional[str] = None
    if want_recs:
        rec = obj.get("recommendations")
        if isinstance(rec, str):
            recommendations = rec.strip().replace("\n", " ")
            if len(recommendations) > 400:
                recommendations = recommendations[:397] + "..."

    if explanation is None and advisory_score is None and recommendations is None:
        return None
    return AlertAiBundle(
        explanation=explanation,
        advisory_score=advisory_score,
        recommendations=recommendations,
    )
