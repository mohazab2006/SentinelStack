"""Optional OpenAI JSON bundle: explanation, advisory score, recommendations (one API call)."""

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


def _parse_json_blob(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json|JSON)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)
    return json.loads(text)


async def fetch_alert_ai_bundle(
    *,
    subject: str,
    event_type: str,
    severity: str,
    reasons_text: str,
    rule_score: int,
    anomaly_score: int,
    final_score: int,
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
            "(do not mirror final_score; stack heuristics remain authoritative for automation)",
        )
    if want_recs:
        key_parts.append(
            '"recommendations": string or null (two short imperative items, separated by " | ")',
        )

    prompt = (
        f"Subject: {subject}\n"
        f"Type: {event_type}\n"
        f"Severity (heuristic): {severity}\n"
        f"Scores: rule={rule_score} anomaly={anomaly_score} final={final_score}\n"
        f"Signals: {reasons_text}\n\n"
        "Return ONLY one JSON object with exactly these keys: "
        + ", ".join(key_parts)
        + ". Use null for any field you cannot justify from the signals. No markdown, no extra text."
    )

    try:
        async with httpx.AsyncClient(timeout=18.0) as client:
            payload: dict[str, Any] = {
                "model": OPENAI_MODEL,
                "temperature": 0.15,
                "max_tokens": 450,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You assist SOC triage. Respond with JSON only. "
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
