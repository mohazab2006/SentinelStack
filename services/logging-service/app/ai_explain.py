"""Optional OpenAI plain-English alert line (Milestone 6). Heuristic scores remain authoritative."""

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger("uvicorn.error")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()

_raw_flag = os.getenv("AI_ALERT_EXPLAIN_ENABLED", "true").lower()
AI_ALERT_EXPLAIN_ENABLED = _raw_flag in ("1", "true", "yes")


def ai_explain_configured() -> bool:
    return bool(OPENAI_API_KEY) and AI_ALERT_EXPLAIN_ENABLED


async def optional_alert_explanation(
    *,
    subject: str,
    event_type: str,
    severity: str,
    reasons_text: str,
    rule_score: int,
    anomaly_score: int,
    final_score: int,
) -> Optional[str]:
    if not ai_explain_configured():
        return None
    prompt = (
        f"Subject: {subject}\n"
        f"Type: {event_type}\n"
        f"Severity: {severity}\n"
        f"Scores: rule={rule_score} anomaly={anomaly_score} final={final_score}\n"
        f"Signals: {reasons_text}\n\n"
        "In one or two short sentences, explain what this likely means for a junior SOC analyst. "
        "Do not invent facts beyond the signals. No markdown."
    )
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": OPENAI_MODEL,
                    "temperature": 0.2,
                    "max_tokens": 150,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You summarize security telemetry tersely for operators.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                },
            )
            if resp.status_code >= 400:
                logger.warning("OpenAI explain failed: %s %s", resp.status_code, resp.text[:200])
                return None
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                return None
            content = (choices[0].get("message") or {}).get("content") or ""
            line = content.strip().replace("\n", " ")
            if len(line) > 450:
                line = line[:447] + "..."
            return line if line else None
    except Exception:
        logger.exception("OpenAI explain request error")
        return None
