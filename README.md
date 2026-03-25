# SentinelStack AI

SentinelStack is a Dockerized cyber security platform that combines deterministic detections with behavioral AI signals and analyst-facing AI triage.

It is built to feel like a real SOC workflow: ingest traffic, extract behavior, detect threats, fuse scores, trigger response, and provide explainable alert context.

---

## What SentinelStack Does

- Ingests HTTP request telemetry from your app flow
- Detects known attack patterns with explicit rules
- Detects suspicious unknown behavior with anomaly scoring
- Fuses rule score + anomaly score into a clear severity outcome
- Automates response (alerting, flagging, optional auto-block)
- Uses OpenAI for post-detection triage summaries and recommendations
- Monitors internal exposure changes with Port Guard

---

## AI in SentinelStack

SentinelStack is AI-powered in two layers:

1) **Behavioral anomaly detection (in detection path)**
- Feature extraction over rolling windows per source
- Learns what normal behavior looks like, then flags unusual patterns
- Combines fast ML checks with optional LLM advisory signal
- Outputs `anomaly_score_norm` for explainable, deterministic fusion

2) **AI triage (post-detection analyst support)**
- Alert explanation
- Advisory risk score
- Recommended next actions

Design policy:
- Detection and enforcement remain deterministic and auditable
- AI influences scoring and triage context
- Blocking is never delegated blindly to LLM output alone

---

## Detection Pipeline

Traffic -> Ingestion -> Behavior Features ->
Rule Detection + AI Anomaly Detection -> Score Fusion -> Severity -> Response -> AI Triage

Key behavior signals include:
- requests per minute
- failed authentication ratio
- unique endpoints
- 4xx / 5xx ratios
- request timing patterns
- path entropy
- suspicious payload frequency
- auth endpoint concentration

---

## Severity and Response Model

- **LOW**: log only
- **MEDIUM**: log + alert
- **HIGH**: alert + flagged
- **CRITICAL**: alert + auto-block

---

## Architecture

| Component | Role |
| :-- | :-- |
| Next.js Dashboard | SOC-style UI for events, alerts, blocks, and AI status |
| nginx | Reverse proxy + single entrypoint |
| FastAPI logging-service | Ingestion, rule engine, anomaly scoring, fusion, response, AI enrichment |
| FastAPI demo-app | Traffic generator / simulation app |
| FastAPI portguard-service | Exposure monitoring and port-delta findings |
| Postgres | Persistent event, alert, and block data |

---
