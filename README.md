# SentinelStack

**AI cybersecurity platform for real-time threat detection, intelligent triage, and automated response.**

SentinelStack implements a full Security Operations Center (SOC) pipeline — from raw traffic ingestion to LLM-assisted alert triage — combining deterministic rule-based detection with machine learning anomaly detection.

---

## Pipeline

Traffic → Ingestion → Feature Extraction → Rule Detection + Anomaly Detection → Score Fusion → Severity Classification → Automated Response → LLM Triage

---

## Detection Engine

SentinelStack uses two detection layers that run in parallel and feed into a unified score fusion engine.

**Rule-Based Detection**
Deterministic detection of known attack patterns — brute force, port scanning, malformed payloads, authentication flooding. Fast, auditable, no false negatives on known signatures.

**Behavioral Anomaly Detection (Isolation Forest)**
Extracts 8 behavioral signals per source IP over rolling time windows:

- Requests per minute
- Failed authentication ratio
- Unique endpoints accessed
- 4xx / 5xx error ratios
- Request timing patterns
- Path entropy
- Suspicious payload frequency
- Authentication endpoint concentration

These features feed an Isolation Forest model (scikit-learn) that learns baseline behavior and flags statistical deviations as normalized anomaly scores.

**Score Fusion Engine**
Combines rule-based and anomaly scores into a unified severity classification:

| Severity | Automated Action |
|---|---|
| LOW | Log only |
| MEDIUM | Log + alert |
| HIGH | Alert + flag |
| CRITICAL | Alert + optional auto-block |

---

## AI Design Principles

Detection and enforcement are fully deterministic. The LLM layer runs post-detection only — it generates alert summaries, contextual risk explanations, and recommended next actions. Blocking decisions are never based on LLM output alone.

---

## Architecture

| Service | Role |
|---|---|
| **Next.js Dashboard** | SOC-style UI — events, alerts, system visibility |
| **logging-service (FastAPI)** | Ingestion, detection, scoring, response, AI enrichment |
| **demo-app (FastAPI)** | Traffic simulation for testing |
| **portguard-service (FastAPI)** | Monitors live infrastructure exposure and port changes |
| **PostgreSQL** | Stores events, alerts, block lists |
| **NGINX** | Reverse proxy, single entry point |

---

## Stack

| Layer | Tech |
|---|---|
| **Backend** | Python, FastAPI |
| **ML** | scikit-learn (Isolation Forest) |
| **Frontend** | Next.js, TypeScript, Tailwind CSS |
| **Data** | PostgreSQL |
| **AI Triage** | LLM APIs |
| **Infra** | Docker Compose, NGINX |

---

## Running

See `RUN.md` for Docker Compose setup, environment variables, and service URLs.
