# SentinelStack

A **Dockerized security monitoring system** that simulates a modern SOC-style pipeline — combining **deterministic threat detection** with **AI-assisted triage** to turn raw telemetry into actionable insight.

SentinelStack is designed to feel like a real security workflow: traffic is ingested, behavior is analyzed, threats are surfaced, responses are triggered, and operators are given both **hard signals** and **AI-enhanced context** in one place.

---

## Why It Stands Out

Most projects stop at logging or dashboards.

SentinelStack connects the full pipeline:

- **Ingest** application traffic
- **Detect** suspicious behavior using rules and scoring
- **Persist** events, alerts, and actions
- **Respond** with blocking and operator control
- **Enhance** with AI-driven context

It sits at the intersection of **cybersecurity engineering, backend systems, and applied AI**.

---

## Core Security Capabilities

### Hybrid Threat Detection

SentinelStack transforms raw HTTP activity into structured security signals such as:

- credential abuse patterns  
- abnormal request volume  
- recon-style probing behavior  
- suspicious endpoint and status combinations  

Detection is built using a hybrid model:

- **explicit rules and thresholds** for clarity  
- **lightweight anomaly scoring** for behavioral context  
- **bounded scoring logic** to keep results explainable  

Each evaluated event produces:

- a score  
- a severity level  
- structured detection reasoning  

---

### Response and Control

High-confidence detections can be promoted into alerts with full traceability.

The system supports:

- **automatic IP blocking** for critical activity  
- **manual operator actions** from the dashboard  
- **clear escalation flow** from event → alert → response  

This makes SentinelStack feel like an **active system**, not just passive monitoring.

---

### Exposure Awareness (Port Guard)

SentinelStack includes a dedicated service that monitors internal exposure:

- tracks open TCP ports on allowlisted targets  
- detects newly exposed services  
- maintains scan history over time  

New exposure is surfaced as a first-class security finding, adding infrastructure-level visibility alongside application-level detection.

---

## AI-Assisted Triage

SentinelStack integrates OpenAI to enhance alert analysis without replacing core logic.

For selected alerts, the system can generate:

- contextual summaries  
- advisory risk scoring  
- actionable recommendations  

The architecture is intentionally split:

- **Detection, severity, and blocking → rule-based and deterministic**
- **AI → interpretation and triage support**

This keeps decisions reliable while still benefiting from modern AI capabilities.

---

## Architecture

SentinelStack is built with clear service boundaries so each component is independently testable and replaceable.

| Component | Role |
| :-- | :-- |
| **Next.js Dashboard** | Operator interface for metrics, alerts, filters, and Port Guard |
| **nginx** | Entry point and reverse proxy |
| **FastAPI (logging)** | Ingest pipeline, scoring engine, alerts, blocking, AI enrichment |
| **FastAPI (demo-app)** | Generates and forwards telemetry |
| **FastAPI (portguard)** | Internal port discovery and exposure tracking |
| **Postgres** | Persistent storage for all system data |

---

## Dashboard

The interface is built for real-time visibility and focused triage:

- activity summaries (1h / 24h)
- alert filtering by severity
- active block tracking
- exposure history (Port Guard)

---

## Run

```bash
docker compose up --build -d
