# SentinelStack AI

A **Dockerized security monitoring system** that simulates a modern SOC-style pipeline — combining **deterministic threat detection**, **AI-assisted triage**, and **exposure monitoring (Port Guard)** to turn raw telemetry into actionable insight.

SentinelStack is designed to feel like a real security workflow: traffic is ingested, behavior is analyzed, threats are surfaced, responses are triggered, and operators get both **hard signals** and **AI-enhanced context** in one place.

---

## What It Does

SentinelStack connects the full pipeline:

- **Ingest** application traffic and telemetry  
- **Detect** threats using rules and behavioral scoring  
- **Monitor** internal exposure with Port Guard  
- **Respond** with blocking and operator control  
- **Enhance** alerts with AI-assisted triage  

---

## Core Capabilities

### Hybrid Threat Detection

Transforms raw HTTP activity into structured signals such as:

- credential abuse patterns  
- abnormal request volume  
- recon-style probing behavior  

Detection combines:

- **explicit rules and thresholds** (clear + explainable)  
- **lightweight anomaly scoring** (behavioral context)  
- **bounded scoring logic** (predictable outputs)  

Each event produces a **score, severity, and reasoning**.

---

### Response and Control

- Escalates high-confidence events into **alerts**  
- Supports **automatic IP blocking** for critical activity  
- Allows **manual operator actions** from the dashboard  

---

### Exposure Monitoring (Port Guard)

Port Guard tracks changes in internal network exposure:

- detects **newly opened TCP ports**  
- maintains scan history over time  
- surfaces unexpected services as findings  

This adds **infrastructure-level visibility**, not just request-level detection.

---

### AI-Assisted Triage

OpenAI is used to enrich alerts with:

- contextual summaries  
- advisory risk scoring  
- actionable recommendations  

Design principle:

- **Detection & response → deterministic (rules + scoring)**  
- **AI → interpretation and triage support**

---

## Architecture

| Component | Role |
| :-- | :-- |
| **Next.js Dashboard** | Operator interface for metrics, alerts, and filtering |
| **nginx** | Entry point and reverse proxy |
| **FastAPI (logging)** | Ingest, scoring, alerts, blocking, AI enrichment |
| **FastAPI (demo-app)** | Generates and forwards telemetry |
| **FastAPI (portguard)** | Internal port discovery and exposure tracking |
| **Postgres** | Persistent storage |

---

## Dashboard

- Real-time activity and alert visibility  
- Severity-based filtering  
- Active block tracking  
- Port Guard exposure history  

---

## Run

```bash
docker compose up --build -d
