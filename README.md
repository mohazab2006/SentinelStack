# SentinelStack

SentinelStack is a Dockerized AI cybersecurity platform that simulates a real Security Operations Center (SOC) workflow. It ingests traffic, analyzes behavior, detects threats, fuses risk signals, automates response, and provides explainable AI-assisted triage.

---

## 🚀 Overview

SentinelStack is engineered to replicate how modern SOC systems operate:

**Traffic → Detection → Scoring → Response → Triage**

It combines deterministic security logic with machine learning and AI to create a transparent, scalable, and production-style cybersecurity pipeline.

---

## 🧠 What SentinelStack Does

- Ingests HTTP request telemetry from application traffic
- Detects known threats using rule-based detection
- Identifies unknown threats using anomaly detection (Isolation Forest)
- Fuses multiple risk signals into a unified severity score
- Automates response workflows (alerting, flagging, optional IP blocking)
- Provides AI-generated alert summaries, risk insights, and recommendations
- Monitors infrastructure exposure changes using Port Guard

---

## ⚙️ Core Capabilities

### 1. Rule-Based Detection
- Detects known attack patterns (e.g., brute force, scanning, malformed payloads)
- Fully deterministic and auditable
- Fast and reliable for known threat signatures

### 2. Behavioral Anomaly Detection
- Extracts behavioral features over rolling time windows per source
- Uses **Isolation Forest (scikit-learn)** for anomaly detection
- Learns baseline behavior and flags deviations
- Outputs normalized anomaly scores (`anomaly_score_norm`)

### 3. Score Fusion Engine
- Combines:
  - Rule-based detection score
  - Anomaly detection score
- Produces final severity classification:
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL

---

## 🔄 Detection Pipeline
Traffic:
→ Ingestion
→ Feature Extraction
→ Rule Detection + Anomaly Detection (Isolation Forest)
→ Score Fusion
→ Severity Classification
→ Automated Response
→ AI Triage (LLM)

---

## 📊 Behavior Signals Used

- Requests per minute
- Failed authentication ratio
- Unique endpoints accessed
- 4xx / 5xx error ratios
- Request timing patterns
- Path entropy
- Suspicious payload frequency
- Authentication endpoint concentration

---

## 🚨 Severity & Response Model

| Severity  | Action                          |
|----------|---------------------------------|
| LOW      | Log only                        |
| MEDIUM   | Log + alert                     |
| HIGH     | Alert + flagged                 |
| CRITICAL | Alert + auto-block (optional)   |

---

## 🤖 AI in SentinelStack

SentinelStack uses AI in **two controlled layers**:

### 1. Behavioral Detection (Real-Time)
- Isolation Forest anomaly detection
- Fast, explainable scoring
- Optional LLM advisory signal (non-blocking)

### 2. AI Triage (Post-Detection)
- Generates alert summaries
- Provides contextual risk scoring
- Recommends next actions

### 🔒 Design Principles

- Detection and enforcement remain deterministic
- AI enhances insights, not control
- Blocking decisions are never based solely on LLM output

---

## 🏗️ Architecture

| Component                  | Role                                                                 |
|---------------------------|----------------------------------------------------------------------|
| Next.js Dashboard         | SOC-style UI for events, alerts, and system visibility              |
| nginx                     | Reverse proxy and single entry point                                |
| FastAPI logging-service   | Ingestion, detection, scoring, response, AI enrichment              |
| FastAPI demo-app          | Traffic simulation and testing                                      |
| FastAPI portguard-service | Monitors exposure and port changes                                  |
| PostgreSQL                | Stores events, alerts, and block data                               |

---

## ✨ Key Features

- Full SOC pipeline simulation
- Hybrid detection (rules + ML)
- Isolation Forest anomaly detection (scikit-learn)
- Real-time scoring and automated response
- AI-powered alert triage
- Dockerized microservices architecture
- Designed for extensibility and real-world workflows

---

## 🛠️ Running SentinelStack

For setup instructions, environment configuration, Docker Compose commands, and service URLs:

👉 See `RUN.md`

---

## 🎯 Project Vision

SentinelStack demonstrates how modern cybersecurity systems can combine:

- Deterministic detection (rules)
- Behavioral intelligence (ML)
- AI-assisted triage (LLMs)

to create a system that is:

- Transparent
- Scalable
- Explainable
- SOC-ready

It bridges the gap between traditional SIEM systems and next-generation AI-powered security platforms.