# SentinelStack

**Dockerized security monitoring lab** that wires together request logging, hybrid detection (rules plus lightweight behavioral scoring), alerting, IP blocking, internal port drift detection, a Next.js operations dashboard, and **LLM-assisted triage** on top of deterministic scoring.

The design is an end-to-end SOC-style pipeline, **ingest → detect → persist → visualize**, with **clear service boundaries** so each concern stays testable and replaceable.

---

## Stack

| Piece | Role |
| :--- | :--- |
| **Next.js** | Operator dashboard: metrics, filtered lists, Port Guard, CSV export, refresh controls |
| **nginx** | Single public entry (`:8080`), reverse proxy to UI and APIs |
| **FastAPI (logging)** | Ingest, scoring pipeline, threat events, alerts, block list, rollups, OpenAI-backed enrichment |
| **FastAPI (demo-app)** | Reference workload that forwards telemetry into the logging API |
| **FastAPI (portguard)** | Allowlisted TCP discovery, scan history, scheduled sweeps, webhooks for newly open ports |
| **Postgres** | Durable store for logs, events, alerts, blocks, scan results, persisted schedule preferences |

---

## What it does

### Detection

- Correlates noisy HTTP telemetry into **coherent signals**: credential abuse, volume anomalies, recon-style paths and status patterns.
- Layers **explicit thresholds** with a capped **anomaly contribution** so scoring stays explainable and bounded.
- Every evaluated episode gets a numeric **score**, a **severity** band, and structured **reasons** suitable for review and automation.

### Response

- Promotes high-confidence outcomes to **alerts** with full traceability back to the underlying event.
- **Critical** paths can **automatically block** the offending source IP for a configurable window.
- **Sub-critical** cases support **operator-driven blocks** directly from the dashboard.
- **Port Guard** compares successive scans and surfaces **newly exposed listeners** on internal targets as first-class findings.

### AI (OpenAI)

- Enriches qualifying alerts in **one structured completion**: narrative context, an **advisory 0 to 100** risk read (independent of the stack score), and **actionable recommendations**, persisted and rendered beside traditional fields.
- **Severity, blocking, and policy** remain owned by **rules and anomaly math**; the model is advisory unless you wire explicit automation (for example low-score auto-ack).
- Behavior is **fully driven by `.env`**: credentials, model id, per-feature toggles, and optional acknowledgment thresholds.

### Dashboard

- Unified view of **live posture**: request and event volume, alert backlog, active blocks, Port Guard history.
- **Activity summary** windows (1 hour / 24 hours) include **consistency hints** so operators can sanity-check rollups at a glance.
- **Severity filters** keep long-running triage sessions focused.

### Ops

- **Pause or retune** full-page auto-refresh without redeploying.
- **`scripts/validate_stack.ps1`**: lightweight smoke against the metrics summary API for demos and CI-style checks.

---

## Run

```bash
docker compose up --build -d
```

| Step | Action |
| :--- | :--- |
| 1 | Browse **http://localhost:8080** |
| 2 | Tear down with `docker compose down` |
| 3 | Copy **`.env.example`** to **`.env`** and adjust secrets |
| 4 | Provide **`OPENAI_API_KEY`** for LLM features; `.env.example` documents model selection, AI flags, and **`AI_AUTO_ACK_WHEN_AI_SCORE_LE`** |
