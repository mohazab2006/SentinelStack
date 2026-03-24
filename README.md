# SentinelStack

**End-to-end AI-augmented SOC lab in Docker.** Telemetry flows from ingest through detection and scoring, into **structured OpenAI completions** on alerts, and out to a live operator dashboard. The point is one continuous pipeline where **generative AI is built in**, not bolted on: every serious alert can carry model-generated **context**, **risk framing**, and **recommended actions** alongside classic SOC fields.

Under the hood the same pipeline is **ingest → detect → enrich → persist → visualize**, with **clear service boundaries** so each stage stays testable and swappable.

---

## Stack

| Piece | Role |
| :--- | :--- |
| **Next.js** | Operator dashboard: metrics, AI-enriched alert and event views, Port Guard, CSV export, refresh controls |
| **nginx** | Single public entry (`:8080`), reverse proxy to UI and APIs |
| **FastAPI (logging)** | Ingest, hybrid scoring, threat events, alerts, block list, rollups, **integrated OpenAI completion path** for alert intelligence |
| **FastAPI (demo-app)** | Reference workload that forwards telemetry into the logging API |
| **FastAPI (portguard)** | Allowlisted TCP discovery, scan history, scheduled sweeps, webhooks for newly open ports |
| **Postgres** | Durable store for logs, events, alerts, blocks, scan results, AI fields, persisted schedule preferences |

---

## What it does

### Detection

- Correlates HTTP telemetry into **coherent signals**: credential abuse, volume anomalies, recon-style paths and status patterns.
- Layers **explicit thresholds** with a capped **anomaly contribution** so every score stays explainable before it ever reaches the AI layer.
- Outputs feed **alerts** that the **LLM pipeline** can complete with narrative and recommendations in the same request lifecycle.

### Response

- Promotes high-confidence outcomes to **alerts** with traceability to the underlying event.
- **Critical** paths can **automatically block** the offending source IP for a configurable window.
- **Sub-critical** cases support **operator-driven blocks** from the dashboard.
- **Port Guard** compares successive scans and surfaces **newly exposed listeners** on internal targets.

### AI in the loop

- **One structured OpenAI completion per qualifying alert** adds **narrative context**, a **0 to 100 AI risk read** that frames the situation for humans, and **concrete next steps**. Results are **persisted** and shown **next to scores and reasons** so triage stays in one screen.
- **Deterministic detection** (rules plus anomaly math) gives you **fast triggers and auditable baselines**. The **LLM layer** turns those triggers into **interpretable, action-oriented intelligence** so operators spend less time deciphering raw signals.
- **`.env`** controls the full AI stack: API credentials, model id, per-output toggles, and workflow helpers such as **auto-ack** when the model’s risk read sits below a floor you define.

### Dashboard

- Unified **live posture**: volume, alert backlog, active blocks, Port Guard history, **and LLM-generated fields** on events and alerts.
- **Activity summary** (1 hour / 24 hours) with **consistency hints** on rollup math.
- **Severity filters** for focused triage sessions.

### Ops

- **Pause or retune** full-page auto-refresh without redeploying.
- **`scripts/validate_stack.ps1`**: lightweight smoke against the metrics summary API for demos and checks.

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
| 4 | Set **`OPENAI_API_KEY`** so the **AI completion path** is live; `.env.example` lists model selection, feature toggles, and **`AI_AUTO_ACK_WHEN_AI_SCORE_LE`** |
