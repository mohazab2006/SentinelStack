# SentinelStack

**Dockerized security monitoring lab** — request logging, rule + behavioral scoring, alerts, IP blocks (auto + manual), internal port-change detection, a Next.js analyst dashboard, and **LLM-assisted triage** layered on deterministic scoring.

It implements an end-to-end SOC-style pipeline — **ingest → detect → persist → visualize** — with each stage in its own service.

---

## Stack

| Piece | Role |
| :--- | :--- |
| **Next.js** | Dashboard: metrics, alerts, events, blocks, Port Guard, CSV export |
| **nginx** | Single entry (`:8080`), routes to UI + APIs |
| **FastAPI (logging)** | Ingest, scoring (rules + anomaly), events, alerts, blocks, summaries, OpenAI-backed enrichment |
| **FastAPI (demo-app)** | Sample app that emits traffic into the pipeline |
| **FastAPI (portguard)** | Scheduled / on-demand TCP probes of allowlisted hosts; webhooks new open ports |
| **Postgres** | Logs, events, alerts, blocks, scans, schedule prefs |

---

## What it does

### Detection

- Watches for risky patterns: e.g. many failed logins, traffic spikes, odd URL / status mix.
- Merges **rule-based signals** with a small **behavioral / anomaly** layer.
- Produces a **score** and **severity** for each threat event.

### Response

- Raises **alerts** from higher scores.
- **Critical** → can **auto-block** the source IP.
- **Lower severities** → **manual block** from the dashboard.
- **Port Guard** → alerts when **new ports** appear on scanned internal targets.

### AI (OpenAI)

- Adds (per new alert, one round-trip): **plain-English summary**, **advisory 0–100 score**, **suggested next steps** — stored and shown in the UI.
- **Severity and blocking** still come from **rules + anomaly** (not the model).
- Configure in **`.env`**: API key, toggles per AI field, optional **auto-ack** for very low AI scores.

### Dashboard

- **Metrics**, **alerts**, **events** (with severity filters).
- **Activity summary** (1h / 24h) plus quick **sanity checks** on the numbers.

### Ops

- **Pause** or change **auto-refresh** interval on the dashboard.
- **`scripts/validate_stack.ps1`** — prints summary health from the API.

---

## Run

```bash
docker compose up --build -d
```

| Step | Action |
| :--- | :--- |
| 1 | Open **http://localhost:8080** |
| 2 | Stop with `docker compose down` |
| 3 | Copy **`.env.example`** → **`.env`** |
| 4 | Set **`OPENAI_API_KEY`** for LLM triage; see `.env.example` for model name, AI toggles, and `AI_AUTO_ACK_WHEN_AI_SCORE_LE` |
