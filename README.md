# SentinelStack

**Dockerized security monitoring lab** — request logging, rule + behavioral scoring, alerts, optional IP blocks, internal port-change detection, and a Next.js analyst dashboard.

Good for showing end-to-end “build something SOC-shaped”: ingest → detect → persist → visualize, with clear service boundaries.

## Stack

| Piece | Role |
|--------|------|
| **Next.js** | Dashboard: metrics, alerts, events, blocks, Port Guard, CSV export |
| **nginx** | Single entry (`:8080`), routes to UI + APIs |
| **FastAPI (logging)** | Ingest, scoring (rules + anomaly layer), events, alerts, blocks, summaries |
| **FastAPI (demo-app)** | Sample app that emits traffic into the pipeline |
| **FastAPI (portguard)** | Scheduled/on-demand TCP probes of allowlisted internal hosts; webhooks new open ports |
| **Postgres** | Logs, events, alerts, blocks, scans, schedule prefs |

## What it does

- **Detection:** Threshold rules (e.g. failed logins, spikes, probing) plus lightweight anomaly signals; merged into a capped **final score** and severity.
- **Response:** Alerts; **auto-block** on critical paths; **manual block** from the UI for lower severities; Port Guard can raise alerts on new listening ports.
- **Analyst view:** Rolling **activity summary** (1h/24h), severity filters, sanity checks on summary math, optional **OpenAI**-assisted explanation / advisory score / recommendations (heuristics stay authoritative).
- **Ops:** Paused/confgurable dashboard refresh, `scripts/validate_stack.ps1` for a quick summary health readout.

## Run

```bash
docker compose up --build -d
```

Open **http://localhost:8080**. Stop with `docker compose down`.

Copy `.env.example` → `.env` and adjust as needed. Optional: set `OPENAI_API_KEY` for AI triage fields on new alerts.
