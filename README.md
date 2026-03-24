# SentinelStack

**Dockerized security monitoring lab** — request logging, rule + behavioral scoring, alerts, optional IP blocks, internal port-change detection, a Next.js analyst dashboard, and **optional LLM-assisted triage** on top of deterministic scoring.

It implements an end-to-end SOC-style pipeline — **ingest → detect → persist → visualize** — with each stage in its own service.

## Stack

| Piece | Role |
|--------|------|
| **Next.js** | Dashboard: metrics, alerts, events, blocks, Port Guard, CSV export |
| **nginx** | Single entry (`:8080`), routes to UI + APIs |
| **FastAPI (logging)** | Ingest, scoring (rules + anomaly layer), events, alerts, blocks, summaries, **optional OpenAI enrichment** |
| **FastAPI (demo-app)** | Sample app that emits traffic into the pipeline |
| **FastAPI (portguard)** | Scheduled/on-demand TCP probes of allowlisted internal hosts; webhooks new open ports |
| **Postgres** | Logs, events, alerts, blocks, scans, schedule prefs |

## What it does

- **Detection:** Threshold rules (e.g. failed logins, spikes, probing) plus lightweight anomaly signals; merged into a capped **final score** and severity.
- **Response:** Alerts; **auto-block** on critical paths; **manual block** from the UI for lower severities; Port Guard can raise alerts on new listening ports.
- **AI leverage (optional):** With `OPENAI_API_KEY`, new alerts get a **structured model response** in one round-trip: short **plain-English summary** on the alert, an **advisory 0–100 risk score** (separate from rule/anomaly scores), and **recommended next steps**, all stored and shown on the dashboard. **Heuristics still drive severity and blocking**; toggles in `.env` let you turn pieces on or off. Optional **auto-ack** when the advisory score is below a threshold you set.
- **Analyst view:** Rolling **activity summary** (1h/24h), severity filters, sanity checks on summary math.
- **Ops:** Paused / configurable dashboard refresh, `scripts/validate_stack.ps1` for a quick summary health readout.

## Run

```bash
docker compose up --build -d
```

Open **http://localhost:8080**. Stop with `docker compose down`.

Copy **`.env.example`** → **`.env`**. For AI triage, set **`OPENAI_API_KEY`** (and optionally `OPENAI_MODEL`, `AI_ALERT_EXPLAIN_ENABLED`, `AI_THREAT_SCORING_ENABLED`, `AI_RECOMMENDATIONS_ENABLED`, `AI_AUTO_ACK_WHEN_AI_SCORE_LE` — see the example file).
