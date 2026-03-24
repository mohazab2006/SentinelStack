# SentinelStack

**Dockerized security monitoring lab** — request logging, rule + behavioral scoring, alerts, IP blocks (auto + manual), internal port-change detection, a Next.js analyst dashboard, and **LLM-assisted triage** layered on deterministic scoring.

It implements an end-to-end SOC-style pipeline — **ingest → detect → persist → visualize** — with each stage in its own service.

## Stack

| Piece | Role |
|--------|------|
| **Next.js** | Dashboard: metrics, alerts, events, blocks, Port Guard, CSV export |
| **nginx** | Single entry (`:8080`), routes to UI + APIs |
| **FastAPI (logging)** | Ingest, scoring (rules + anomaly layer), events, alerts, blocks, summaries, **OpenAI-backed alert enrichment** |
| **FastAPI (demo-app)** | Sample app that emits traffic into the pipeline |
| **FastAPI (portguard)** | Scheduled/on-demand TCP probes of allowlisted internal hosts; webhooks new open ports |
| **Postgres** | Logs, events, alerts, blocks, scans, schedule prefs |

## What it does

- **Detection:** Threshold rules (e.g. failed logins, spikes, probing) plus lightweight anomaly signals; merged into a capped **final score** and severity.
- **Response:** Alerts; **auto-block** on critical paths; **manual block** from the UI for lower severities; Port Guard can raise alerts on new listening ports.
- **AI leverage:** New alerts can receive a **structured LLM response** in one round-trip (`OPENAI_API_KEY` in `.env`): **plain-English summary** on the alert, an **advisory 0–100 risk score** (separate from rule/anomaly scores), and **recommended next steps**, stored and surfaced on the dashboard. **Heuristics still drive severity and blocking**; env toggles control each AI output; **auto-ack** can clear low-confidence noise when the advisory score is below a threshold you set.
- **Analyst view:** Rolling **activity summary** (1h/24h), severity filters, sanity checks on summary math.
- **Ops:** Paused / configurable dashboard refresh, `scripts/validate_stack.ps1` for a quick summary health readout.

## Run

```bash
docker compose up --build -d
```

Open **http://localhost:8080**. Stop with `docker compose down`.

Copy **`.env.example`** → **`.env`**. Set **`OPENAI_API_KEY`** for LLM triage; see the example file for **`OPENAI_MODEL`**, feature toggles, and **`AI_AUTO_ACK_WHEN_AI_SCORE_LE`**.
