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

**Detection**  
Looks for bad patterns (like many failed logins, traffic spikes, or odd URL/status mix).  
Combines **fixed rules** with a small **behavioral/anomaly** bump, then assigns a **score** and **severity**.

**Response**  
Turns serious scores into **alerts**. **Critical** can **auto-block** the IP. **Lower** severities can be **blocked manually** from the dashboard. **Port Guard** can alert when **new ports** show up on internal hosts.

**AI (OpenAI)**  
One API call can add to each new alert: a **short explanation**, an **advisory risk score (0–100)**, and **suggested next steps** — shown on the dashboard and stored in the DB.  
**Who’s in charge?** Rules + anomaly scores still set **severity** and **blocking**. You turn AI pieces on/off in `.env`. You can also **auto-ack** alerts when the AI score is very low (noise control).

**Dashboard**  
Live **metrics**, **alerts** and **events** (with severity filters), **Activity summary** (last hour or 24h), and quick checks that summary numbers add up.

**Day-to-day**  
You can **pause** or slow **auto-refresh**. Run **`scripts/validate_stack.ps1`** to print summary health from the API.

## Run

```bash
docker compose up --build -d
```

Open **http://localhost:8080**. Stop with `docker compose down`.

Copy **`.env.example`** → **`.env`**. Set **`OPENAI_API_KEY`** for LLM triage; see the example file for **`OPENAI_MODEL`**, feature toggles, and **`AI_AUTO_ACK_WHEN_AI_SCORE_LE`**.
