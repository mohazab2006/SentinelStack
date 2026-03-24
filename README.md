# SentinelStack

SentinelStack is a local security monitoring lab that runs fully in Docker.

It is built to simulate a small SOC-style workflow in one stack:
- Collects request logs
- Detects suspicious behavior
- Creates alerts (and temporary IP blocks for critical threats)
- Scans internal services for newly opened ports (Port Guard)

## How It's Built
- `frontend` (Next.js) - dashboard UI
- `nginx` - single entrypoint + reverse proxy
- `demo-app` (FastAPI) - generates and serves test traffic
- `logging-service` (FastAPI) - log ingest, rule scoring, events, alerts, block logic
- `portguard-service` (FastAPI) - internal TCP scanning + scan history + new-port detection
- `postgres` - persistence for logs, events, alerts, blocks, and scan data

Detection uses fixed rules first, then adds a small behavioral anomaly layer (path diversity, HTTP status mix, traffic velocity) so `final_score` can rise above rule-only scoring when patterns look odd.

The logging service exposes `GET /metrics/summary?window=1h|24h` for a rolling analyst snapshot (counts, alert severity breakdown, top IPs and event types). The response also includes `alerts_count_consistent` and `top_ips_counts_valid` so you can spot-check that severity buckets sum to new alerts and that top-IP counts stay within total events. The dashboard shows this as **Activity summary** with those checks surfaced inline. List views can filter with `GET /events?severity=MEDIUM` and `GET /alerts?severity=HIGH` (dashboard uses query params on the home page).

Optional AI triage (requires `OPENAI_API_KEY` in `.env`): one model call can populate (1) a short explanation appended to the alert message, (2) an **advisory** 0–100 risk score stored on the threat event and shown on the dashboard, and (3) brief recommended next steps. Toggles: `AI_ALERT_EXPLAIN_ENABLED`, `AI_THREAT_SCORING_ENABLED`, `AI_RECOMMENDATIONS_ENABLED`. Rule + anomaly scores still drive severity and auto-block; AI output is informational unless you opt into auto-ack with `AI_AUTO_ACK_WHEN_AI_SCORE_LE` (acknowledges new alerts when the AI advisory score is at or below that threshold).

## How It Works
- Requests come in through `nginx` to `demo-app`
- `demo-app` sends request metadata to `logging-service`
- `logging-service` stores data in Postgres and creates threat events/alerts
- `portguard-service` scans allowlisted internal targets and reports `new_open_ports`
- The dashboard shows live metrics, events, alerts, blocked IPs, and Port Guard scans

## Start / Stop
- Start: `docker compose up --build -d`
- Stop: `docker compose down`

## Quick checks
- With the stack up on `http://localhost:8080`, run `scripts/validate_stack.ps1` to print summary counters and consistency flags from `GET /metrics/summary?window=24h`.
- Port Guard schedule settings (on/off, interval, targets) are stored in Postgres (`portguard_schedule_prefs`) and reloaded on service restart.
