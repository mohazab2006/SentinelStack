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

## How It Works
- Requests come in through `nginx` to `demo-app`
- `demo-app` sends request metadata to `logging-service`
- `logging-service` stores data in Postgres and creates threat events/alerts
- `portguard-service` scans allowlisted internal targets and reports `new_open_ports`
- The dashboard shows live metrics, events, alerts, blocked IPs, and Port Guard scans

## Start / Stop
- Start: `docker compose up --build -d`
- Stop: `docker compose down`
