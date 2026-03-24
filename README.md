# SentinelStack - Milestone 3

Milestone 3 extends Milestone 2 with response actions:

- traffic enters through NGINX
- requests hit the demo app
- request metadata is ingested by the logging service
- logs are stored in Postgres
- suspicious patterns trigger threat events
- medium/high/critical events generate alerts
- critical threats can trigger automated IP blocking
- a Next.js dashboard displays logs, alerts, and blocked IPs

## Services

- `nginx`: reverse proxy entrypoint (`http://localhost:8080`)
- `demo-app`: protected demo API (proxied at `/api/demo/*`)
- `logging-service`: ingest/list logs API (proxied at `/api/logging/*`)
- `postgres`: stores `request_logs`, `threat_events`, `alerts`, and `blocked_ips`
- `frontend`: dashboard UI

## Project Structure

- `frontend/` - Next.js dashboard
- `services/demo-app/` - FastAPI app generating protected traffic
- `services/logging-service/` - FastAPI ingest and log retrieval APIs
- `postgres/init.sql` - DB schema bootstrap
- `nginx/nginx.conf` - reverse proxy routing
- `docker-compose.yml` - local orchestration

## Quick Start

1. Ensure Docker Desktop is running.
2. Copy `.env.example` to `.env` (already done for this workspace).
3. Build and start the stack:

```bash
docker compose up --build -d
```

4. Open dashboard:

`http://localhost:8080`

## Generate Demo Traffic

Run these against NGINX:

```bash
curl http://localhost:8080/api/demo/
curl -X POST http://localhost:8080/api/demo/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"wrong\"}"
curl -X POST http://localhost:8080/api/demo/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"password123\"}"
curl http://localhost:8080/api/demo/admin
curl http://localhost:8080/api/demo/admin -H "x-admin-token: admin-secret"
```

These requests are forwarded by `demo-app` to:

- `POST /ingest-request` on `logging-service`

Then visible in dashboard via:

- `GET /logs?limit=50` on `logging-service`

## API Endpoints

### Demo App (`/api/demo`)

- `GET /` - health/demo response
- `POST /login` - simulated auth
- `GET /admin` - token-protected route via `x-admin-token`
- `GET /profile` - normal route for traffic variety
- `GET /reports` - normal route for traffic variety
- `GET /config` - token-protected sensitive route

### Logging Service (`/api/logging`)

- `GET /health` - service health
- `POST /ingest-request` - store request metadata
- `GET /logs?limit=50` - list newest request logs
- `GET /events?limit=50` - list newest threat events
- `GET /alerts?limit=50` - list newest alerts
- `GET /blocked-ips?limit=100` - list active blocked IPs
- `GET /is-blocked?ip=<ip>` - check if IP is blocked
- `POST /block-ip` - manual block
- `POST /unblock-ip?ip=<ip>` - remove active blocks
- `POST /alerts/{alert_id}/acknowledge` - acknowledge an alert
- `GET /metrics/overview` - request/event/alert/block counters
- `GET /metrics/severity` - severity distribution counts

## Detection Rules (Milestone 2)

Rules are evaluated on ingest per source IP:

- brute-force: 5+ failed `/login` attempts in 5 minutes
- repeated 404 probing: 8+ 404 responses in 5 minutes
- request spike: 30+ requests in 1 minute
- sensitive route probing: 3+ unauthorized hits to `/admin` or `/config` in 5 minutes

Scoring maps to severity:

- `0-29`: Low
- `30-59`: Medium
- `60-79`: High
- `80-100`: Critical

Alerts are created automatically for Medium and above.

## Response Actions (Milestone 3)

- Critical events trigger automatic IP block for 60 minutes.
- Demo app checks block status before serving protected requests.
- Blocked IP requests receive `403 Forbidden`.
- Manual blocking and unblocking are supported via logging-service endpoints.
- Alerts can be acknowledged from the dashboard operations panel.

## Configurable Thresholds

Rule thresholds, weights, severity cutoffs, and auto-block duration are configurable through `.env`:

- `FAILED_LOGIN_THRESHOLD`, `FAILED_LOGIN_SCORE`
- `REQUEST_SPIKE_THRESHOLD`, `REQUEST_SPIKE_SCORE`
- `REPEATED_404_THRESHOLD`, `REPEATED_404_SCORE`
- `SENSITIVE_PROBE_THRESHOLD`, `SENSITIVE_PROBE_SCORE`
- `LOW_MAX`, `MEDIUM_MAX`, `HIGH_MAX`
- `AUTO_BLOCK_MINUTES`

## Validation Checklist

- `docker compose up --build` starts all services
- hitting `/api/demo/*` writes rows to Postgres
- suspicious traffic creates rows in `/api/logging/events`
- medium/high/critical events create rows in `/api/logging/alerts`
- critical traffic can create active entries in `/api/logging/blocked-ips`
- blocked IP traffic gets `403`
- dashboard shows logs, alerts, and blocked IPs
- data persists with `postgres_data` volume

## Notes
- If startup fails with Docker engine/pipe errors on Windows, start Docker Desktop and rerun `docker compose up --build -d`.
