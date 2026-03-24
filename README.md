# SentinelStack - Milestone 2

Milestone 2 keeps the Milestone 1 observability pipeline and adds rule-based threat detection with alerts:

- traffic enters through NGINX
- requests hit the demo app
- request metadata is ingested by the logging service
- logs are stored in Postgres
- suspicious patterns trigger threat events
- medium/high/critical events generate alerts
- a Next.js dashboard displays recent logs and alerts

## Services

- `nginx`: reverse proxy entrypoint (`http://localhost:8080`)
- `demo-app`: protected demo API (proxied at `/api/demo/*`)
- `logging-service`: ingest/list logs API (proxied at `/api/logging/*`)
- `postgres`: stores `request_logs`, `threat_events`, and `alerts`
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

## Validation Checklist

- `docker compose up --build` starts all services
- hitting `/api/demo/*` writes rows to Postgres
- suspicious traffic creates rows in `/api/logging/events`
- medium/high/critical events create rows in `/api/logging/alerts`
- dashboard shows logs and alerts
- data persists with `postgres_data` volume

## Notes
- If startup fails with Docker engine/pipe errors on Windows, start Docker Desktop and rerun `docker compose up --build -d`.
