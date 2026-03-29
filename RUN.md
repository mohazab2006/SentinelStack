# Running SentinelStack

SentinelStack runs as a multi-container stack: Postgres, three FastAPI services, a Next.js frontend, and nginx as the single HTTP entrypoint.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) with [Docker Compose](https://docs.docker.com/compose/) v2 (`docker compose` CLI)

## 1. Environment file

From the repository root, copy the example env file and edit if needed:

```bash
cp .env.example .env
```

The stack reads `./.env` for Postgres credentials, service URLs inside Docker, detection thresholds, and optional OpenAI settings. At minimum, the values in `.env.example` are enough for a local demo.

**Optional — AI triage features:** set `OPENAI_API_KEY` in `.env` for alert explanations, advisory scoring, and recommendations. Heuristic detection and blocking work without it.

## 2. Start the stack

From the repository root:

```bash
docker compose up --build
```

First start may take several minutes while images build. Wait until all services are healthy or running without restart loops.

## 3. Open the app

- **Dashboard (main UI):** [http://localhost:8080](http://localhost:8080)  
  nginx proxies `/` to the Next.js app and routes APIs under `/api/*`.

- **Behind nginx (paths you rarely need directly):**
  - Logging API: `http://localhost:8080/api/logging/...`
  - Demo app: `http://localhost:8080/api/demo/...`
  - Port Guard API: `http://localhost:8080/api/portguard/...`

Postgres is exposed on host port **5432** for local tools if you need direct DB access.

## 4. Stop the stack

Press `Ctrl+C` in the terminal where Compose is running, or in another shell from the repo root:

```bash
docker compose down
```

To remove the named volume and reset the database:

```bash
docker compose down -v
```

## 5. Optional: validate the logging API (Windows)

With the stack up, from the repo root in PowerShell:

```powershell
.\scripts\validate_stack.ps1
```

By default this calls `http://localhost:8080/api/logging`. Override the base URL with `SENTINELSTACK_URL` if needed.

## Troubleshooting

- **Port 8080 in use:** change the host mapping in `docker-compose.yml` under the `nginx` service (`"8080:80"` → e.g. `"9080:80"`) and open `http://localhost:9080`.
- **Port 5432 in use:** adjust the `postgres` ports mapping or stop the conflicting Postgres instance.
- **Stale containers after code changes:** `docker compose up --build` rebuilds images; use `docker compose build --no-cache` if you suspect a bad layer cache.
