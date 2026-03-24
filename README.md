# SentinelStack

SentinelStack is a Docker-based security monitoring lab. It collects request telemetry, detects suspicious behavior, generates alerts, applies temporary blocks for critical threats, and tracks internal service port exposure over time.

## How It Works

- `nginx` is the single entrypoint.
- `demo-app` handles requests and forwards request metadata to `logging-service`.
- `logging-service` stores logs in Postgres, evaluates detection rules, creates threat events and alerts, and manages block state.
- `portguard-service` scans allowlisted internal targets, stores results, compares against the previous scan, and reports newly opened ports back to `logging-service`.
- `frontend` displays logs, events, alerts, blocked IPs, and Port Guard scan history.

## Detection and Response

Request-based rules include repeated failed login attempts, request spikes, repeated 404 probing, and unauthorized access to sensitive routes.

Each event receives a score and severity:
- `0-29` Low
- `30-59` Medium
- `60-79` High
- `80-100` Critical

Medium+ events generate alerts. Critical events can trigger temporary IP blocking.

## Port Guard

Port Guard runs TCP probes only against allowed internal targets.  
Each scan is saved and compared to the previous scan for that same target.

- `new_open_ports` = ports that are open now but were not open in the previous scan.
- New port findings can be ingested as threat events/alerts through `POST /ingest-portguard`.
- Repeated identical findings are deduplicated for a configurable time window.
- Optional scheduled scans are supported through environment variables.

## Data Stored

Postgres persists:
- `request_logs`
- `threat_events`
- `alerts`
- `blocked_ips`
- `port_scans`
- `port_scan_results`

## Main Config Areas (`.env`)

- Rule thresholds and score weights
- Severity cutoffs
- Auto-block duration
- Port Guard targets, scan timing, and alert/ingest settings
