# SentinelStack TODO

## Next Session
- [ ] Confirm dashboard auto-refresh feels smooth (no flicker)
- [ ] Verify scheduler stays reliable at 1-minute interval for 10+ minutes
- [ ] Add "last auto-scan time" label in Port Guard card
- [ ] Add scheduler setting persistence across container restarts
- [x] Improve Port Guard alert message formatting (replace odd dash character)
- [ ] Decide if background scans should be enabled by default
- [ ] Commit and push final M5 + dashboard UX changes

## Milestone 6 (Anomaly + Scoring)
- [x] Define anomaly signals (path diversity, status mix, velocity jump vs prior minute)
- [x] Add anomaly score calculation in `logging-service` (`app/anomaly.py`)
- [x] Merge rule score + anomaly score into final score (capped at 100; anomaly capped by `ANOMALY_SCORE_CAP`)
- [x] Add anomaly reason text into threat event `reasons` (`anomaly: ...`)
- [x] Optional: call LLM for supplemental risk text on alerts only (keep heuristics as source of truth)
- [ ] Validate severity mapping and alert thresholds with sample traffic

## Milestone 7 (Summaries + Analyst View)
- [x] Add summary endpoint `GET /metrics/summary?window=1h|24h`
- [x] Include top IPs, top event types, new alerts by severity, open alerts, active blocks
- [x] Dashboard **Activity summary** panel with 1h / 24h toggle + auto-refresh
- [x] Severity filters for **Recent Alerts** and **Threat Events** (`?alertSeverity=` / `?eventSeverity=`), backed by `GET /alerts` and `GET /events` optional `severity` query param
- [x] Summary sanity checklist (manual or via API flags):
  - [ ] `GET /metrics/summary?window=24h` → `requests_in_window` matches rough expectation from `GET /logs` volume in that period (or SQL count)
  - [ ] `alerts_count_consistent` is true (equivalently: sum of `alerts_by_severity` equals `alerts_created_in_window`)
  - [ ] `top_ips_counts_valid` is true; spot-check one IP in `GET /events?limit=500`

## Upgrade SentinelStack with AI
- [ ] AI threat scoring
- [x] AI alert explanation (plain English, optional via `OPENAI_API_KEY`)
- [ ] AI recommendations
- [ ] Optional auto-response

## Nice To Have Later
- [ ] Add pause/resume button for auto-refresh interval
- [ ] Add per-target scan duration and status in UI
- [ ] Add export button for alerts/events
