# SentinelStack TODO

## Next Session
- [ ] Confirm dashboard auto-refresh feels smooth (no flicker)
- [ ] Verify scheduler stays reliable at 1-minute interval for 10+ minutes
- [ ] Add "last auto-scan time" label in Port Guard card
- [ ] Add scheduler setting persistence across container restarts
- [ ] Improve Port Guard alert message formatting (replace odd dash character)
- [ ] Decide if background scans should be enabled by default
- [ ] Commit and push final M5 + dashboard UX changes

## Milestone 6 (Anomaly + Scoring)
- [ ] Define anomaly signals (time burst, unusual path mix, repeated sensitive route hits)
- [ ] Add anomaly score calculation in `logging-service`
- [ ] Merge rule score + anomaly score into final score with clear weights
- [ ] Add anomaly reason text into threat event `reasons`
- [ ] Validate severity mapping and alert thresholds with sample traffic

## Milestone 7 (Summaries + Analyst View)
- [ ] Add summary endpoint for recent security activity (last 1h / 24h)
- [ ] Include top offending IPs, top event types, and alert counts by severity
- [ ] Add dashboard summary card/panel for quick analyst view
- [ ] Add simple filters (time window + severity) for events/alerts table
- [ ] Add test checklist for summary accuracy vs raw events

## Nice To Have Later
- [ ] Add pause/resume button for auto-refresh interval
- [ ] Add per-target scan duration and status in UI
- [ ] Add export button for alerts/events
