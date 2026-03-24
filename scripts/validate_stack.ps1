# Quick health checks for SentinelStack (run while stack is up on localhost:8080).
$ErrorActionPreference = "Stop"
$Base = if ($env:SENTINELSTACK_URL) { $env:SENTINELSTACK_URL.TrimEnd("/") } else { "http://localhost:8080/api/logging" }

Write-Host "GET $Base/metrics/summary?window=24h"
$summary = Invoke-RestMethod -Uri "$Base/metrics/summary?window=24h" -Method Get

Write-Host "  requests_in_window: $($summary.requests_in_window)"
Write-Host "  events_in_window: $($summary.events_in_window)"
Write-Host "  alerts_created_in_window: $($summary.alerts_created_in_window)"
Write-Host "  alerts_count_consistent: $($summary.alerts_count_consistent)"
Write-Host "  top_ips_counts_valid: $($summary.top_ips_counts_valid)"

if (-not $summary.alerts_count_consistent) {
    Write-Warning "alerts_count_consistent is false — severity buckets may not sum to new alerts (investigate data or query logic)."
}
if (-not $summary.top_ips_counts_valid) {
    Write-Warning "top_ips_counts_valid is false — top-IP row sums exceed events in window (investigate)."
}

Write-Host "Done."
