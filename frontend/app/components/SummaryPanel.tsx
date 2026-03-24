"use client";

import { useCallback, useEffect, useState } from "react";

type SummaryNamedCount = {
  name: string;
  count: number;
};

type ActivitySummary = {
  window: string;
  requests_in_window: number;
  events_in_window: number;
  alerts_created_in_window: number;
  open_alerts: number;
  active_blocks: number;
  alerts_by_severity: Record<string, number>;
  top_event_ips: SummaryNamedCount[];
  top_event_types: SummaryNamedCount[];
  alerts_severity_sum: number;
  alerts_count_consistent: boolean;
  top_event_ip_rows_sum: number;
  top_ips_counts_valid: boolean;
};

const numberFormatter = new Intl.NumberFormat();

function formatNumber(value: number) {
  return numberFormatter.format(value);
}

export default function SummaryPanel() {
  const [windowKey, setWindowKey] = useState<"1h" | "24h">("24h");
  const [data, setData] = useState<ActivitySummary | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async (w: "1h" | "24h") => {
    try {
      setError("");
      const response = await fetch(`/api/logging/metrics/summary?window=${w}`, { cache: "no-store" });
      if (!response.ok) {
        throw new Error("Summary unavailable");
      }
      const json = (await response.json()) as ActivitySummary;
      setData(json);
    } catch {
      setError("Could not load activity summary.");
      setData(null);
    }
  }, []);

  useEffect(() => {
    void load(windowKey);
  }, [load, windowKey]);

  useEffect(() => {
    const id = window.setInterval(() => {
      void load(windowKey);
    }, 10000);
    return () => window.clearInterval(id);
  }, [load, windowKey]);

  return (
    <section className="card summary-card">
      <div className="card-header">
        <h2>Activity summary</h2>
        <div className="summary-window-toggle" role="group" aria-label="Time window">
          <button
            type="button"
            className={windowKey === "1h" ? "summary-window-btn active" : "summary-window-btn"}
            onClick={() => setWindowKey("1h")}
          >
            Last hour
          </button>
          <button
            type="button"
            className={windowKey === "24h" ? "summary-window-btn active" : "summary-window-btn"}
            onClick={() => setWindowKey("24h")}
          >
            Last 24h
          </button>
        </div>
      </div>
      <p className="ops-subtitle">
        Rolling counts for requests, threat events, and alerts. Top lists are from threat events in the selected window.
      </p>
      {error ? <p className="error-text">{error}</p> : null}
      {data ? (
        <>
          <div className="summary-stats">
            <div className="summary-stat">
              <span className="summary-stat-label">Requests</span>
              <strong>{formatNumber(data.requests_in_window)}</strong>
            </div>
            <div className="summary-stat">
              <span className="summary-stat-label">Threat events</span>
              <strong>{formatNumber(data.events_in_window)}</strong>
            </div>
            <div className="summary-stat">
              <span className="summary-stat-label">Alerts (new)</span>
              <strong>{formatNumber(data.alerts_created_in_window)}</strong>
            </div>
            <div className="summary-stat">
              <span className="summary-stat-label">Open alerts</span>
              <strong>{formatNumber(data.open_alerts)}</strong>
            </div>
            <div className="summary-stat">
              <span className="summary-stat-label">Active blocks</span>
              <strong>{formatNumber(data.active_blocks)}</strong>
            </div>
          </div>
          <div className="summary-severity-row">
            <span className="summary-subheading">New alerts by severity</span>
            <div className="summary-severity-chips">
              {(["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).map((s) => (
                <span key={s} className={`severity severity-${s.toLowerCase()}`}>
                  {s}: {formatNumber(data.alerts_by_severity[s] ?? 0)}
                </span>
              ))}
            </div>
          </div>
          <div className="summary-verify" aria-label="Summary consistency checks">
            <div
              className={`summary-verify-item ${data.alerts_count_consistent ? "ok" : "warn"}`}
              title="Sum of severity chips should equal new alerts in the same window"
            >
              <span className="summary-verify-label">Severity sum</span>
              <span className="summary-verify-value">
                {formatNumber(data.alerts_severity_sum)} / {formatNumber(data.alerts_created_in_window)}
                {data.alerts_count_consistent ? " — OK" : " — mismatch"}
              </span>
            </div>
            <div
              className={`summary-verify-item ${data.top_ips_counts_valid ? "ok" : "warn"}`}
              title="Top IP counts are a subset of events; their sum should not exceed total events"
            >
              <span className="summary-verify-label">Top IP counts</span>
              <span className="summary-verify-value">
                {formatNumber(data.top_event_ip_rows_sum)} / {formatNumber(data.events_in_window)}
                {data.top_ips_counts_valid ? " — OK" : " — check data"}
              </span>
            </div>
          </div>
          <div className="summary-columns">
            <div>
              <span className="summary-subheading">Top IPs (events)</span>
              <ul className="summary-list">
                {data.top_event_ips.length === 0 ? (
                  <li className="empty-cell">No events in this window.</li>
                ) : (
                  data.top_event_ips.map((row) => (
                    <li key={row.name}>
                      <span className="mono">{row.name}</span>
                      <span className="summary-count">{formatNumber(row.count)}</span>
                    </li>
                  ))
                )}
              </ul>
            </div>
            <div>
              <span className="summary-subheading">Top event types</span>
              <ul className="summary-list">
                {data.top_event_types.length === 0 ? (
                  <li className="empty-cell">No events in this window.</li>
                ) : (
                  data.top_event_types.map((row) => (
                    <li key={row.name}>
                      <span className="mono">{row.name}</span>
                      <span className="summary-count">{formatNumber(row.count)}</span>
                    </li>
                  ))
                )}
              </ul>
            </div>
          </div>
        </>
      ) : !error ? (
        <p className="empty-cell">Loading summary…</p>
      ) : null}
    </section>
  );
}
