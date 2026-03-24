"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const PAUSED_KEY = "sentinelstack_dashboard_refresh_paused";
const INTERVAL_KEY = "sentinelstack_dashboard_refresh_interval_ms";

export default function DashboardRefreshBar() {
  const router = useRouter();
  const [paused, setPaused] = useState(false);
  const [intervalMs, setIntervalMs] = useState(10_000);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    try {
      setPaused(sessionStorage.getItem(PAUSED_KEY) === "1");
      const raw = sessionStorage.getItem(INTERVAL_KEY);
      if (raw) {
        const n = Number.parseInt(raw, 10);
        if (Number.isFinite(n) && n >= 5000 && n <= 120_000) {
          setIntervalMs(n);
        }
      }
    } catch {
      /* ignore */
    }
    setHydrated(true);
  }, []);

  function persistPaused(next: boolean) {
    setPaused(next);
    try {
      sessionStorage.setItem(PAUSED_KEY, next ? "1" : "0");
    } catch {
      /* ignore */
    }
  }

  function persistInterval(ms: number) {
    setIntervalMs(ms);
    try {
      sessionStorage.setItem(INTERVAL_KEY, String(ms));
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    if (!hydrated || paused) {
      return;
    }
    const id = window.setInterval(() => {
      router.refresh();
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [router, intervalMs, paused, hydrated]);

  return (
    <div className="dashboard-refresh-bar" role="group" aria-label="Dashboard auto-refresh">
      <button type="button" className="btn btn-refresh" onClick={() => persistPaused(!paused)}>
        {paused ? "Resume refresh" : "Pause refresh"}
      </button>
      <label className="refresh-interval-label">
        <span>Interval</span>
        <select
          className="refresh-interval-select"
          value={intervalMs}
          onChange={(e) => persistInterval(Number(e.target.value))}
          disabled={!hydrated}
          aria-label="Refresh interval"
        >
          <option value={5000}>5s</option>
          <option value={10000}>10s</option>
          <option value={30000}>30s</option>
          <option value={60000}>60s</option>
        </select>
      </label>
      {paused ? <span className="refresh-paused-note">Auto-refresh paused</span> : null}
    </div>
  );
}
