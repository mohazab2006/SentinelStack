"use client";

import { useCallback, useEffect, useState } from "react";
import { formatDateTime } from "../lib/formatDateTime";

type OpenPortSummary = {
  port: number;
  service: string | null;
  risk_level: string;
};

type PortScanSummary = {
  id: number;
  target: string;
  scanned_at: string;
  duration_ms?: number | null;
  open_count: number;
  high_risk_count: number;
  open_ports?: OpenPortSummary[];
};

type PortguardScheduleStatus = {
  enabled: boolean;
  minutes: number;
  targets: string[];
  allowed_targets: string[];
  last_background_run_at?: string | null;
};

function riskTone(risk: string): string {
  const r = risk.toLowerCase();
  if (r === "critical") return "critical";
  if (r === "high") return "high";
  if (r === "medium") return "medium";
  return "low";
}

type Props = {
  scans: PortScanSummary[];
  allowedTargets: string[];
  defaultTarget: string;
  schedule: PortguardScheduleStatus;
};

export default function PortGuardSection({ scans, allowedTargets, defaultTarget, schedule }: Props) {
  const [liveScans, setLiveScans] = useState(scans);
  const [busy, setBusy] = useState(false);
  const [scheduleBusy, setScheduleBusy] = useState(false);
  const [error, setError] = useState("");
  const [scheduleError, setScheduleError] = useState("");
  const [target, setTarget] = useState(
    allowedTargets.includes(defaultTarget) ? defaultTarget : allowedTargets[0] ?? defaultTarget
  );
  const [scheduleEnabled, setScheduleEnabled] = useState(schedule.enabled);
  const [scheduleMinutes, setScheduleMinutes] = useState(String(schedule.minutes));
  const [scheduleTargets, setScheduleTargets] = useState<string[]>(
    schedule.targets.length > 0 ? schedule.targets : allowedTargets
  );
  const [lastBackgroundRunAt, setLastBackgroundRunAt] = useState<string | null>(
    schedule.last_background_run_at ?? null
  );

  const refreshPortguard = useCallback(async () => {
    try {
      const [scansRes, scheduleRes] = await Promise.all([
        fetch("/api/portguard/scans?limit=15", { cache: "no-store" }),
        fetch("/api/portguard/schedule", { cache: "no-store" })
      ]);
      if (scansRes.ok) {
        const nextScans = (await scansRes.json()) as PortScanSummary[];
        setLiveScans(nextScans);
      }
      if (scheduleRes.ok) {
        const nextSchedule = (await scheduleRes.json()) as PortguardScheduleStatus;
        setScheduleEnabled(nextSchedule.enabled);
        setScheduleMinutes(String(nextSchedule.minutes));
        setScheduleTargets(nextSchedule.targets);
        setLastBackgroundRunAt(nextSchedule.last_background_run_at ?? null);
      }
    } catch {
      // Ignore polling errors to avoid noisy UI while services restart.
    }
  }, []);

  useEffect(() => {
    setLiveScans(scans);
  }, [scans]);

  useEffect(() => {
    setLastBackgroundRunAt(schedule.last_background_run_at ?? null);
  }, [schedule.last_background_run_at]);

  useEffect(() => {
    const id = window.setInterval(() => {
      void refreshPortguard();
    }, 10000);
    return () => window.clearInterval(id);
  }, [refreshPortguard]);

  async function runScan() {
    try {
      setBusy(true);
      setError("");
      const response = await fetch("/api/portguard/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target || undefined })
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const detail =
          typeof body?.detail === "string"
            ? body.detail
            : Array.isArray(body?.detail)
              ? body.detail.map((d: { msg?: string }) => d.msg).filter(Boolean).join("; ")
              : "Scan failed";
        throw new Error(detail || "Scan failed");
      }
      await refreshPortguard();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function saveSchedule(nextEnabled: boolean, minutes: number, targets: string[]) {
    const response = await fetch("/api/portguard/schedule", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: nextEnabled, minutes, targets })
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      const detail =
        typeof body?.detail === "string"
          ? body.detail
          : Array.isArray(body?.detail)
            ? body.detail.map((d: { msg?: string }) => d.msg).filter(Boolean).join("; ")
            : "Schedule update failed";
      throw new Error(detail || "Schedule update failed");
    }
    const updated = (await response.json()) as PortguardScheduleStatus;
    setScheduleEnabled(updated.enabled);
    setScheduleMinutes(String(updated.minutes));
    setScheduleTargets(updated.targets);
  }

  async function toggleSchedule() {
    if (scheduleTargets.length === 0) {
      setScheduleError("Pick at least one background target.");
      return;
    }
    const nextEnabled = !scheduleEnabled;
    const parsed = Number.parseInt(scheduleMinutes, 10);
    const minutes = Number.isFinite(parsed) ? Math.min(1440, Math.max(1, parsed)) : 60;
    try {
      setScheduleBusy(true);
      setScheduleError("");
      await saveSchedule(nextEnabled, minutes, scheduleTargets);
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : "Schedule update failed");
    } finally {
      setScheduleBusy(false);
    }
  }

  async function applyMinutes() {
    if (scheduleTargets.length === 0) {
      setScheduleError("Pick at least one background target.");
      return;
    }
    const parsed = Number.parseInt(scheduleMinutes, 10);
    const minutes = Number.isFinite(parsed) ? Math.min(1440, Math.max(1, parsed)) : 60;
    try {
      setScheduleBusy(true);
      setScheduleError("");
      await saveSchedule(scheduleEnabled, minutes, scheduleTargets);
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : "Schedule update failed");
    } finally {
      setScheduleBusy(false);
    }
  }

  function toggleScheduleTarget(changed: string) {
    setScheduleTargets((prev) => {
      if (prev.includes(changed)) {
        if (prev.length === 1) {
          return prev;
        }
        return prev.filter((t) => t !== changed);
      }
      return [...prev, changed];
    });
  }

  return (
    <section className="card portguard-card">
      <div className="card-header">
        <h2>Port Guard</h2>
        <span className="count-badge">{liveScans.length}</span>
      </div>
      <p className="ops-subtitle">
        Allowlisted TCP probes against internal stack hosts. Results persist in Postgres; new open ports
        are highlighted after each run.
      </p>
      <div className="portguard-schedule">
        <p className="portguard-last-run">
          <span className="portguard-last-run-label">Last background sweep</span>
          <span className="mono">
            {lastBackgroundRunAt ? formatDateTime(lastBackgroundRunAt) : "— (none yet)"}
          </span>
        </p>
        <label className="portguard-label">
          Background scan
          <span className="portguard-status-text">
            Current: {scheduleEnabled ? "On" : "Off"}
          </span>
          <button
            type="button"
            className={`btn ${scheduleEnabled ? "" : "btn-danger"}`}
            onClick={toggleSchedule}
            disabled={scheduleBusy}
          >
            {scheduleBusy
              ? "Saving..."
              : scheduleEnabled
                ? "Turn off background scans"
                : "Turn on background scans"}
          </button>
        </label>
        <label className="portguard-label">
          Every (minutes)
          <input
            className="portguard-input"
            type="number"
            min={1}
            max={1440}
            value={scheduleMinutes}
            onChange={(e) => setScheduleMinutes(e.target.value)}
            disabled={scheduleBusy}
          />
        </label>
        <button type="button" className="btn" onClick={applyMinutes} disabled={scheduleBusy}>
          Apply interval
        </button>
      </div>
      <div className="portguard-targets">
        <span className="portguard-targets-title">Background targets</span>
        <div className="portguard-targets-list">
          {allowedTargets.map((t) => (
            <label key={`sched-${t}`} className="portguard-target-item">
              <input
                type="checkbox"
                checked={scheduleTargets.includes(t)}
                onChange={() => toggleScheduleTarget(t)}
                disabled={scheduleBusy}
              />
              <span className="mono">{t}</span>
            </label>
          ))}
        </div>
      </div>
      {scheduleError ? <p className="error-text">{scheduleError}</p> : null}
      <div className="portguard-actions">
        <label className="portguard-label">
          Target
          <select
            className="portguard-select"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={busy || allowedTargets.length === 0}
          >
            {allowedTargets.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="portguard-run" onClick={runScan} disabled={busy}>
          {busy ? "Scanning…" : "Run scan"}
        </button>
      </div>
      {error ? <p className="error-text">{error}</p> : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Target</th>
              <th>Duration</th>
              <th>Open</th>
              <th>High / critical</th>
              <th>Open ports</th>
            </tr>
          </thead>
          <tbody>
            {liveScans.length === 0 ? (
              <tr>
                <td colSpan={6} className="empty-cell">
                  No scans yet. Run a scan to populate history.
                </td>
              </tr>
            ) : (
              liveScans.map((s) => {
                const opens = s.open_ports ?? [];
                return (
                <tr key={s.id}>
                  <td>{formatDateTime(s.scanned_at)}</td>
                  <td className="mono">{s.target}</td>
                  <td className="mono" title="Wall time for TCP probes + DB write for this target">
                    {s.duration_ms != null ? `${s.duration_ms} ms` : "—"}
                  </td>
                  <td className="mono">{s.open_count}</td>
                  <td className="mono">{s.high_risk_count}</td>
                  <td className="portguard-ports-cell">
                    {opens.length === 0 ? (
                      <span className="empty-cell" style={{ fontStyle: "italic" }}>
                        none
                      </span>
                    ) : (
                      <ul className="portguard-port-list">
                        {opens.map((p) => (
                          <li key={`${s.id}-${p.port}`}>
                            <span className="mono">{p.port}</span>
                            {p.service ? (
                              <span className="portguard-svc">{p.service}</span>
                            ) : null}
                            <span className={`severity severity-${riskTone(p.risk_level)}`}>
                              {p.risk_level}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
