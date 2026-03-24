"use client";

import { useState } from "react";

type OpenPortSummary = {
  port: number;
  service: string | null;
  risk_level: string;
};

type PortScanSummary = {
  id: number;
  target: string;
  scanned_at: string;
  open_count: number;
  high_risk_count: number;
  open_ports?: OpenPortSummary[];
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
};

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function PortGuardSection({ scans, allowedTargets, defaultTarget }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [target, setTarget] = useState(
    allowedTargets.includes(defaultTarget) ? defaultTarget : allowedTargets[0] ?? defaultTarget
  );

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
      window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card portguard-card">
      <div className="card-header">
        <h2>Port Guard</h2>
        <span className="count-badge">{scans.length}</span>
      </div>
      <p className="ops-subtitle">
        Allowlisted TCP probes against internal stack hosts. Results persist in Postgres; new open ports
        are highlighted after each run.
      </p>
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
              <th>Open</th>
              <th>High / critical</th>
              <th>Open ports</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 ? (
              <tr>
                <td colSpan={5} className="empty-cell">
                  No scans yet. Run a scan to populate history.
                </td>
              </tr>
            ) : (
              scans.map((s) => {
                const opens = s.open_ports ?? [];
                return (
                <tr key={s.id}>
                  <td>{formatDateTime(s.scanned_at)}</td>
                  <td className="mono">{s.target}</td>
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
