"use client";

import { useState } from "react";

type AlertItem = {
  id: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  acknowledged: boolean;
};

type BlockedIpItem = {
  id: number;
  ip_address: string;
};

type Props = {
  alerts: AlertItem[];
  blockedIps: BlockedIpItem[];
};

export default function OperationsPanel({ alerts, blockedIps }: Props) {
  const [busy, setBusy] = useState<string>("");
  const [error, setError] = useState<string>("");
  const openAlerts = alerts.filter((a) => !a.acknowledged).slice(0, 8);
  const activeBlocks = blockedIps.slice(0, 8);

  async function acknowledgeAlert(alertId: number) {
    try {
      setBusy(`ack-${alertId}`);
      setError("");
      const response = await fetch(`/api/logging/alerts/${alertId}/acknowledge`, {
        method: "POST"
      });
      if (!response.ok) {
        throw new Error("Failed to acknowledge alert");
      }
      window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy("");
    }
  }

  async function unblockIp(ipAddress: string) {
    try {
      setBusy(`unblock-${ipAddress}`);
      setError("");
      const response = await fetch(
        `/api/logging/unblock-ip?ip=${encodeURIComponent(ipAddress)}`,
        {
          method: "POST"
        }
      );
      if (!response.ok) {
        throw new Error("Failed to unblock IP");
      }
      window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <section className="card operations-card">
      <div className="card-header">
        <h2>Operations</h2>
        <span className="count-badge">{openAlerts.length + activeBlocks.length}</span>
      </div>
      <p className="ops-subtitle">Acknowledge alerts and unblock IPs directly from the dashboard.</p>
      {error ? <p className="error-text">{error}</p> : null}
      <div className="ops-grid">
        <div>
          <h3>Open Alerts</h3>
          {openAlerts.length === 0 ? <p className="empty-cell">No open alerts.</p> : null}
          {openAlerts.map((alert) => (
            <div key={alert.id} className="ops-row">
              <span className={`severity severity-${alert.severity.toLowerCase()}`}>
                {alert.severity}
              </span>
              <button
                className="btn"
                onClick={() => acknowledgeAlert(alert.id)}
                disabled={busy === `ack-${alert.id}`}
              >
                {busy === `ack-${alert.id}` ? "Acknowledging..." : `Acknowledge #${alert.id}`}
              </button>
            </div>
          ))}
        </div>
        <div>
          <h3>Active Blocks</h3>
          {activeBlocks.length === 0 ? <p className="empty-cell">No active blocks.</p> : null}
          {activeBlocks.map((entry) => (
            <div key={entry.id} className="ops-row">
              <span>{entry.ip_address}</span>
              <button
                className="btn btn-danger"
                onClick={() => unblockIp(entry.ip_address)}
                disabled={busy === `unblock-${entry.ip_address}`}
              >
                {busy === `unblock-${entry.ip_address}` ? "Unblocking..." : "Unblock"}
              </button>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
