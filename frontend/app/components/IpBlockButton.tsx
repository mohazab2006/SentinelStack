"use client";

import { useState } from "react";

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

type Props = {
  ipAddress: string;
  severity: Severity;
  context: "alert" | "event";
  contextId: number;
  activeBlockedIps: string[];
};

const BLOCK_MINUTES = 60;

export default function IpBlockButton({
  ipAddress,
  severity,
  context,
  contextId,
  activeBlockedIps
}: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const synthetic = ipAddress.startsWith("portguard:");
  const blocked = activeBlockedIps.includes(ipAddress);
  const manualAllowed = severity !== "CRITICAL";

  async function blockNow() {
    try {
      setBusy(true);
      setError("");
      const response = await fetch("/api/logging/block-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ip_address: ipAddress,
          reason: `manual block (${context} #${contextId})`,
          duration_minutes: BLOCK_MINUTES
        })
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(detail || "Block failed");
      }
      window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Block failed");
    } finally {
      setBusy(false);
    }
  }

  if (synthetic) {
    return (
      <span className="table-block-na" title="Port Guard uses a synthetic key; block the real client at the edge if needed.">
        —
      </span>
    );
  }

  if (blocked) {
    return (
      <span className="status-chip status-ok" title="This IP has an active block.">
        blocked
      </span>
    );
  }

  if (!manualAllowed) {
    return (
      <span
        className="table-block-na"
        title="Critical severity is auto-blocked when the alert is created. Unblock from Operations if this was a false positive."
      >
        auto
      </span>
    );
  }

  return (
    <div className="table-block-wrap">
      <button type="button" className="btn btn-table-block" disabled={busy} onClick={() => void blockNow()}>
        {busy ? "Blocking…" : "Block IP"}
      </button>
      {error ? (
        <span className="table-block-error" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}
