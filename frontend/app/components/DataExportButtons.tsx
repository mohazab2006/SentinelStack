"use client";

type Props = {
  alertSeverity?: string;
  eventSeverity?: string;
};

function csvEscape(value: unknown): string {
  const t = value == null ? "" : String(value);
  if (/[",\n\r]/.test(t)) {
    return `"${t.replace(/"/g, '""')}"`;
  }
  return t;
}

function downloadCsv(filename: string, header: string[], rows: string[][]) {
  const lines = [header.join(","), ...rows.map((r) => r.map(csvEscape).join(","))];
  const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function DataExportButtons({ alertSeverity, eventSeverity }: Props) {
  async function exportAlerts() {
    const params = new URLSearchParams({ limit: "500" });
    if (alertSeverity) {
      params.set("severity", alertSeverity);
    }
    const response = await fetch(`/api/logging/alerts?${params}`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error("Failed to load alerts");
    }
    const data = (await response.json()) as Array<{
      id: number;
      threat_event_id: number;
      severity: string;
      message: string;
      created_at: string;
      acknowledged: boolean;
      source_ip?: string;
    }>;
    const header = ["id", "threat_event_id", "severity", "source_ip", "message", "created_at", "acknowledged"];
    const rows = data.map((a) => [
      String(a.id),
      String(a.threat_event_id),
      a.severity,
      a.source_ip ?? "",
      a.message,
      a.created_at,
      String(a.acknowledged),
    ]);
    downloadCsv(`sentinelstack-alerts-${Date.now()}.csv`, header, rows);
  }

  async function exportEvents() {
    const params = new URLSearchParams({ limit: "500" });
    if (eventSeverity) {
      params.set("severity", eventSeverity);
    }
    const response = await fetch(`/api/logging/events?${params}`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error("Failed to load threat events");
    }
    const data = (await response.json()) as Array<{
      id: number;
      ip_address: string;
      event_type: string;
      rule_score: number;
      anomaly_score: number;
      final_score: number;
      severity: string;
      reasons: string;
      created_at: string;
    }>;
    const header = [
      "id",
      "ip_address",
      "event_type",
      "rule_score",
      "anomaly_score",
      "final_score",
      "severity",
      "reasons",
      "created_at",
    ];
    const rows = data.map((e) => [
      String(e.id),
      e.ip_address,
      e.event_type,
      String(e.rule_score),
      String(e.anomaly_score),
      String(e.final_score),
      e.severity,
      e.reasons,
      e.created_at,
    ]);
    downloadCsv(`sentinelstack-events-${Date.now()}.csv`, header, rows);
  }

  return (
    <div className="data-export-bar">
      <span className="data-export-label">Export CSV</span>
      <button type="button" className="btn btn-table-block" onClick={() => void exportAlerts()}>
        Alerts
      </button>
      <button type="button" className="btn btn-table-block" onClick={() => void exportEvents()}>
        Threat events
      </button>
    </div>
  );
}
