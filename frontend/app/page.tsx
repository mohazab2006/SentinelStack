import { Suspense } from "react";
import OperationsPanel from "./components/OperationsPanel";
import PortGuardSection from "./components/PortGuardSection";
import DashboardRefreshBar from "./components/DashboardRefreshBar";
import SummaryPanel from "./components/SummaryPanel";
import TableSeverityFilters from "./components/TableSeverityFilters";
import DataExportButtons from "./components/DataExportButtons";
import IpBlockButton from "./components/IpBlockButton";

type RequestLog = {
  id: number;
  ip_address: string;
  method: string;
  path: string;
  status_code: number;
  user_agent: string | null;
  response_time_ms: number | null;
  timestamp: string;
};

type Alert = {
  id: number;
  threat_event_id: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  created_at: string;
  acknowledged: boolean;
  source_ip: string;
  ai_advisory_score?: number | null;
  ai_recommendations?: string | null;
  anomaly_score_norm?: number | null;
  triggered_rules?: unknown[] | null;
  contributing_features?: unknown[] | null;
  severity_reason?: string | null;
  flagged?: boolean | null;
};

type ThreatEvent = {
  id: number;
  ip_address: string;
  event_type: string;
  rule_score: number;
  anomaly_score: number;
  final_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reasons: string;
  created_at: string;
  ai_advisory_score?: number | null;
  ai_recommendations?: string | null;
  source_key?: string | null;
  anomaly_score_norm?: number | null;
  features?: Record<string, unknown> | null;
  triggered_rules?: unknown[] | null;
  contributing_features?: unknown[] | null;
  severity_reason?: string | null;
  flagged?: boolean | null;
};

type BlockedIp = {
  id: number;
  ip_address: string;
  reason: string;
  blocked_at: string;
  expires_at: string | null;
  active: boolean;
};

type OverviewMetrics = {
  total_requests: number;
  total_events: number;
  open_alerts: number;
  active_blocks: number;
};

type SeverityMetrics = {
  LOW: number;
  MEDIUM: number;
  HIGH: number;
  CRITICAL: number;
};

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

const numberFormatter = new Intl.NumberFormat();

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function formatNumber(value: number) {
  return numberFormatter.format(value);
}

function formatAnomalyNorm(value: number | null | undefined) {
  if (value == null || Number.isNaN(value)) {
    return "—";
  }
  return value.toFixed(3);
}

function formatFlagged(value: boolean | null | undefined) {
  if (value == null) {
    return "—";
  }
  return value ? "yes" : "no";
}

const apiBase =
  process.env.LOGGING_API_BASE_URL || "http://logging-service:8000";

const portguardApiBase =
  process.env.PORTGUARD_API_BASE_URL || "http://portguard-service:8000";

function parseAllowedTargets(): string[] {
  const raw = process.env.PORTGUARD_ALLOWED_TARGETS || "demo-app,nginx,postgres,logging-service";
  return raw
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
}

function defaultPortguardTarget(): string {
  return (process.env.PORTGUARD_DEFAULT_TARGET || "demo-app").trim().toLowerCase();
}

async function getLogs(): Promise<RequestLog[]> {
  const response = await fetch(`${apiBase}/logs?limit=50`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load request logs");
  }
  return response.json();
}

async function getAlerts(limit: number, severity?: string): Promise<Alert[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (severity) {
    params.set("severity", severity);
  }
  const response = await fetch(`${apiBase}/alerts?${params}`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load alerts");
  }
  return response.json();
}

async function getEvents(limit: number, severity?: string): Promise<ThreatEvent[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (severity) {
    params.set("severity", severity);
  }
  const response = await fetch(`${apiBase}/events?${params}`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load threat events");
  }
  return response.json();
}

function severityFromSearchParam(raw: string | undefined): string | undefined {
  if (!raw) {
    return undefined;
  }
  const u = raw.trim().toUpperCase();
  if (u === "LOW" || u === "MEDIUM" || u === "HIGH" || u === "CRITICAL") {
    return u;
  }
  return undefined;
}

async function getBlockedIps(): Promise<BlockedIp[]> {
  const response = await fetch(`${apiBase}/blocked-ips?limit=20`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load blocked IPs");
  }
  return response.json();
}

async function getOverviewMetrics(): Promise<OverviewMetrics> {
  const response = await fetch(`${apiBase}/metrics/overview`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load overview metrics");
  }
  return response.json();
}

async function getSeverityMetrics(): Promise<SeverityMetrics> {
  const response = await fetch(`${apiBase}/metrics/severity`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load severity metrics");
  }
  return response.json();
}

async function getPortScans(): Promise<PortScanSummary[]> {
  const response = await fetch(`${portguardApiBase}/scans?limit=15`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load port scans");
  }
  return response.json();
}

async function getPortguardSchedule(): Promise<PortguardScheduleStatus> {
  const response = await fetch(`${portguardApiBase}/schedule`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load Port Guard schedule");
  }
  return response.json();
}

function getErrorMessage(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }
  return "Unknown error";
}

type HomePageProps = {
  searchParams: { alertSeverity?: string; eventSeverity?: string };
};

export default async function HomePage({ searchParams }: HomePageProps) {
  const alertSeverity = severityFromSearchParam(searchParams.alertSeverity);
  const eventSeverity = severityFromSearchParam(searchParams.eventSeverity);

  const [
    logsResult,
    alertsResult,
    eventsResult,
    eventsLookupResult,
    blockedIpsResult,
    overviewResult,
    severityResult,
    portScansResult,
    portguardScheduleResult
  ] = await Promise.allSettled([
    getLogs(),
    getAlerts(50, alertSeverity),
    getEvents(50, eventSeverity),
    getEvents(200),
    getBlockedIps(),
    getOverviewMetrics(),
    getSeverityMetrics(),
    getPortScans(),
    getPortguardSchedule()
  ]);

  const loadErrors: string[] = [];

  const logs = logsResult.status === "fulfilled" ? logsResult.value : [];
  if (logsResult.status === "rejected") {
    loadErrors.push(`Logs unavailable: ${getErrorMessage(logsResult.reason)}`);
  }

  const alerts = alertsResult.status === "fulfilled" ? alertsResult.value : [];
  if (alertsResult.status === "rejected") {
    loadErrors.push(`Alerts unavailable: ${getErrorMessage(alertsResult.reason)}`);
  }

  const events = eventsResult.status === "fulfilled" ? eventsResult.value : [];
  if (eventsResult.status === "rejected") {
    loadErrors.push(`Threat events unavailable: ${getErrorMessage(eventsResult.reason)}`);
  }

  const eventsLookup = eventsLookupResult.status === "fulfilled" ? eventsLookupResult.value : [];
  if (eventsLookupResult.status === "rejected") {
    loadErrors.push(`Threat event lookup unavailable: ${getErrorMessage(eventsLookupResult.reason)}`);
  }

  const eventById = new Map(eventsLookup.map((event) => [event.id, event]));

  const blockedIps = blockedIpsResult.status === "fulfilled" ? blockedIpsResult.value : [];
  if (blockedIpsResult.status === "rejected") {
    loadErrors.push(`Blocked IPs unavailable: ${getErrorMessage(blockedIpsResult.reason)}`);
  }
  const activeBlockedIpList = blockedIps.map((b) => b.ip_address);

  const overview =
    overviewResult.status === "fulfilled"
      ? overviewResult.value
      : {
          total_requests: 0,
          total_events: 0,
          open_alerts: 0,
          active_blocks: 0
        };
  if (overviewResult.status === "rejected") {
    loadErrors.push(`Overview metrics unavailable: ${getErrorMessage(overviewResult.reason)}`);
  }

  const severity =
    severityResult.status === "fulfilled"
      ? severityResult.value
      : {
          LOW: 0,
          MEDIUM: 0,
          HIGH: 0,
          CRITICAL: 0
        };
  if (severityResult.status === "rejected") {
    loadErrors.push(`Severity metrics unavailable: ${getErrorMessage(severityResult.reason)}`);
  }

  const portScans = portScansResult.status === "fulfilled" ? portScansResult.value : [];
  if (portScansResult.status === "rejected") {
    loadErrors.push(`Port Guard unavailable: ${getErrorMessage(portScansResult.reason)}`);
  }
  const portguardSchedule =
    portguardScheduleResult.status === "fulfilled"
      ? portguardScheduleResult.value
      : { enabled: false, minutes: 60, targets: [], allowed_targets: [], last_background_run_at: null };
  if (portguardScheduleResult.status === "rejected") {
    loadErrors.push(`Port Guard schedule unavailable: ${getErrorMessage(portguardScheduleResult.reason)}`);
  }

  const allowedTargets = parseAllowedTargets();
  const portguardDefaultTarget = defaultPortguardTarget();

  const metrics = [
    { label: "Total Requests", value: overview.total_requests, tone: "neutral" },
    { label: "Threat Events", value: overview.total_events, tone: "warn" },
    { label: "Open Alerts", value: overview.open_alerts, tone: "danger" },
    { label: "Active Blocks", value: overview.active_blocks, tone: "danger" },
    { label: "Low", value: severity.LOW, tone: "low" },
    { label: "Medium", value: severity.MEDIUM, tone: "medium" },
    { label: "High", value: severity.HIGH, tone: "high" },
    { label: "Critical", value: severity.CRITICAL, tone: "critical" }
  ];

  return (
    <main className="dashboard-page">
      <header className="dashboard-header">
        <h1>SentinelStack Dashboard</h1>
        <DashboardRefreshBar />
      </header>
      {loadErrors.length > 0 ? (
        <section className="card load-warning" aria-live="polite">
          <h2>Partial Data</h2>
          <p>Some services are still starting or temporarily unavailable.</p>
          <ul>
            {loadErrors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="metrics-grid" aria-label="Overview metrics">
        {metrics.map((metric) => (
          <article key={metric.label} className={`metric-card metric-${metric.tone}`}>
            <span className="metric-label">{metric.label}</span>
            <strong className="metric-value">{formatNumber(metric.value)}</strong>
          </article>
        ))}
      </section>

      <SummaryPanel />

      <OperationsPanel alerts={alerts} blockedIps={blockedIps} />

      <PortGuardSection
        scans={portScans}
        allowedTargets={allowedTargets}
        defaultTarget={portguardDefaultTarget}
        schedule={portguardSchedule}
      />

      <Suspense fallback={null}>
        <TableSeverityFilters />
      </Suspense>

      <DataExportButtons alertSeverity={alertSeverity} eventSeverity={eventSeverity} />

      <section className="card">
        <div className="card-header">
          <h2>Recent Alerts</h2>
          <span className="count-badge">{formatNumber(alerts.length)}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Anomaly</th>
                <th>Flagged</th>
                <th>Why (fused)</th>
                <th>AI advisory</th>
                <th>Message</th>
                <th>AI actions</th>
                <th>Block</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={12} className="empty-cell">
                    No alerts yet.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  (() => {
                    const event = eventById.get(alert.threat_event_id);
                    const aiScore = alert.ai_advisory_score ?? event?.ai_advisory_score;
                    const aiRecs = alert.ai_recommendations ?? event?.ai_recommendations;
                    const aNorm = alert.anomaly_score_norm ?? event?.anomaly_score_norm;
                    const flagged = alert.flagged ?? event?.flagged;
                    const sevReason = alert.severity_reason ?? event?.severity_reason;
                    return (
                  <tr key={alert.id}>
                    <td>{formatDateTime(alert.created_at)}</td>
                    <td className="mono">{alert.source_ip}</td>
                    <td>
                      <span className={`severity severity-${alert.severity.toLowerCase()}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="mono">{event ? event.final_score : "n/a"}</td>
                    <td className="mono">{formatAnomalyNorm(aNorm)}</td>
                    <td className="mono">{formatFlagged(flagged)}</td>
                    <td className="why-cell">{sevReason ?? "—"}</td>
                    <td className="mono">
                      {aiScore != null ? aiScore : "—"}
                    </td>
                    <td>{alert.message}</td>
                    <td className="ai-recs-cell">{aiRecs ?? "—"}</td>
                    <td>
                      <IpBlockButton
                        ipAddress={alert.source_ip}
                        severity={alert.severity}
                        context="alert"
                        contextId={alert.id}
                        activeBlockedIps={activeBlockedIpList}
                      />
                    </td>
                    <td>
                      <span className={`status-chip ${alert.acknowledged ? "status-ok" : "status-open"}`}>
                        {alert.acknowledged ? "acknowledged" : "open"}
                      </span>
                    </td>
                  </tr>
                    );
                  })()
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Recent Threat Events</h2>
          <span className="count-badge">{formatNumber(events.length)}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>IP</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Rule</th>
                <th>Anomaly (0–100)</th>
                <th>A_norm</th>
                <th>Final</th>
                <th>Flagged</th>
                <th>AI adv.</th>
                <th>Signals</th>
                <th>Severity reason</th>
                <th>AI actions</th>
                <th>Block</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={14} className="empty-cell">
                    No threat events yet.
                  </td>
                </tr>
              ) : (
                events.map((event) => (
                  <tr key={event.id}>
                    <td>{formatDateTime(event.created_at)}</td>
                    <td className="mono">{event.ip_address}</td>
                    <td>{event.event_type}</td>
                    <td>
                      <span className={`severity severity-${event.severity.toLowerCase()}`}>
                        {event.severity}
                      </span>
                    </td>
                    <td className="mono">{event.rule_score}</td>
                    <td className="mono">{event.anomaly_score}</td>
                    <td className="mono">{formatAnomalyNorm(event.anomaly_score_norm)}</td>
                    <td className="mono">{event.final_score}</td>
                    <td className="mono">{formatFlagged(event.flagged)}</td>
                    <td className="mono">{event.ai_advisory_score ?? "—"}</td>
                    <td>{event.reasons}</td>
                    <td className="why-cell">{event.severity_reason ?? "—"}</td>
                    <td className="ai-recs-cell">{event.ai_recommendations ?? "—"}</td>
                    <td>
                      <IpBlockButton
                        ipAddress={event.ip_address}
                        severity={event.severity}
                        context="event"
                        contextId={event.id}
                        activeBlockedIps={activeBlockedIpList}
                      />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Blocked IPs</h2>
          <span className="count-badge">{formatNumber(blockedIps.length)}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Blocked At</th>
                <th>IP</th>
                <th>Reason</th>
                <th>Expires</th>
              </tr>
            </thead>
            <tbody>
              {blockedIps.length === 0 ? (
                <tr>
                  <td colSpan={4} className="empty-cell">
                    No blocked IP entries.
                  </td>
                </tr>
              ) : (
                blockedIps.map((entry) => (
                  <tr key={entry.id}>
                    <td>{formatDateTime(entry.blocked_at)}</td>
                    <td className="mono">{entry.ip_address}</td>
                    <td>{entry.reason}</td>
                    <td>{entry.expires_at ? formatDateTime(entry.expires_at) : "never"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Recent Request Logs</h2>
          <span className="count-badge">{formatNumber(logs.length)}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>IP</th>
                <th>Method</th>
                <th>Path</th>
                <th>Status</th>
                <th>Response (ms)</th>
                <th>User Agent</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="empty-cell">
                    No request logs yet.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id}>
                    <td>{formatDateTime(log.timestamp)}</td>
                    <td className="mono">{log.ip_address}</td>
                    <td>
                      <span className="method-chip">{log.method}</span>
                    </td>
                    <td className="mono">{log.path}</td>
                    <td className="mono">{log.status_code}</td>
                    <td>{log.response_time_ms ?? "n/a"}</td>
                    <td>{log.user_agent || "n/a"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
