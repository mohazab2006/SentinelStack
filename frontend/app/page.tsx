import OperationsPanel from "./components/OperationsPanel";

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

const numberFormatter = new Intl.NumberFormat();

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function formatNumber(value: number) {
  return numberFormatter.format(value);
}

const apiBase =
  process.env.LOGGING_API_BASE_URL || "http://logging-service:8000";

async function getLogs(): Promise<RequestLog[]> {
  const response = await fetch(`${apiBase}/logs?limit=50`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load request logs");
  }
  return response.json();
}

async function getAlerts(): Promise<Alert[]> {
  const response = await fetch(`${apiBase}/alerts?limit=20`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load alerts");
  }
  return response.json();
}

async function getEvents(): Promise<ThreatEvent[]> {
  const response = await fetch(`${apiBase}/events?limit=20`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("Failed to load threat events");
  }
  return response.json();
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

function getErrorMessage(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }
  return "Unknown error";
}

export default async function HomePage() {
  const [logsResult, alertsResult, eventsResult, blockedIpsResult, overviewResult, severityResult] =
    await Promise.allSettled([
    getLogs(),
    getAlerts(),
    getEvents(),
    getBlockedIps(),
    getOverviewMetrics(),
    getSeverityMetrics()
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

  const eventById = new Map(events.map((event) => [event.id, event]));

  const blockedIps = blockedIpsResult.status === "fulfilled" ? blockedIpsResult.value : [];
  if (blockedIpsResult.status === "rejected") {
    loadErrors.push(`Blocked IPs unavailable: ${getErrorMessage(blockedIpsResult.reason)}`);
  }

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
        <p>Milestone 3: detection with alerts and automated response actions.</p>
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

      <OperationsPanel alerts={alerts} blockedIps={blockedIps} />

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
                <th>Severity</th>
                <th>Score</th>
                <th>Message</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty-cell">
                    No alerts yet.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  (() => {
                    const event = eventById.get(alert.threat_event_id);
                    return (
                  <tr key={alert.id}>
                    <td>{formatDateTime(alert.created_at)}</td>
                    <td>
                      <span className={`severity severity-${alert.severity.toLowerCase()}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="mono">{event ? event.final_score : "n/a"}</td>
                    <td>{alert.message}</td>
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
                <th>Anomaly</th>
                <th>Final</th>
                <th>Why</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty-cell">
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
                    <td className="mono">{event.final_score}</td>
                    <td>{event.reasons}</td>
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
