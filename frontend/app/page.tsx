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

export default async function HomePage() {
  const [logs, alerts] = await Promise.all([getLogs(), getAlerts()]);
  return (
    <main>
      <h1>SentinelStack Dashboard</h1>
      <p>Milestone 2: request visibility plus rule-based threat alerts.</p>

      <section className="card">
        <h2>Recent Alerts ({alerts.length})</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Severity</th>
              <th>Message</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>{new Date(alert.created_at).toLocaleString()}</td>
                <td>
                  <span className={`severity severity-${alert.severity.toLowerCase()}`}>
                    {alert.severity}
                  </span>
                </td>
                <td>{alert.message}</td>
                <td>{alert.acknowledged ? "acknowledged" : "open"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Recent Request Logs ({logs.length})</h2>
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
            {logs.map((log) => (
              <tr key={log.id}>
                <td>{new Date(log.timestamp).toLocaleString()}</td>
                <td>{log.ip_address}</td>
                <td>{log.method}</td>
                <td>{log.path}</td>
                <td>{log.status_code}</td>
                <td>{log.response_time_ms ?? "n/a"}</td>
                <td>{log.user_agent || "n/a"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}
