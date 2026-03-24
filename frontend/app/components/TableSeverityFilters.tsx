"use client";

import { useRouter, useSearchParams } from "next/navigation";

const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export default function TableSeverityFilters() {
  const router = useRouter();
  const searchParams = useSearchParams();

  function patchQuery(key: "alertSeverity" | "eventSeverity", value: string) {
    const params = new URLSearchParams(searchParams.toString());
    const trimmed = value.trim();
    if (!trimmed) {
      params.delete(key);
    } else {
      params.set(key, trimmed);
    }
    const qs = params.toString();
    router.replace(qs ? `/?${qs}` : "/", { scroll: false });
  }

  const alertSeverity = searchParams.get("alertSeverity") ?? "";
  const eventSeverity = searchParams.get("eventSeverity") ?? "";

  return (
    <section className="card table-filters-card">
      <div className="card-header">
        <h2>Table filters</h2>
      </div>
      <p className="ops-subtitle">Narrow Recent Alerts and Threat Events by severity. URLs update so refresh keeps your filters.</p>
      <div className="table-filters-row">
        <label className="table-filter-field">
          <span className="table-filter-label">Alerts</span>
          <select
            className="table-filter-select"
            value={alertSeverity}
            onChange={(e) => patchQuery("alertSeverity", e.target.value)}
            aria-label="Filter alerts by severity"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="table-filter-field">
          <span className="table-filter-label">Threat events</span>
          <select
            className="table-filter-select"
            value={eventSeverity}
            onChange={(e) => patchQuery("eventSeverity", e.target.value)}
            aria-label="Filter threat events by severity"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </div>
    </section>
  );
}
