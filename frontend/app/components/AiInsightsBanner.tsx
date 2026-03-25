"use client";

import { useEffect, useState } from "react";

type AiStatus = {
  openai_configured: boolean;
  openai_model: string;
  triage_enabled: boolean;
  anomaly_llm_enabled: boolean;
  isolation_forest_enabled: boolean;
  note: string;
};

export default function AiInsightsBanner() {
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/logging/ai/status", { cache: "no-store" });
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const data = (await res.json()) as AiStatus;
        if (!cancelled) {
          setStatus(data);
        }
      } catch (e) {
        if (!cancelled) {
          setErr(e instanceof Error ? e.message : "unavailable");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (err) {
    return (
      <section className="ai-insights-banner ai-insights-muted" aria-live="polite">
        <strong>AI stack</strong>
        <span className="ai-insights-detail">Status unavailable ({err}).</span>
      </section>
    );
  }

  if (!status) {
    return (
      <section className="ai-insights-banner ai-insights-muted" aria-busy="true">
        <strong>AI stack</strong>
        <span className="ai-insights-detail">Loading…</span>
      </section>
    );
  }

  const chips = [
    { label: "OpenAI", ok: status.openai_configured },
    { label: "Triage", ok: status.triage_enabled },
    { label: "Anomaly LLM", ok: status.anomaly_llm_enabled },
    { label: "Isolation Forest", ok: status.isolation_forest_enabled },
  ];

  return (
    <section className="ai-insights-banner" aria-label="AI detection stack status">
      <div className="ai-insights-row">
        <strong>AI-assisted detection</strong>
        <span className="ai-insights-model">Model: {status.openai_model}</span>
      </div>
      <div className="ai-insights-chips">
        {chips.map((c) => (
          <span key={c.label} className={`ai-chip ${c.ok ? "ai-chip-on" : "ai-chip-off"}`}>
            {c.label}: {c.ok ? "on" : "off"}
          </span>
        ))}
      </div>
      <p className="ai-insights-note">{status.note}</p>
    </section>
  );
}
