from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    ip_address: str
    method: str
    path: str
    status_code: int
    user_agent: Optional[str] = None
    response_time_ms: Optional[int] = None
    timestamp: Optional[datetime] = None


class RequestLog(BaseModel):
    id: int
    ip_address: str
    method: str
    path: str
    status_code: int
    user_agent: Optional[str]
    response_time_ms: Optional[int]
    timestamp: datetime


class ThreatEvent(BaseModel):
    id: int
    ip_address: str
    event_type: str
    rule_score: int
    anomaly_score: int
    final_score: int
    severity: str
    reasons: str
    created_at: datetime


class Alert(BaseModel):
    id: int
    threat_event_id: int
    severity: str
    message: str
    created_at: datetime
    acknowledged: bool


class BlockedIp(BaseModel):
    id: int
    ip_address: str
    reason: str
    blocked_at: datetime
    expires_at: Optional[datetime]
    active: bool


class BlockIpRequest(BaseModel):
    ip_address: str
    reason: str = "manual block"
    duration_minutes: Optional[int] = Field(default=60, ge=1, le=10080)


class PortguardNewPortItem(BaseModel):
    port: int
    service: Optional[str] = None
    risk_level: str


class PortguardIngestRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    scan_id: int = Field(..., ge=1)
    new_ports: List[PortguardNewPortItem] = Field(..., min_length=1)


class SummaryNamedCount(BaseModel):
    name: str
    count: int


class ActivitySummary(BaseModel):
    window: str
    requests_in_window: int
    events_in_window: int
    alerts_created_in_window: int
    open_alerts: int
    active_blocks: int
    alerts_by_severity: dict[str, int]
    top_event_ips: List[SummaryNamedCount]
    top_event_types: List[SummaryNamedCount]
    alerts_severity_sum: int = Field(
        description="Sum of alerts_by_severity; should match alerts_created_in_window",
    )
    alerts_count_consistent: bool = Field(
        description="True when severity buckets sum to new alerts in window",
    )
    top_event_ip_rows_sum: int = Field(
        description="Sum of counts in top_event_ips (each ≤ events_in_window)",
    )
    top_ips_counts_valid: bool = Field(
        description="True when top_event_ip_rows_sum ≤ events_in_window",
    )
