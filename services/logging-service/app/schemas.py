from datetime import datetime
from typing import Optional

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
