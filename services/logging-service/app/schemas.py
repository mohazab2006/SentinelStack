from datetime import datetime
from typing import Optional

from pydantic import BaseModel


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
