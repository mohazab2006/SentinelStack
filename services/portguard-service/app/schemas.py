from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: Optional[str] = Field(
        default=None,
        description="Hostname or IP to scan (must be in PORTGUARD_ALLOWED_TARGETS)",
    )


class PortResult(BaseModel):
    id: int
    scan_id: int
    port: int
    protocol: str
    state: str
    service: Optional[str]
    risk_level: str


class OpenPortSummary(BaseModel):
    port: int
    service: Optional[str] = None
    risk_level: str


class PortScanSummary(BaseModel):
    id: int
    target: str
    scanned_at: datetime
    open_count: int
    high_risk_count: int
    open_ports: List[OpenPortSummary] = Field(default_factory=list)


class PortScanDetail(BaseModel):
    id: int
    target: str
    scanned_at: datetime
    results: List[PortResult]
    new_open_ports: List[int] = Field(default_factory=list)
