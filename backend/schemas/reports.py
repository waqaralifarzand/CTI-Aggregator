from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class ReportRow(BaseModel):
    scan_id: str
    ioc_value: str
    ioc_type: str
    overall_severity: str
    threat_score: int
    ml_severity: Optional[str] = None
    ml_confidence: Optional[float] = None
    scanned_at: datetime

    model_config = {"from_attributes": True}


class ReportFilter(BaseModel):
    page: int = 1
    limit: int = 20
    severity: Optional[str] = None
    ioc_type: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    search: Optional[str] = None


class ReportResponse(BaseModel):
    total: int
    page: int
    limit: int
    results: List[ReportRow]
