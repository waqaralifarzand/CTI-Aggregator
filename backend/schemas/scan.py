from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, field_validator


class ScanRequest(BaseModel):
    value: str

    @field_validator("value")
    @classmethod
    def value_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("value must not be empty")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    ioc: Dict[str, Any]
    overall_severity: str
    threat_score: int
    ml_severity: Optional[str] = None
    ml_confidence: Optional[float] = None
    scanned_at: datetime
    feeds: Dict[str, Any]
    blacklist_status: Dict[str, Any]
    recommendations: List[str]


class ScanSummary(BaseModel):
    scan_id: str
    ioc_value: str
    ioc_type: str
    overall_severity: str
    threat_score: int
    scanned_at: datetime
