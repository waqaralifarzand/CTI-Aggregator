from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict


class DashboardSummary(BaseModel):
    total_indicators: int
    by_severity: Dict[str, int]
    by_source: Dict[str, int]
    by_type: Dict[str, int]


class TimelinePoint(BaseModel):
    date: str
    count: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardTimeline(BaseModel):
    data: List[TimelinePoint]


class TopIoC(BaseModel):
    ioc_value: str
    ioc_type: str
    num_sources: int
    severity: str
    malware_family: Optional[str] = None


class FeedHealth(BaseModel):
    feed: str
    last_success: Optional[datetime] = None
    avg_fetch_time_ms: Optional[float] = None
    error_rate: float = 0.0
    total_runs: int = 0


class RecentActivity(BaseModel):
    timestamp: datetime
    event: str
    feed: Optional[str] = None
    details: Optional[str] = None
