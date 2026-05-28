from typing import List, Optional
from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_scans: int
    threats_found: int
    critical_alerts: int
    clean_scans: int


class ActivityPoint(BaseModel):
    date: str
    scans: int
    threats: int


class TickerItem(BaseModel):
    ioc_value: str
    ioc_type: str
    severity: str
    tags: List[str]
    scanned_at: str


class SeverityCount(BaseModel):
    severity: str
    count: int


class IocTypeCount(BaseModel):
    ioc_type: str
    count: int
