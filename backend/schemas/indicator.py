from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List


class IndicatorBase(BaseModel):
    ioc_value: str
    ioc_type: str
    source_feed: str
    source_reference: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    severity: str = "medium"
    confidence: float = 50.0
    tags: Optional[List[str]] = None
    malware_family: Optional[str] = None
    tlp: str = "white"


class IndicatorCreate(IndicatorBase):
    raw_data: Optional[str] = None
    feed_run_id: Optional[int] = None


class IndicatorRead(IndicatorBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class IndicatorDetail(IndicatorRead):
    raw_data: Optional[str] = None
    feed_run_id: Optional[int] = None


class IndicatorList(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[IndicatorRead]


class IndicatorSearch(BaseModel):
    value: str
    results: List[IndicatorRead]
