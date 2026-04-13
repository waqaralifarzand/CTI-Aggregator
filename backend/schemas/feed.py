from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class FeedFetchRequest(BaseModel):
    feed: str = "all"  # "all", "urlhaus", "malwarebazaar", "alienvault_otx", "misp"


class FeedFetchResponse(BaseModel):
    status: str
    feed_run_ids: List[int]
    message: str


class FeedStatus(BaseModel):
    feed: str
    last_run: Optional[datetime] = None
    records_fetched: int = 0
    status: str = "never_run"
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None


class FeedStatusList(BaseModel):
    feeds: List[FeedStatus]


class FeedRunRead(BaseModel):
    id: int
    feed_name: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    records_fetched: int
    records_normalized: int
    records_stored: int
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None

    model_config = {"from_attributes": True}
