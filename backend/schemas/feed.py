from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class FeedStatusResponse(BaseModel):
    id: int
    feed_name: str
    status: str
    last_synced: Optional[datetime] = None
    record_count: int
    error_message: Optional[str] = None
    updated_at: datetime

    model_config = {"from_attributes": True}


class FeedRefreshResponse(BaseModel):
    feed_name: str
    status: str
    message: str
    last_synced: Optional[datetime] = None
    record_count: int
    error_message: Optional[str] = None
