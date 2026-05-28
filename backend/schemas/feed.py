from pydantic import BaseModel
from typing import Optional


class FeedStatusResponse(BaseModel):
    feed_name: str
    display_name: str
    status: str
    last_synced: Optional[str] = None
    record_count: int = 0
    error_message: Optional[str] = None


class FeedRefreshResponse(BaseModel):
    feed_name: str
    status: str
    message: str
