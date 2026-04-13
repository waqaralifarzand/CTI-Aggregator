from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func

from backend.database import Base


class FeedRun(Base):
    __tablename__ = "feed_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_name = Column(String(64), nullable=False, index=True)
    started_at = Column(DateTime, nullable=False, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(16), nullable=False, default="running")
    records_fetched = Column(Integer, default=0)
    records_normalized = Column(Integer, default=0)
    records_stored = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)
