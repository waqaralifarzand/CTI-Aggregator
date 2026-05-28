from datetime import datetime
from sqlalchemy import Column, Integer, Text, DateTime
from database import Base


class FeedStatus(Base):
    __tablename__ = "feed_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_name = Column(Text, nullable=False, unique=True)
    status = Column(Text, default="unknown")
    last_synced = Column(DateTime, nullable=True)
    record_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
