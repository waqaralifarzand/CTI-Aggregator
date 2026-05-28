from sqlalchemy import Column, Integer, Text, TIMESTAMP
from sqlalchemy.sql import func
from ..database import Base


class FeedStatus(Base):
    __tablename__ = "feed_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_name = Column(Text, nullable=False, unique=True)
    status = Column(Text, nullable=False, default="unknown")
    last_synced = Column(TIMESTAMP, nullable=True)
    record_count = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    updated_at = Column(TIMESTAMP, nullable=False, server_default=func.now())
