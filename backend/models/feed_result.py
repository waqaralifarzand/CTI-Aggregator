from sqlalchemy import Column, Integer, Text, Boolean, TIMESTAMP, ForeignKey
from sqlalchemy.sql import func
from ..database import Base


class FeedResult(Base):
    __tablename__ = "feed_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    feed_name = Column(Text, nullable=False)
    found = Column(Boolean, nullable=False, default=False)
    threat_tags = Column(Text, nullable=True)
    raw_data = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, server_default=func.now())
