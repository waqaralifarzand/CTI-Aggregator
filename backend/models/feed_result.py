from datetime import datetime
from sqlalchemy import Column, Integer, Text, DateTime, Boolean, ForeignKey
from database import Base


class FeedResult(Base):
    __tablename__ = "feed_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_result_id = Column(
        Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False
    )
    feed_name = Column(Text, nullable=False)
    found = Column(Boolean, default=False)
    threat_tags = Column(Text, nullable=True)
    raw_data = Column(Text, nullable=False)  # JSON
    created_at = Column(DateTime, default=datetime.utcnow)
