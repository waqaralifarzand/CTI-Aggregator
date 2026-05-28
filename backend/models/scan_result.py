from datetime import datetime
from sqlalchemy import Column, Integer, Text, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Text, nullable=False, unique=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    overall_severity = Column(Text, nullable=False)
    ml_severity = Column(Text, nullable=True)
    ml_confidence = Column(Float, nullable=True)
    threat_score = Column(Integer, default=0)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    raw_summary = Column(Text, nullable=False)  # JSON blob

    ioc = relationship("IoC", backref="scan_results")
    feed_results = relationship(
        "FeedResult",
        backref="scan_result",
        cascade="all, delete-orphan",
    )
