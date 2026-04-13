from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, Index
from sqlalchemy.sql import func

from backend.database import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_value = Column(String(2048), nullable=False, index=True)
    ioc_type = Column(String(32), nullable=False, index=True)
    source_feed = Column(String(64), nullable=False, index=True)
    source_reference = Column(String(2048), nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    severity = Column(String(16), nullable=False, default="medium", index=True)
    confidence = Column(Float, nullable=False, default=50.0)
    tags = Column(Text, nullable=True)  # JSON-serialized list
    malware_family = Column(String(256), nullable=True, index=True)
    tlp = Column(String(16), nullable=False, default="white")
    raw_data = Column(Text, nullable=True)
    feed_run_id = Column(Integer, ForeignKey("feed_runs.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    __table_args__ = (
        Index("ix_ioc_value_source", "ioc_value", "source_feed"),
        Index("ix_severity_type", "severity", "ioc_type"),
    )
