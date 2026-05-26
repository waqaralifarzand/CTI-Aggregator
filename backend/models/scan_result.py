from sqlalchemy import Column, Integer, Text, TIMESTAMP, REAL, ForeignKey
from sqlalchemy.sql import func
from ..database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Text, nullable=False, unique=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    overall_severity = Column(Text, nullable=False)
    ml_severity = Column(Text, nullable=True)
    ml_confidence = Column(REAL, nullable=True)
    threat_score = Column(Integer, nullable=False, default=0)
    scanned_at = Column(TIMESTAMP, nullable=False, server_default=func.now())
    raw_summary = Column(Text, nullable=False)
