from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.sql import func

from backend.database import Base


class AnomalyFlag(Base):
    __tablename__ = "anomaly_flags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=False, index=True)
    flag_type = Column(String(64), nullable=False, index=True)
    description = Column(Text, nullable=True)
    anomaly_score = Column(Float, default=0.0)
    detected_at = Column(DateTime, server_default=func.now())
    metadata_json = Column(Text, nullable=True)
