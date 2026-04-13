from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.sql import func

from backend.database import Base


class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=False, index=True)
    model_version = Column(String(32), nullable=False)
    predicted_severity = Column(String(16), nullable=False)
    confidence = Column(Float, nullable=False)
    feature_vector_json = Column(Text, nullable=True)
    predicted_at = Column(DateTime, server_default=func.now())
