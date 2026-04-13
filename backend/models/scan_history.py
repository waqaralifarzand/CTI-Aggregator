from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func

from backend.database import Base


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(64), nullable=False)
    feed_name = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    performed_at = Column(DateTime, server_default=func.now())
    user_triggered = Column(Integer, default=1)
