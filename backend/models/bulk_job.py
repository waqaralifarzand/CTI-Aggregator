from datetime import datetime
from sqlalchemy import Column, Integer, Text, DateTime
from database import Base


class BulkJob(Base):
    __tablename__ = "bulk_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(Text, nullable=False, unique=True)
    total = Column(Integer, default=0)
    completed = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    status = Column(Text, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
