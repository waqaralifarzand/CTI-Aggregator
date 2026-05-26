from sqlalchemy import Column, Integer, Text, TIMESTAMP
from sqlalchemy.sql import func
from ..database import Base


class IoC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(Text, nullable=False, unique=True)
    type = Column(Text, nullable=False)
    first_seen = Column(TIMESTAMP, nullable=False, server_default=func.now())
    last_seen = Column(TIMESTAMP, nullable=False, server_default=func.now())
    scan_count = Column(Integer, nullable=False, default=1)
