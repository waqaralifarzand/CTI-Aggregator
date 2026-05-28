from datetime import datetime
from sqlalchemy import Column, Integer, Text, DateTime
from database import Base


class IoC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(Text, nullable=False, unique=True)
    type = Column(Text, nullable=False)  # 'ip'|'domain'|'hash_md5'|'hash_sha256'|'hash_sha1'
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    scan_count = Column(Integer, default=1)
