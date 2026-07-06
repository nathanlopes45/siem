import uuid
from sqlalchemy import Column, String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class Host(Base):
    __tablename__ = "hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    os_type = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    log_source = Column(String, nullable=False)
    raw_log = Column(Text, nullable=False)
    attacker_ip = Column(String, nullable=True)
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    host = relationship("Host")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"))
    alert_type = Column(String, nullable=False)
    description = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)