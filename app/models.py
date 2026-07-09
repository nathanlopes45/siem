import uuid
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Index, Integer
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

    # Structured fields populated by app/parsers.py at ingest time
    event_type = Column(String, nullable=True)   # e.g. failed_password, accepted_password, invalid_user, unknown
    username = Column(String, nullable=True)
    attacker_ip = Column(String, nullable=True)  # kept name for backwards compat with existing detectors/API
    src_port = Column(Integer, nullable=True)

    received_at = Column(DateTime(timezone=True), server_default=func.now())
    host = relationship("Host")

    __table_args__ = (
        Index("ix_rawlog_host_received", "host_id", "received_at"),
        Index("ix_rawlog_attacker_ip", "attacker_ip"),
        # speeds up "failed_password logs for this host" — now an equality
        # lookup instead of the old leading-wildcard ilike scan
        Index("ix_rawlog_host_event_type", "host_id", "event_type"),
        # supports detect_cross_host_correlation, which groups by
        # attacker_ip across ALL hosts filtered by event_type + received_at
        Index("ix_rawlog_event_received_ip", "event_type", "received_at", "attacker_ip"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"))
    alert_type = Column(String, nullable=False)
    description = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_alert_host_description", "host_id", "description"),
    )