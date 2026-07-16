import uuid
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Index, Integer, Boolean
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
    event_type = Column(String, nullable=True)   # e.g. failed_password, accepted_password, invalid_user, http_4xx, unknown
    username = Column(String, nullable=True)
    attacker_ip = Column(String, nullable=True)  # kept name for backwards compat with existing detectors/API
    src_port = Column(Integer, nullable=True)

    # Populated only for web access log sources (nginx/apache/web/access)
    http_status = Column(Integer, nullable=True)
    http_path = Column(String, nullable=True)
    http_method = Column(String, nullable=True)

    received_at = Column(DateTime(timezone=True), server_default=func.now())
    host = relationship("Host")

    __table_args__ = (
        Index("ix_rawlog_host_received", "host_id", "received_at"),
        Index("ix_rawlog_attacker_ip", "attacker_ip"),
        # speeds up "failed_password logs for this host", now an equality
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

    # Populated on demand via POST /alerts/{id}/triage, null until triaged
    triage_summary = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    recommended_action = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_alert_host_description", "host_id", "description"),
    )


class AgentInvestigation(Base):
    """
    Full audit trail for a single agent investigation run, every thought,
    tool call, and observation, not just the final answer. Separate from
    Alert (which only stores the latest severity/summary/recommended_action,
    same fields whether they came from simple triage or a full agent run)
    so the reasoning trace is preserved even if the alert is re-triaged.
    """
    __tablename__ = "agent_investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False)
    trace = Column(Text, nullable=False)          # JSON-encoded list of step dicts
    tools_used = Column(Text, nullable=True)       # JSON-encoded list of tool names
    final_summary = Column(Text, nullable=True)
    final_severity = Column(String, nullable=True)
    recommended_action = Column(Text, nullable=True)
    key_evidence = Column(Text, nullable=True)     # JSON-encoded list of strings
    iterations = Column(Integer, nullable=True)
    fell_back = Column(Boolean, nullable=True)       # see agent.py fallback logic
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_agent_investigation_alert", "alert_id"),
    )