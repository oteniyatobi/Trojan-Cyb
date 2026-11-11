"""SQLAlchemy models for the TROJAN database.

One class per table. The tables are created by backend/db/schema.sql;
these models exist so the API and the scan worker can read and write
rows in Python rather than raw SQL.
"""

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text, func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True)
    name = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    wazuh_id = Column(String, unique=True, nullable=False)
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    event_time = Column(DateTime(timezone=True))
    rule_id = Column(String)
    rule_level = Column(Integer)
    rule_groups = Column(JSONB)
    signature_id = Column(String, index=True)
    signature_name = Column(Text)
    suricata_sev = Column(Integer)
    fired_times = Column(Integer, default=1)
    description = Column(Text)
    src_ip = Column(String)
    dest_ip = Column(String)
    dest_port = Column(Integer)
    proto = Column(String)
    agent_id = Column(String)
    agent_name = Column(String)
    manager_name = Column(String)
    decoder_name = Column(String)
    location = Column(String)
    raw = Column(JSONB)
    status = Column(String, default="new")
    review_status = Column(String, default="pending")

    review = relationship("Review", back_populates="alert", uselist=False)


class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    attack_type = Column(String)
    severity = Column(String)
    headline = Column(Text)
    what_happened = Column(Text)
    why_it_matters = Column(Text)
    steps = Column(JSONB)
    when_to_escalate = Column(Text)
    model = Column(String)
    attempts = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", back_populates="review")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    target = Column(Text, nullable=False)
    tools = Column(JSONB)
    requested_by = Column(String)
    approved = Column(Boolean, default=False)
    status = Column(String, default="pending")
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    error = Column(Text)

    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tool = Column(String, nullable=False)
    target = Column(Text)
    finding_type = Column(String)
    severity = Column(String)
    title = Column(Text)
    description = Column(Text)
    cve_id = Column(String)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="new")

    scan = relationship("Scan", back_populates="findings")


class Setting(Base):
    __tablename__ = "settings"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), primary_key=True)
    key = Column(String, primary_key=True)
    value = Column(Text, nullable=False)
    is_secret = Column(Boolean, default=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    who = Column(String)
    action = Column(String)
    object = Column(String)
    at = Column(DateTime(timezone=True), server_default=func.now())
