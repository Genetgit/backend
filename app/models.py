from sqlalchemy import String, DateTime, Text, JSON, Integer, ForeignKey, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base
from datetime import datetime
from typing import List, Optional

alert_event_association = Table(
    "alert_event_association",
    Base.metadata,
    Column("alert_id", String, ForeignKey("alerts.alert_id"), primary_key=True),
    Column("event_id", String, ForeignKey("events.event_id"), primary_key=True)
)

class EventModel(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    host_id: Mapped[str] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(String)
    event_type: Mapped[str] = mapped_column(String, index=True)
    src_ip: Mapped[str] = mapped_column(String, index=True)
    username: Mapped[str] = mapped_column(String)
    raw: Mapped[str] = mapped_column(Text)

class AlertModel(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    risk_score: Mapped[int] = mapped_column(Integer)
    host_id: Mapped[str] = mapped_column(String)
    src_ip: Mapped[str] = mapped_column(String, index=True)
    mitre_technique: Mapped[str] = mapped_column(String)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String, default="open")
    ai_analysis: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    events: Mapped[List[EventModel]] = relationship(
        "EventModel",
        secondary=alert_event_association,
        lazy="selectin"
    )

class VerificationModel(Base):
    __tablename__ = "verifications"
    verification_id: Mapped[str] = mapped_column(String, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String, index=True)
    baseline: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    retest: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    result: Mapped[str] = mapped_column(String, default="running")
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
