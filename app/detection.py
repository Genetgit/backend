from datetime import datetime, timedelta
from typing import List
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import EventModel, AlertModel

SEVERITY_WEIGHTS = {"low": 20, "medium": 50, "high": 75, "critical": 100}
CONFIDENCE_LEVELS = {"R001_ssh_bruteforce": 0.8, "R002_success_after_failures": 0.95}

def calculate_risk_score(severity: str, rule_id: str) -> int:
    weight = SEVERITY_WEIGHTS.get(severity, 50)
    confidence = CONFIDENCE_LEVELS.get(rule_id, 0.5)
    return int(weight * confidence)

async def check_deduplication(db: AsyncSession, rule_id: str, src_ip: str, current_time: datetime) -> bool:
    five_minutes_ago = current_time - timedelta(minutes=5)
    stmt = select(AlertModel).where(
        AlertModel.rule_id == rule_id,
        AlertModel.src_ip == src_ip,
        AlertModel.first_seen >= five_minutes_ago
    )
    result = await db.execute(stmt)
    return result.scalars().first() is not None

async def run_detection_engine(db: AsyncSession, new_events: List[EventModel]):
    for event in new_events:
        if event.event_type == "ssh_login_failed":
            one_minute_ago = event.timestamp - timedelta(seconds=60)
            stmt = select(EventModel).where(
                EventModel.src_ip == event.src_ip,
                EventModel.event_type == "ssh_login_failed",
                EventModel.timestamp >= one_minute_ago,
                EventModel.timestamp <= event.timestamp
            )
            res = await db.execute(stmt)
            failures = res.scalars().all()

            if len(failures) >= 5:
                if not await check_deduplication(db, "R001_ssh_bruteforce", event.src_ip, event.timestamp):
                    alert_id = str(uuid.uuid4())
                    new_alert = AlertModel(
                        alert_id=alert_id,
                        rule_id="R001_ssh_bruteforce",
                        title="SSH Brute Force Attempt Detected",
                        severity="high",
                        risk_score=calculate_risk_score("high", "R001_ssh_bruteforce"),
                        host_id=event.host_id,
                        src_ip=event.src_ip,
                        mitre_technique="T1110",
                        first_seen=min([f.timestamp for f in failures]),
                        last_seen=max([f.timestamp for f in failures]),
                        status="open"
                    )
                    new_alert.events.extend(failures)
                    db.add(new_alert)

        if event.event_type == "ssh_login_success":
            window_start = event.timestamp - timedelta(minutes=10)
            stmt = select(EventModel).where(
                EventModel.src_ip == event.src_ip,
                EventModel.event_type == "ssh_login_failed",
                EventModel.timestamp >= window_start,
                EventModel.timestamp <= event.timestamp
            )
            res = await db.execute(stmt)
            recent_failures = res.scalars().all()

            if len(recent_failures) >= 5:
                if not await check_deduplication(db, "R002_success_after_failures", event.src_ip, event.timestamp):
                    alert_id = str(uuid.uuid4())
                    all_related_events = recent_failures + [event]
                    new_alert = AlertModel(
                        alert_id=alert_id,
                        rule_id="R002_success_after_failures",
                        title="SSH Login Success After Multiple Failures",
                        severity="critical",
                        risk_score=calculate_risk_score("critical", "R002_success_after_failures"),
                        host_id=event.host_id,
                        src_ip=event.src_ip,
                        mitre_technique="T1110",
                        first_seen=min([e.timestamp for e in all_related_events]),
                        last_seen=max([e.timestamp for e in all_related_events]),
                        status="open"
                    )
                    new_alert.events.extend(all_related_events)
                    db.add(new_alert)
    await db.commit()
