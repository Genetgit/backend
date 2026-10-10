from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import List, Optional, Literal

class Event(BaseModel):
    event_id: str
    timestamp: datetime
    host_id: str
    source: str
    event_type: Literal["ssh_login_failed", "ssh_login_success", "process_start", "net_connection"]
    src_ip: str
    username: str
    raw: str

    @field_validator("timestamp")
    @classmethod
    def format_timestamp(cls, v: datetime) -> datetime:
        return v

    class Config:
        from_attributes = True

class AIAnalysis(BaseModel):
    summary: str
    impact: str
    recommended_defense_id: Literal["block_ip_iptables", "install_fail2ban"]

class Alert(BaseModel):
    alert_id: str
    rule_id: Literal["R001_ssh_bruteforce", "R002_success_after_failures"]
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    risk_score: int = Field(..., ge=0, le=100)
    host_id: str
    src_ip: str
    mitre_technique: str
    first_seen: datetime
    last_seen: datetime
    event_ids: List[str]
    status: Literal["open", "defended", "verified", "failed_verification"]
    ai_analysis: Optional[AIAnalysis] = None

    class Config:
        from_attributes = True

class EventIngestRequest(BaseModel):
    events: List[Event]

class EventIngestResponse(BaseModel):
    accepted: int

class AlertDetailResponse(Alert):
    events: List[Event]

class DefenseApplyRequest(BaseModel):
    alert_id: str
    defense_id: Literal["block_ip_iptables", "install_fail2ban"]

class DefenseApplyResponse(BaseModel):
    run_id: str
    status: str

class VerificationRequest(BaseModel):
    alert_id: str

class VerificationResponse(BaseModel):
    verification_id: str
    status: str

class VerificationBaselineRetest(BaseModel):
    attack_succeeded: bool
    detected: bool

class VerificationDetailResponse(BaseModel):
    verification_id: str
    alert_id: str
    baseline: Optional[VerificationBaselineRetest] = None
    retest: Optional[VerificationBaselineRetest] = None
    result: Literal["verified", "not_verified", "running"]
    evidence: Optional[str] = None

    class Config:
        from_attributes = True

class ErrorResponse(BaseModel):
    error: str
