from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List
import uuid

from app.config import settings
from app.database import get_db, engine, Base, async_session
from app.models import EventModel, AlertModel, VerificationModel
from app.schemas import (
    EventIngestRequest, EventIngestResponse, Alert, AlertDetailResponse,
    DefenseApplyRequest, DefenseApplyResponse, VerificationRequest, 
    VerificationResponse, VerificationDetailResponse, ErrorResponse
)
from app.detection import run_detection_engine
from app.client import call_llm_analysis, RunnerClient
from app.verification import run_verification_pipeline

app = FastAPI(
    title="Adaptive Cyber Attack Simulation & Defense Verification Platform API",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    if x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key."
        )

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.post("/api/events", response_model=EventIngestResponse, status_code=status.HTTP_200_OK)
async def ingest_events(payload: EventIngestRequest, db: AsyncSession = Depends(get_db), auth=Depends(verify_api_key)):
    try:
        new_models = []
        for e in payload.events:
            model = EventModel(
                event_id=e.event_id,
                timestamp=e.timestamp.replace(tzinfo=None),
                host_id=e.host_id,
                source=e.source,
                event_type=e.event_type,
                src_ip=e.src_ip,
                username=e.username,
                raw=e.raw
            )
            new_models.append(model)
            db.add(model)
        await db.commit()
        
        await run_detection_engine(db, new_models)
        return EventIngestResponse(accepted=len(payload.events))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts", response_model=List[Alert])
async def list_alerts(db: AsyncSession = Depends(get_db), auth=Depends(verify_api_key)):
    stmt = select(AlertModel).order_by(desc(AlertModel.first_seen))
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    
    out = []
    for a in alerts:
        out.append(Alert(
            alert_id=a.alert_id,
            rule_id=a.rule_id,
            title=a.title,
            severity=a.severity,
            risk_score=a.risk_score,
            host_id=a.host_id,
            src_ip=a.src_ip,
            mitre_technique=a.mitre_technique,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
            event_ids=[e.event_id for e in a.events],
            status=a.status,
            ai_analysis=a.ai_analysis
        ))
    return out

@app.get("/api/alerts/{alert_id}", response_model=AlertDetailResponse)
async def get_alert_detail(alert_id: str, db: AsyncSession = Depends(get_db), auth=Depends(verify_api_key)):
    stmt = select(AlertModel).where(AlertModel.alert_id == alert_id)
    result = await db.execute(stmt)
    a = result.scalars().first()
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    return AlertDetailResponse(
        alert_id=a.alert_id,
        rule_id=a.rule_id,
        title=a.title,
        severity=a.severity,
        risk_score=a.risk_score,
        host_id=a.host_id,
        src_ip=a.src_ip,
        mitre_technique=a.mitre_technique,
        first_seen=a.first_seen,
        last_seen=a.last_seen,
        event_ids=[e.event_id for e in a.events],
        status=a.status,
        ai_analysis=a.ai_analysis,
        events=[
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "host_id": e.host_id,
                "source": e.source,
                "event_type": e.event_type,
                "src_ip": e.src_ip,
                "username": e.username,
                "raw": e.raw
            } for e in a.events
        ]
    )

@app.post("/api/alerts/{alert_id}/analyze", response_model=Alert)
async def analyze_alert(alert_id: str, db: AsyncSession = Depends(get_db), auth=Depends(verify_api_key)):
    stmt = select(AlertModel).where(AlertModel.alert_id == alert_id)
    result = await db.execute(stmt)
    a = result.scalars().first()
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    analysis_json = await call_llm_analysis(a.title, a.mitre_technique, a.rule_id)
    a.ai_analysis = analysis_json
    await db.commit()
    
    return Alert(
        alert_id=a.alert_id,
        rule_id=a.rule_id,
        title=a.title,
        severity=a.severity,
        risk_score=a.risk_score,
        host_id=a.host_id,
        src_ip=a.src_ip,
        mitre_technique=a.mitre_technique,
        first_seen=a.first_seen,
        last_seen=a.last_seen,
        event_ids=[e.event_id for e in a.events],
        status=a.status,
        ai_analysis=a.ai_analysis
    )

@app.post("/api/defenses/apply", response_model=DefenseApplyResponse)
async def apply_defense(payload: DefenseApplyRequest, db: AsyncSession = Depends(get_db), auth=Depends(verify_api_key)):
    stmt = select(AlertModel).where(AlertModel.alert_id == payload.alert_id)
    res = await db.execute(stmt)
    alert = res.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    runner = RunnerClient()
    runner_res = await runner.run_defense(payload.defense_id, alert.src_ip)
    
    if runner_res.get("status") == "success":
        alert.status = "defended"
        await db.commit()
        
    return DefenseApplyResponse(
        run_id=runner_res.get("run_id", "unknown"),
        status=runner_res.get("status", "failed")
    )

@app.post("/api/verifications", response_model=VerificationResponse)
async def start_verification(payload: VerificationRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), auth=Depends(verify_api_key)):
    v_id = str(uuid.uuid4())
    verification = VerificationModel(
        verification_id=v_id,
        alert_id=payload.alert_id,
        result="running",
        baseline=None,
        retest=None
    )
    db.add(verification)
    await db.commit()
    
    background_tasks.add_task(run_verification_pipeline, v_id, payload.alert_id, async_session)
    return VerificationResponse(verification_id=v_id, status="running")

@app.get("/api/verifications/{id}", response_model=VerificationDetailResponse)
async def get_verification(id: str, db: AsyncSession = Depends(get_db), auth=Depends(verify_api_key)):
    stmt = select(VerificationModel).where(VerificationModel.verification_id == id)
    res = await db.execute(stmt)
    v = res.scalars().first()
    if not v:
        raise HTTPException(status_code=404, detail="Verification not found")
    return v
