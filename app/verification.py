import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import VerificationModel, AlertModel, EventModel
from app.client import RunnerClient
from datetime import datetime, timedelta

async def run_verification_pipeline(verification_id: str, alert_id: str, db_factory):
    runner = RunnerClient()
    attack1 = await runner.run_attack("ssh_bruteforce", "10.0.0.5")
    
    async with db_factory() as db:
        stmt = select(VerificationModel).where(VerificationModel.verification_id == verification_id)
        v_res = await db.execute(stmt)
        v_obj = v_res.scalars().first()
        if not v_obj: return
        
        v_obj.baseline = {
            "attack_succeeded": attack1.get("attack_succeeded") or False,
            "detected": attack1.get("status") == "success"
        }
        await db.commit()

    defense = await runner.run_defense("block_ip_iptables", "10.0.0.5")
    attack2 = await runner.run_attack("ssh_bruteforce", "10.0.0.5")

    async with db_factory() as db:
        stmt = select(VerificationModel).where(VerificationModel.verification_id == verification_id)
        v_res = await db.execute(stmt)
        v_obj = v_res.scalars().first()
        
        alert_stmt = select(AlertModel).where(AlertModel.alert_id == alert_id)
        a_res = await db.execute(alert_stmt)
        alert_obj = a_res.scalars().first()

        if v_obj and alert_obj:
            v_obj.retest = {
                "attack_succeeded": attack2.get("attack_succeeded") or False,
                "detected": False
            }
            
            if attack2.get("attack_succeeded") is False:
                v_obj.result = "verified"
                alert_obj.status = "verified"
                v_obj.evidence = f"Baseline execution: Attack succeeded={v_obj.baseline['attack_succeeded']}. Retest execution: Attack succeeded={v_obj.retest['attack_succeeded']} (Successfully Blocked)."
            else:
                v_obj.result = "not_verified"
                alert_obj.status = "failed_verification"
                v_obj.evidence = "Retest attack bypassed defenses and executed successfully."
            
            await db.commit()
