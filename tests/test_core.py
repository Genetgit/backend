import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from datetime import datetime, timedelta
import uuid

@pytest.mark.asyncio
async def test_unauthorized_request(client_session):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/alerts", headers={"X-API-Key": "wrong-key"})
        assert res.status_code == 401

@pytest.mark.asyncio
async def test_r001_brute_force_detection(client_session):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        headers = {"X-API-Key": "secure_shared_lab_key_2026"}
        events = []
        base_time = datetime.utcnow()
        
        for i in range(5):
            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": (base_time + timedelta(seconds=i)).isoformat() + "Z",
                "host_id": "target-01",
                "source": "auth_log",
                "event_type": "ssh_login_failed",
                "src_ip": "192.168.1.50",
                "username": "root",
                "raw": "Failed password for root"
            })
            
        res = await ac.post("/api/events", json={"events": events}, headers=headers)
        assert res.status_code == 200

        alert_res = await ac.get("/api/alerts", headers=headers)
        assert len(alert_res.json()) >= 1
        assert alert_res.json()[0]["rule_id"] == "R001_ssh_bruteforce"
