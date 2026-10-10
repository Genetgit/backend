import httpx
from typing import Dict, Any, Optional
from app.config import settings
import uuid
from datetime import datetime

class RunnerClient:
    def __init__(self):
        self.base_url = settings.RUNNER_API_BASE
        self.mock = settings.MOCK_RUNNER

    async def _post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        if self.mock:
            now = datetime.utcnow().isoformat() + "Z"
            if "attack" in endpoint:
                return {
                    "run_id": str(uuid.uuid4()),
                    "status": "success",
                    "attack_succeeded": True,
                    "output": "Simulated SSH brute force execution completed.",
                    "started_at": now,
                    "finished_at": now
                }
            elif "defense" in endpoint:
                return {
                    "run_id": str(uuid.uuid4()),
                    "status": "success",
                    "attack_succeeded": None,
                    "output": "Simulated iptables rule applied.",
                    "started_at": now,
                    "finished_at": now
                }
            return {"run_id": str(uuid.uuid4()), "status": "success"}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(f"{self.base_url}{endpoint}", json=json_data, timeout=30.0)
                if response.status_code != 200:
                    return {"run_id": "error", "status": "failed", "output": response.text, "attack_succeeded": False}
                return response.json()
            except Exception as e:
                return {"run_id": "error", "status": f"failed: {str(e)}", "output": "", "attack_succeeded": False}

    async def run_attack(self, scenario_id: str, target_ip: str) -> Dict[str, Any]:
        return await self._post("/run/attack", {"scenario_id": scenario_id, "target_ip": target_ip})

    async def run_defense(self, defense_id: str, ip: str) -> Dict[str, Any]:
        return await self._post("/run/defense", {"defense_id": defense_id, "params": {"ip": ip}})

async def call_llm_analysis(alert_title: str, technique: str, rule_id: str) -> Dict[str, Any]:
    fallback = {
        "summary": f"Automated analysis for {alert_title}.",
        "impact": "Potential system compromise via unauthorized host configuration changes.",
        "recommended_defense_id": "block_ip_iptables" if rule_id == "R001_ssh_bruteforce" else "install_fail2ban"
    }
    return fallback
