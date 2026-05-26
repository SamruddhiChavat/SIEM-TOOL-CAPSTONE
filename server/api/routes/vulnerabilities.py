from fastapi import APIRouter
from typing import List, Dict, Any
from datetime import datetime
from models.vuln_schemas import VulnerabilitySchema

router = APIRouter()

# Dummy DB for Vuln events
VULN_DB: List[Dict[str, Any]] = [
    {
        "id": "v-001",
        "agent_id": "test-agent-1",
        "hostname": "linux-prod-web1",
        "package": "openssl",
        "installed_version": "1.1.1f-1ubuntu2",
        "cve_id": "CVE-2022-0778",
        "cvss_score": 7.5,
        "severity": "High",
        "description": "Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
        "patch_available": True,
        "fix_version": "1.1.1f-1ubuntu2.13",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "id": "v-002",
        "agent_id": "test-agent-2",
        "hostname": "win-desk-001",
        "package": "Google Chrome",
        "installed_version": "114.0.5735.199",
        "cve_id": "CVE-2023-3079",
        "cvss_score": 8.8,
        "severity": "High",
        "description": "Type Confusion in V8",
        "patch_available": True,
        "fix_version": "115.0.5790.98",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "id": "v-003",
        "agent_id": "test-agent-1",
        "hostname": "linux-prod-web1",
        "package": "bash",
        "installed_version": "4.3-7ubuntu1.1",
        "cve_id": "CVE-2014-6271",
        "cvss_score": 10.0,
        "severity": "Critical",
        "description": "Shellshock vulnerability",
        "patch_available": True,
        "fix_version": "4.3-7ubuntu1.5",
        "timestamp": datetime.utcnow().isoformat()
    }
]

@router.get("", response_model=List[Dict[str, Any]])
async def get_vulnerabilities():
    return sorted(VULN_DB, key=lambda x: x["cvss_score"], reverse=True)

@router.get("/summary")
async def get_vuln_summary():
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }
    for vuln in VULN_DB:
        sev = vuln.get("severity", "Low")
        if sev in summary:
            summary[sev] += 1
    return summary

@router.post("/scan/{agent_id}")
async def trigger_scan(agent_id: str):
    # In reality, this would queue a command to the agent
    return {"status": "scan_queued", "agent_id": agent_id}
