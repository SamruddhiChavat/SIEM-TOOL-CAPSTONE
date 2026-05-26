from fastapi import APIRouter
from typing import List, Dict, Any
from datetime import datetime

router = APIRouter()

SCA_DB: List[Dict[str, Any]] = [
    {
        "id": "sca-001",
        "agent_id": "test-agent-1",
        "hostname": "linux-prod-web1",
        "policy_id": "cis_linux_level1",
        "policy_name": "CIS Ubuntu Linux Benchmark Level 1",
        "score": 66,
        "total_checks": 3,
        "passed_checks": 2,
        "timestamp": datetime.utcnow().isoformat(),
        "results": [
            {
                "check_id": "CIS-1.1.2",
                "title": "Ensure /tmp is configured",
                "status": "failed",
                "description": "The /tmp directory should be mounted as a separate partition.",
                "remediation": "Configure /etc/fstab to mount /tmp"
            },
            {
                "check_id": "CIS-4.2.1.2",
                "title": "Ensure rsyslog Service is enabled",
                "status": "passed",
                "description": "Ensure that logging is active.",
                "remediation": "Run systemctl enable rsyslog"
            },
            {
                "check_id": "CIS-5.2.4",
                "title": "Ensure SSH Protocol is set to 2",
                "status": "passed",
                "description": "SSH protocol 1 is insecure.",
                "remediation": "Edit /etc/ssh/sshd_config to Protocol 2"
            }
        ]
    }
]

@router.get("", response_model=List[Dict[str, Any]])
async def get_sca_results():
    return sorted(SCA_DB, key=lambda x: x["timestamp"], reverse=True)

@router.get("/summary")
async def get_sca_summary():
    if not SCA_DB:
        return {"avg_score": 0, "total_policies_scanned": 0, "failed_checks": 0}
        
    total_score = sum(s["score"] for s in SCA_DB)
    failed = sum(1 for s in SCA_DB for r in s["results"] if r.get("status") == "failed")
    
    return {
        "avg_score": int(total_score / len(SCA_DB)),
        "total_policies_scanned": len(SCA_DB),
        "failed_checks": failed
    }

@router.get("/{result_id}")
async def get_sca_result(result_id: str):
    for r in SCA_DB:
        if r["id"] == result_id:
            return r
    return {"error": "Not found"}
