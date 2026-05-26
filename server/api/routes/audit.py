from fastapi import APIRouter
from typing import List, Dict, Any
from datetime import datetime
from models.audit_schemas import AuditLogSchema

router = APIRouter()

# Dummy in-memory audit log
AUDIT_DB: List[Dict[str, Any]] = [
    {
        "id": "audit-001",
        "timestamp": datetime.utcnow().isoformat(),
        "user": "admin",
        "action": "execute_playbook",
        "resource_type": "active_response",
        "resource_id": "isolate_host",
        "details": {"target_ip": "10.0.0.45", "reason": "Ransomware detection"},
        "ip_address": "192.168.1.100",
        "status": "success"
    },
    {
        "id": "audit-002",
        "timestamp": datetime.utcnow().isoformat(),
        "user": "system",
        "action": "agent_registered",
        "resource_type": "agent",
        "resource_id": "test-agent-1",
        "details": {"hostname": "linux-prod-web1"},
        "ip_address": "10.0.0.45",
        "status": "success"
    }
]

@router.get("", response_model=List[Dict[str, Any]])
async def get_audit_logs(limit: int = 100):
    sorted_db = sorted(AUDIT_DB, key=lambda x: x["timestamp"], reverse=True)
    return sorted_db[:limit]

@router.post("")
async def create_audit_log(log: Dict[str, Any]):
    log["id"] = f"audit-{len(AUDIT_DB)+1}"
    log["timestamp"] = datetime.utcnow().isoformat()
    AUDIT_DB.append(log)
    return {"status": "created", "id": log["id"]}
