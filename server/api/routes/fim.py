from fastapi import APIRouter
from typing import List, Dict, Any
from datetime import datetime

router = APIRouter()

# Dummy DB for FIM events
# Needs to be extracted from elasticsearch eventually or stored in PG
FIM_EVENTS: List[Dict[str, Any]] = [
    # Some initial dummy data to show the frontend structure working
    {
        "id": "fim-001",
        "agent_id": "test-agent-1",
        "hostname": "linux-prod-web1",
        "event_type": "file_modified",
        "file_path": "/etc/passwd",
        "old_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "new_hash": "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90",
        "owner": "root",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "id": "fim-002",
        "agent_id": "test-agent-1",
        "hostname": "linux-prod-web1",
        "event_type": "file_created",
        "file_path": "/var/www/html/backdoor.php",
        "old_hash": None,
        "new_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "owner": "www-data",
        "timestamp": datetime.utcnow().isoformat()
    }
]

@router.get("", response_model=List[Dict[str, Any]])
async def get_fim_events():
    # In production, we'd query elasticsearch where module=fim
    return sorted(FIM_EVENTS, key=lambda x: x["timestamp"], reverse=True)

@router.post("/events")
async def receive_fim_event(event: Dict[str, Any]):
    event['timestamp'] = datetime.utcnow().isoformat()
    FIM_EVENTS.append(event)
    return {"status": "success"}

@router.get("/summary")
async def get_fim_summary():
    host_counts = {}
    for ev in FIM_EVENTS:
        host = ev.get('hostname', 'unknown')
        host_counts[host] = host_counts.get(host, 0) + 1
    return host_counts
