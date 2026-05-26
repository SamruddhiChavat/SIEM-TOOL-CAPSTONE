from fastapi import APIRouter
from typing import List, Dict, Any
from models.hunting_schemas import HuntQuerySchema, HuntPlaybookSchema, HuntResultSchema
from services.hunt_playbooks import HUNT_PLAYBOOKS
import json
import random
from datetime import datetime

router = APIRouter()

@router.get("/playbooks", response_model=List[HuntPlaybookSchema])
async def get_playbooks():
    """Returns the library of predefined hunting playbooks."""
    return HUNT_PLAYBOOKS

@router.post("/execute", response_model=HuntResultSchema)
async def execute_hunt(query: HuntQuerySchema):
    """
    Executes a lucene/KQL style query against Elasticsearch.
    (Currently mocked to simulate a hunt returning data for the UI).
    """
    # In a real environment, this connects to ES:
    # res = es.search(index=query.index, q=query.query_string, size=query.limit)
    
    # Mocking hunt results
    mock_hits = []
    num_hits = random.randint(0, 15)
    
    for i in range(num_hits):
        mock_hits.append({
            "_index": "siem-logs-endpoint-2024.10",
            "_id": f"doc_{i}",
            "_score": random.uniform(1.0, 5.0),
            "_source": {
                "@timestamp": datetime.utcnow().isoformat(),
                "agent": {"name": f"win-machine-{random.randint(1,10)}"},
                "process": {
                    "name": "powershell.exe" if "powershell" in query.query_string.lower() else "unknown.exe",
                    "command_line": query.query_string.split(":")[-1] if ":" in query.query_string else "mocked_command",
                    "pid": random.randint(1000, 9999)
                },
                "user": {"name": "NT AUTHORITY\\SYSTEM"}
            }
        })
        
    return {
        "total_hits": num_hits,
        "took_ms": random.randint(15, 120),
        "data": mock_hits
    }
