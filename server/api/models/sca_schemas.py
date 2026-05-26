from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

class ScaCheckSchema(BaseModel):
    check_id: str
    title: str
    status: str # passed, failed
    description: str
    remediation: str

class ScaResultSchema(BaseModel):
    id: str
    agent_id: str
    hostname: str
    policy_id: str
    policy_name: str
    score: int
    total_checks: int
    passed_checks: int
    timestamp: datetime
    results: List[ScaCheckSchema]
