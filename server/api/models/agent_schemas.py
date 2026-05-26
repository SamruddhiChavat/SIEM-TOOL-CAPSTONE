from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class AgentRegisterSchema(BaseModel):
    hostname: str
    os_type: str
    os_version: str
    agent_version: str
    group: str
    ip_address: str

class AgentResponseSchema(BaseModel):
    agent_id: str
    hostname: str
    ip_address: str
    os_type: str
    os_version: str
    agent_version: str
    registration_date: Optional[datetime]
    last_seen: Optional[datetime]
    status: str
    group_name: str
    labels: Dict[str, Any]

class AgentCommandSchema(BaseModel):
    command: str
    args: Optional[Dict[str, Any]] = None

class AgentHeartbeatSchema(BaseModel):
    events: List[Dict[str, Any]]
