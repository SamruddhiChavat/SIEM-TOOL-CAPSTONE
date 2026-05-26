from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import uuid
import time
from datetime import datetime
import json
import redis.asyncio as redis

from db.database import get_db
from db.models import Agent, User
from auth.rbac import get_current_user, require_admin, log_audit
from models.agent_schemas import AgentResponseSchema, AgentCommandSchema

router = APIRouter()

# Setup Redis for command queue (Manager should pull from here or similar, but for now we push)
redis_client = redis.from_url("redis://redis:6379/0", decode_responses=True)

@router.get("", response_model=List[AgentResponseSchema])
async def list_agents(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Agent))
    agents = result.scalars().all()
    
    # Map to schema
    response = []
    for a in agents:
        response.append(AgentResponseSchema(
            agent_id=a.agent_id,
            hostname=a.hostname,
            ip_address=a.ip_address,
            os_type=a.os_type,
            os_version=a.os_version,
            agent_version=a.agent_version,
            status=a.status,
            group_name=a.group_name,
            last_seen=a.last_seen,
            registration_date=a.registered_at,
            labels=a.labels
        ))
    return response

@router.get("/{agent_id}", response_model=AgentResponseSchema)
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    a = result.scalars().first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    return AgentResponseSchema(
        agent_id=a.agent_id,
        hostname=a.hostname,
        ip_address=a.ip_address,
        os_type=a.os_type,
        os_version=a.os_version,
        agent_version=a.agent_version,
        status=a.status,
        group_name=a.group_name,
        last_seen=a.last_seen,
        registration_date=a.registered_at,
        labels=a.labels
    )

@router.delete("/{agent_id}")
async def remove_agent(agent_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_admin)):
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    a = result.scalars().first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    await db.delete(a)
    await db.commit()
    
    await log_audit(db, current_user.username, "delete", "agents", agent_id)
    return {"status": "removed"}

@router.post("/{agent_id}/command")
async def send_command(agent_id: str, cmd_data: AgentCommandSchema, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_admin)):
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    a = result.scalars().first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    cmd_id = str(uuid.uuid4())
    command_obj = {
        "id": cmd_id,
        "command": cmd_data.command,
        "args": cmd_data.args or {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # We push into a Redis list that the manager or a background task can read
    await redis_client.rpush(f"agent_commands:{agent_id}", json.dumps(command_obj))
    await log_audit(db, current_user.username, "command", "agents", agent_id, details=command_obj)
    
    return {"status": "queued", "command_id": cmd_id}
