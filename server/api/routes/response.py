from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
import uuid
import logging

from db.database import get_db
from db.models import Playbook, ResponseHistory
from auth.rbac import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_condition: Optional[str] = None
    is_active: bool = True

class PlaybookResponse(PlaybookCreate):
    id: str

class BlockRequest(BaseModel):
    ip_address: str
    reason: str

# Mock State for blocked IPs
BLOCKED_IPS = set()

@router.get("/playbooks", response_model=List[PlaybookResponse])
async def list_playbooks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Playbook))
    return result.scalars().all()

@router.post("/playbooks", response_model=PlaybookResponse)
async def create_playbook(pb: PlaybookCreate, db: AsyncSession = Depends(get_db)):
    new_pb = Playbook(id=str(uuid.uuid4()), **pb.dict())
    db.add(new_pb)
    await db.commit()
    await db.refresh(new_pb)
    return new_pb

@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    pb = result.scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    await db.delete(pb)
    await db.commit()
    return {"status": "success"}

@router.post("/block-ip")
async def block_ip(request: BlockRequest, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Simulates pushing an iptables drop rule or firewall API call."""
    logger.warning(f"ACTIVE RESPONSE INIT: Blocking IP {request.ip_address}. Reason: {request.reason}")
    BLOCKED_IPS.add(request.ip_address)
    
    # Record history
    history = ResponseHistory(
        id=str(uuid.uuid4()),
        playbook_name="Manual Block",
        target=request.ip_address,
        action_taken="block_ip",
        initiated_by=user.username
    )
    db.add(history)
    await db.commit()
    
    return {"status": "success", "action": "blocked", "ip": request.ip_address}

@router.post("/unblock-ip")
async def unblock_ip(request: BlockRequest, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if request.ip_address in BLOCKED_IPS:
        BLOCKED_IPS.remove(request.ip_address)
        logger.info(f"ACTIVE RESPONSE INIT: Unblocking IP {request.ip_address}")
        
        history = ResponseHistory(
            id=str(uuid.uuid4()),
            playbook_name="Manual Unblock",
            target=request.ip_address,
            action_taken="unblock_ip",
            initiated_by=user.username
        )
        db.add(history)
        await db.commit()
        
        return {"status": "success", "action": "unblocked"}
    raise HTTPException(status_code=404, detail="IP not currently blocked")

@router.get("/blocklist")
async def get_blocklist():
    return {"blocked_ips": list(BLOCKED_IPS)}

@router.get("/history")
async def get_history(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ResponseHistory).order_by(ResponseHistory.timestamp.desc()))
    return result.scalars().all()
