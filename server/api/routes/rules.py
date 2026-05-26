from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid

from db.database import get_db
from db.models import Rule, User
from auth.rbac import get_current_user, require_analyst, log_audit

router = APIRouter()

class RuleCreate(BaseModel):
    rule_id: str
    name: str
    severity: str = "low"
    description: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    logic: Dict[str, Any]
    suppression: int = 0
    enabled: bool = True

class RuleOut(RuleCreate):
    id: str

@router.get("", response_model=List[RuleOut])
async def list_rules(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Rule))
    return result.scalars().all()

@router.get("/{id}", response_model=RuleOut)
async def get_rule(id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Rule).where(Rule.id == id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.post("", response_model=RuleOut)
async def create_rule(data: RuleCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_analyst)):
    new_rule = Rule(
        id=str(uuid.uuid4()),
        rule_id=data.rule_id,
        name=data.name,
        severity=data.severity,
        description=data.description,
        mitre_tactic=data.mitre_tactic,
        mitre_technique_id=data.mitre_technique_id,
        mitre_technique_name=data.mitre_technique_name,
        logic=data.logic,
        suppression=data.suppression,
        enabled=data.enabled
    )
    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)
    
    await log_audit(db, current_user.username, "create", "rules", new_rule.id)
    return new_rule

@router.put("/{id}", response_model=RuleOut)
async def update_rule(id: str, data: RuleCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_analyst)):
    result = await db.execute(select(Rule).where(Rule.id == id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule.rule_id = data.rule_id
    rule.name = data.name
    rule.severity = data.severity
    rule.description = data.description
    rule.mitre_tactic = data.mitre_tactic
    rule.mitre_technique_id = data.mitre_technique_id
    rule.mitre_technique_name = data.mitre_technique_name
    rule.logic = data.logic
    rule.suppression = data.suppression
    rule.enabled = data.enabled
    
    await db.commit()
    await db.refresh(rule)
    
    await log_audit(db, current_user.username, "update", "rules", rule.id)
    return rule

@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_analyst)):
    result = await db.execute(select(Rule).where(Rule.id == id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    await db.delete(rule)
    await db.commit()
    
    await log_audit(db, current_user.username, "delete", "rules", id)
    return None
