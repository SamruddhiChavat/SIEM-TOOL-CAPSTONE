from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class AlertCreate(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    mitre_tactic: str
    mitre_technique: str
    severity: str
    entity: str
    status: str = "new"
    timestamp: str
    raw_event: dict
    recommended_action: str

class AlertResponse(AlertCreate):
    id: int
    created_at: datetime
    updated_at: datetime
    assignee_id: Optional[str] = None
    resolution_notes: Optional[str] = None

class AssetUpdate(BaseModel):
    entity_id: str
    added_risk: int
    last_seen_alert: str
    mitre_technique_triggered: Optional[str] = None
