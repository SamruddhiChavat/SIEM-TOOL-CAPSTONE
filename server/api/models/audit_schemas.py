from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime

class AuditLogSchema(BaseModel):
    id: str
    timestamp: datetime
    user: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    status: str # "success", "failed", "denied"
