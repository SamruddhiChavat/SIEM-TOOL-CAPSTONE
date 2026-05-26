from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

class VulnerabilitySchema(BaseModel):
    id: str
    agent_id: str
    hostname: str
    package: str
    installed_version: str
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    patch_available: bool
    fix_version: Optional[str] = None
    timestamp: datetime
