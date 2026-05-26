from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

class ComplianceFrameworkSummary(BaseModel):
    name: str
    total_violations: int
    controls_failed: List[str]
    compliance_score: int

class ComplianceStateSchema(BaseModel):
    timestamp: datetime
    overall_score: int
    frameworks: Dict[str, ComplianceFrameworkSummary]
