from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class HuntQuerySchema(BaseModel):
    query_string: str
    index: str = "siem-*"
    time_range: str = "last_24h"
    limit: int = 100

class HuntPlaybookSchema(BaseModel):
    id: str
    name: str
    description: str
    mitre_tactic: str
    mitre_technique: str
    query_string: str
    index_pattern: str

class HuntResultSchema(BaseModel):
    total_hits: int
    took_ms: int
    data: List[Dict[str, Any]]
