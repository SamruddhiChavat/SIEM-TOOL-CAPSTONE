from fastapi import APIRouter
from typing import Dict, Any
import psutil

router = APIRouter()

@router.get("")
async def get_system_health():
    """
    Returns the real-time health of the SecureWatch backend components.
    Normally this would aggregate from the correlation_engine's health monitor heartbeat,
    but for the UI demo we will fetch some active stats from the FastAPI backend host.
    """
    # Mocking component statuses since they are hardcoded in docker-compose
    services = {
        "elasticsearch": "ok",
        "logstash": "ok",
        "kibana": "ok",
        "redis": "ok",
        "postgres": "ok",
        "correlation_engine": "ok",
        "backend_api": "ok"
    }
    
    try:
        disk_pct = psutil.disk_usage('/').percent
    except Exception:
        disk_pct = 0.0  # Fallback for Windows Docker hosts where '/' doesn't exist

    system = {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": disk_pct
    }
    
    # Calculate overall health with correct priority: critical > warning > healthy
    overall = "healthy"
    if system["cpu_percent"] > 90 or system["memory_percent"] > 90 or disk_pct > 90:
        overall = "warning"
    
    for k, v in services.items():
        if v != "ok":
            overall = "critical"  # Service failures always override system warnings
            break
            
    return {
        "status": overall,
        "system": system,
        "services": services
    }
