from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends
from typing import List, Dict
from models.schemas import AlertCreate
from services.socket_manager import manager
from auth.rbac import get_current_user
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory store for Phase 4 (Would be replaced by SQLAlchemy + Postgres session injection)
ALERTS_DB: Dict[str, dict] = {}

@router.post("", status_code=201)
async def create_alert(alert: AlertCreate, background_tasks: BackgroundTasks):  # No auth: internal service call from Correlation Engine
    """Correlation Engine posts new alerts here."""
    alert_dict = alert.model_dump()
    ALERTS_DB[alert.alert_id] = alert_dict
    
    # Broadcast to all connected SIEM dashboards
    background_tasks.add_task(manager.broadcast, {"type": "new_alert", "data": alert_dict})
    
    # Optional logic to trigger active response could intercept here based on rules
    
    return {"message": "Alert created successfully"}

@router.get("", response_model=List[AlertCreate])
async def list_alerts(severity: str = None, status: str = None, limit: int = 100, _ = Depends(get_current_user)):
    """Frontend fetches alert history."""
    results = list(ALERTS_DB.values())
    if severity:
        results = [a for a in results if a["severity"] == severity]
    if status:
        results = [a for a in results if a["status"] == status]
    
    # Sort by newest first
    results.sort(key=lambda x: x["timestamp"], reverse=True)
    return results[:limit]

@router.post("/{alert_id}/close")
async def close_alert(alert_id: str, notes: str = "", _ = Depends(get_current_user)):
    if alert_id not in ALERTS_DB:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    ALERTS_DB[alert_id]["status"] = "closed"
    ALERTS_DB[alert_id]["resolution_notes"] = notes
    return {"status": "success", "alert_id": alert_id}

# WebSocket Endpoint
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, wait for client messages if any
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
