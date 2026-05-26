from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
import httpx
import os
import json
import asyncio
from typing import Dict, List, Any
from pydantic import BaseModel
from datetime import datetime, timedelta

router = APIRouter()
ES_HOST = os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")

class SearchQuery(BaseModel):
    query_string: str
    time_range: str = "24h" # e.g., 24h, 7d
    from_time: str = None
    to_time: str = None
    size: int = 100

def parse_to_es_dsl(q: str) -> dict:
    """Parses simplified syntax to ES Query DSL."""
    if not q or q.strip() == "*":
        return {"match_all": {}}
    
    # Very basic parsing for demo
    # Split by spaces, handle key:value, NOT, AND, OR
    must_clauses = []
    must_not_clauses = []
    should_clauses = []
    
    tokens = q.split()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        
        if token == "NOT" and i + 1 < len(tokens):
            next_token = tokens[i+1]
            if ":" in next_token:
                k, v = next_token.split(":", 1)
                must_not_clauses.append({"match": {k: v}})
            i += 2
            continue
            
        if token == "AND":
            i += 1
            continue
            
        if token == "OR":
            # Just push everything to should for this simple demo
            i += 1
            continue
            
        if ":" in token:
            k, v = token.split(":", 1)
            if "*" in v:
                must_clauses.append({"wildcard": {f"{k}.keyword": v}})
            else:
                must_clauses.append({"match": {k: v}})
        else:
            # Phrase search
            if token.startswith('"') and token.endswith('"'):
                must_clauses.append({"match_phrase": {"message": token.strip('"')}})
            else:
                must_clauses.append({"multi_match": {"query": token, "fields": ["message", "rule_name"]}})
        i += 1
        
    bool_q = {}
    if must_clauses: bool_q["must"] = must_clauses
    if must_not_clauses: bool_q["must_not"] = must_not_clauses
    if should_clauses: bool_q["should"] = should_clauses
    
    return {"bool": bool_q} if bool_q else {"match_all": {}}

@router.post("/search")
async def search_logs(req: SearchQuery):
    es_query = parse_to_es_dsl(req.query_string)
    
    # Time bounds
    now = datetime.utcnow()
    if req.from_time and req.to_time:
        time_filter = {"range": {"@timestamp": {"gte": req.from_time, "lte": req.to_time}}}
    else:
        hours = 24
        if req.time_range.endswith("h"):
            hours = int(req.time_range[:-1])
        elif req.time_range.endswith("d"):
            hours = int(req.time_range[:-1]) * 24
        elif req.time_range.endswith("m"):
            hours = int(req.time_range[:-1]) / 60.0
            
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": (now - timedelta(hours=hours)).isoformat() + "Z",
                    "lte": now.isoformat() + "Z"
                }
            }
        }
        
    if "bool" in es_query:
        if "must" not in es_query["bool"]:
            es_query["bool"]["must"] = []
        es_query["bool"]["must"].append(time_filter)
    else:
        es_query = {"bool": {"must": [es_query, time_filter]}}
        
    # Aggregations for field statistics
    aggs = {
        "source_ip_stats": {"terms": {"field": "source_ip.keyword", "size": 10}},
        "severity_stats": {"terms": {"field": "severity.keyword", "size": 10}},
        "event_action_stats": {"terms": {"field": "event_action.keyword", "size": 10}},
        "host_stats": {"terms": {"field": "host.name.keyword", "size": 10}}
    }
    
    payload = {
        "size": req.size,
        "query": es_query,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "aggs": aggs
    }
    
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(
                f"{ES_HOST}/siem-logs-*/_search?ignore_unavailable=true",
                json=payload
            )
            data = res.json()
            if res.status_code != 200:
                return {"error": data}
                
            hits = data.get("hits", {}).get("hits", [])
            aggregations = data.get("aggregations", {})
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            
            # Format aggregations for frontend
            stats = {}
            for k, v in aggregations.items():
                field_name = k.replace("_stats", "")
                stats[field_name] = [{"value": b["key"], "count": b["doc_count"]} for b in v.get("buckets", [])]
                
            return {
                "total": total,
                "logs": [{"_id": h["_id"], **h["_source"]} for h in hits],
                "stats": stats
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

@router.post("/export")
async def export_logs(req: SearchQuery):
    req.size = 10000
    res = await search_logs(req)
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res

# WebSocket for real-time log streaming
# Mounted at /api/v1/logs/ws inside main.py router inclusion, but let's define here
active_log_connections = []

@router.websocket("/ws")
async def logs_websocket(websocket: WebSocket):
    await websocket.accept()
    active_log_connections.append(websocket)
    try:
        # Simulate log streaming for now since ES tailing needs a specific setup
        import random
        while True:
            await asyncio.sleep(random.uniform(0.5, 2.0))
            mock_log = {
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "source_ip": f"192.168.1.{random.randint(1, 255)}",
                "severity": random.choice(["info", "low", "medium", "high", "critical"]),
                "event_action": random.choice(["failed_login", "authentication_success", "network_connection"]),
                "message": "Simulated real-time log event",
                "host": {"name": f"server-{random.randint(1,5)}"}
            }
            await websocket.send_json(mock_log)
    except WebSocketDisconnect:
        active_log_connections.remove(websocket)
