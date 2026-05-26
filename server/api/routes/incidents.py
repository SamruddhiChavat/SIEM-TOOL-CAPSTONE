from fastapi import APIRouter, HTTPException
import httpx
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from pydantic import BaseModel

router = APIRouter()
logger = logging.getLogger(__name__)

ES_HOST = os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")

# Mock Redis connection for TI and False Positive storage since we don't have a formal DB setup here
import redis.asyncio as redis
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

class CloseIncidentRequest(BaseModel):
    verdict: str  # True Positive, False Positive, Benign Positive
    attack_confirmed: bool
    damage_done: bool
    root_cause: str
    analyst: str
    reason: str

@router.get("/triage")
async def get_triage_queue():
    """Returns priority queue and grouped alerts."""
    now = datetime.utcnow()
    past_24h = now - timedelta(hours=24)
    
    query = {
        "size": 200,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": past_24h.isoformat() + "Z"}}}
                ],
                "filter": [
                    {"terms": {"status.keyword": ["new", "investigating", "open"]}}
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}]
    }
    
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(
                f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
                json=query
            )
            alerts = res.json().get("hits", {}).get("hits", []) if res.status_code == 200 else []
            
            # 1. Fetch False Positive mappings from Redis
            # We store fp:{rule_id}:{source_ip}
            
            enriched_alerts = []
            
            for alert in alerts:
                src = alert["_source"]
                alert_id = alert["_id"]
                rule_id = src.get("rule_id", "")
                source_ip = src.get("source_ip", "")
                
                # Check FP list
                fp_key = f"fp:{rule_id}:{source_ip}"
                try:
                    fp_data_str = await redis_client.get(fp_key)
                except Exception:
                    fp_data_str = None
                
                fp_data = json.loads(fp_data_str) if fp_data_str else None
                
                # Calculate priority
                severity = src.get("severity", "medium").lower()
                sev_pts = {"critical": 100, "high": 60, "medium": 30, "low": 10}.get(severity, 10)
                
                asset_risk = src.get("asset_risk_score", 0)
                asset_pts = 50 if asset_risk >= 90 else 30 if asset_risk >= 70 else 15 if asset_risk >= 40 else 5
                
                # Threat Intel Points
                ti_pts = 0
                try:
                    ti_str = await redis_client.get(f"ti:{source_ip}")
                    if ti_str:
                        ti = json.loads(ti_str)
                        if ti.get("malicious", False) or ti.get("vt_hits", 0) > 0:
                            ti_pts = 40
                        elif ti.get("confidence", 0) > 80:
                            ti_pts = 20
                except Exception:
                    pass
                
                # Age Penalty
                created_at = datetime.fromisoformat(src.get("timestamp", "").replace("Z", "+00:00").split(".")[0] + "+00:00")
                hours_open = max(0, (now.replace(tzinfo=None) - created_at.replace(tzinfo=None)).total_seconds() / 3600)
                age_penalty = int(hours_open * 2)
                
                priority = sev_pts + asset_pts + ti_pts - age_penalty
                
                is_fp = False
                fp_msg = ""
                if fp_data:
                    is_fp = True
                    fp_msg = f"Likely False Positive (previously closed by {fp_data.get('analyst')} on {fp_data.get('date')})"
                    priority = -100  # Bottom of queue
                
                enriched_alerts.append({
                    "id": alert_id,
                    "title": src.get("rule_name", "Unknown Alert"),
                    "severity": severity,
                    "status": src.get("status", "new").capitalize(),
                    "assignee": src.get("assignee", "Unassigned"),
                    "affected": src.get("entity", "Unknown"),
                    "created": src.get("timestamp"),
                    "source_ip": source_ip,
                    "priority": max(-100, priority),
                    "is_fp": is_fp,
                    "fp_msg": fp_msg,
                    "mitre": src.get("mitre_tactic", "Unknown")
                })
            
            # 2. GROUPING
            groups = []
            ungrouped = []
            
            # Group by source_ip -> list of alerts
            ip_groups = {}
            # Group by asset -> list of source_ips
            asset_groups = {}
            
            for a in enriched_alerts:
                ip = a["source_ip"]
                asset = a["affected"]
                if ip:
                    ip_groups.setdefault(ip, []).append(a)
                if asset and ip:
                    asset_groups.setdefault(asset, set()).add(ip)
            
            processed_ids = set()
            
            # Rule 1: Same source_ip with 3+ alerts
            for ip, alist in ip_groups.items():
                if len(alist) >= 3:
                    avg_prio = sum(x["priority"] for x in alist) / len(alist)
                    groups.append({
                        "is_group": True,
                        "id": f"grp_ip_{ip.replace('.', '_')}",
                        "title": f"Campaign: {len(alist)} alerts from {ip}",
                        "priority": avg_prio + 20, # Boost group priority
                        "alerts": alist,
                        "type": "campaign"
                    })
                    for x in alist:
                        processed_ids.add(x["id"])
            
            # Rule 2: Same asset targeted by 3+ different source IPs
            for asset, ips in asset_groups.items():
                if len(ips) >= 3:
                    asset_alerts = [a for a in enriched_alerts if a["affected"] == asset and a["id"] not in processed_ids]
                    if len(asset_alerts) >= 3:
                        avg_prio = sum(x["priority"] for x in asset_alerts) / len(asset_alerts)
                        groups.append({
                            "is_group": True,
                            "id": f"grp_asset_{asset}",
                            "title": f"Coordinated attack on {asset}",
                            "priority": avg_prio + 30,
                            "alerts": asset_alerts,
                            "type": "coordinated"
                        })
                        for x in asset_alerts:
                            processed_ids.add(x["id"])
            
            # Remaining ungrouped
            for a in enriched_alerts:
                if a["id"] not in processed_ids:
                    ungrouped.append(a)
            
            final_list = groups + ungrouped
            final_list.sort(key=lambda x: x["priority"], reverse=True)
            
            return final_list
            
        except Exception as e:
            logger.error(f"Error building triage queue: {e}")
            return []


@router.get("/{incident_id}/detail")
async def get_incident_detail(incident_id: str):
    """Returns the 5 steps for the investigation workflow."""
    async with httpx.AsyncClient() as client:
        # Get the alert
        res = await client.get(f"{ES_HOST}/siem-alerts-*/_doc/{incident_id}?ignore_unavailable=true")
        if res.status_code != 200:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        alert_src = res.json()["_source"]
        source_ip = alert_src.get("source_ip", "")
        asset = alert_src.get("entity", "")
        tactic = alert_src.get("mitre_tactic", "")
        technique = alert_src.get("mitre_technique", "Unknown")
        raw_ids = alert_src.get("raw_event_ids", [])
        
        # STEP A: Raw Logs
        raw_events = []
        if raw_ids:
            raw_res = await client.post(
                f"{ES_HOST}/siem-logs-*/_search?ignore_unavailable=true",
                json={"query": {"terms": {"_id": raw_ids}}, "sort": [{"@timestamp": {"order": "asc"}}], "size": 100}
            )
            raw_events = [hit["_source"] for hit in raw_res.json().get("hits", {}).get("hits", [])] if raw_res.status_code == 200 else []
        
        # STEP B: Source Enrichment
        ti_data = {}
        if source_ip:
            try:
                ti_str = await redis_client.get(f"ti:{source_ip}")
                ti_data = json.loads(ti_str) if ti_str else {}
            except Exception:
                pass
            
            # Other alerts this IP triggered (30d)
            past_30d = (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"
            ip_alerts_res = await client.post(
                f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
                json={"query": {"bool": {"must": [{"term": {"source_ip.keyword": source_ip}}, {"range": {"timestamp": {"gte": past_30d}}}]}}, "size": 0}
            )
            ti_data["alerts_30d"] = ip_alerts_res.json().get("hits", {}).get("total", {}).get("value", 0) if ip_alerts_res.status_code == 200 else 0
        
        # STEP C: Target Asset Context
        asset_context = {
            "name": asset,
            "criticality": "High" if alert_src.get("asset_risk_score", 0) > 70 else "Medium",
            "risk_score": alert_src.get("asset_risk_score", 0),
            "owner": "IT Security"
        }
        if asset:
            # Open incidents on this asset
            open_res = await client.post(
                f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
                json={"query": {"bool": {"must": [{"term": {"entity.keyword": asset}}, {"terms": {"status.keyword": ["new", "investigating", "open"]}}]}}, "size": 5}
            )
            asset_context["open_incidents"] = open_res.json().get("hits", {}).get("total", {}).get("value", 0) if open_res.status_code == 200 else 0
        
        # STEP D: Related Alerts (Pivot)
        related = {
            "subnet": [],
            "asset_24h": [],
            "technique_1h": []
        }
        
        if source_ip and "." in source_ip:
            subnet = ".".join(source_ip.split(".")[:3]) + ".*"
            sub_res = await client.post(
                f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
                json={"query": {"wildcard": {"source_ip.keyword": subnet}}, "size": 5}
            )
            if sub_res.status_code == 200:
                related["subnet"] = [{"id": hit["_id"], "title": hit["_source"].get("rule_name")} for hit in sub_res.json().get("hits", {}).get("hits", []) if hit["_id"] != incident_id]
        
        # STEP E: Recommendations (Static based on tactic)
        recommendations = []
        tactic_lower = tactic.lower()
        if "brute" in tactic_lower or "credential" in tactic_lower:
            recommendations = ["Block Source IP", "Enable Account Lockout", "Check for successful logins from this IP"]
        elif "execution" in tactic_lower or "powershell" in tactic_lower:
            recommendations = ["Isolate Host", "Pull Memory Dump", "Check Parent Process Tree"]
        elif "exfiltration" in tactic_lower:
            recommendations = ["Block IP + Port", "Check Data Volume", "Identify Data Classification"]
        else:
            recommendations = ["Investigate Source IP", "Review recent host network connections", "Check for lateral movement"]
        
        return {
            "alert": alert_src,
            "workflow": {
                "step_a_timeline": raw_events,
                "step_b_source": ti_data,
                "step_c_asset": asset_context,
                "step_d_related": related,
                "step_e_response": recommendations
            }
        }


@router.post("/{incident_id}/close")
async def close_incident(incident_id: str, req: CloseIncidentRequest):
    """Records verdict and updates False Positive learning."""
    now = datetime.utcnow().isoformat() + "Z"
    
    async with httpx.AsyncClient() as client:
        # Get alert to check rule_id and source_ip
        res = await client.get(f"{ES_HOST}/siem-alerts-*/_doc/{incident_id}?ignore_unavailable=true")
        if res.status_code != 200:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        alert_src = res.json()["_source"]
        rule_id = alert_src.get("rule_id", "unknown")
        source_ip = alert_src.get("source_ip", "")
        
        # False Positive Learning
        if req.verdict == "False Positive" and rule_id and source_ip:
            fp_key = f"fp:{rule_id}:{source_ip}"
            fp_data = {
                "rule_id": rule_id,
                "source_ip": source_ip,
                "reason": req.reason,
                "analyst": req.analyst,
                "date": datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            }
            try:
                # Store in Redis for 30 days
                await redis_client.setex(fp_key, 2592000, json.dumps(fp_data))
            except Exception as e:
                logger.error(f"Error saving FP data to Redis: {e}")
        
        # Calculate time to respond
        created_ts = datetime.fromisoformat(alert_src.get("timestamp", "").replace("Z", "+00:00").split(".")[0] + "+00:00")
        ttr_hours = (datetime.utcnow() - created_ts.replace(tzinfo=None)).total_seconds() / 3600
        
        # Update alert in ES
        update_body = {
            "doc": {
                "status": "closed",
                "resolved_at": now,
                "resolution_notes": req.reason,
                "verdict": req.verdict,
                "attack_confirmed": req.attack_confirmed,
                "damage_done": req.damage_done,
                "root_cause": req.root_cause,
                "analyst": req.analyst,
                "time_to_respond_hours": ttr_hours
            }
        }
        
        await client.post(
            f"{ES_HOST}/siem-alerts-*/_update/{incident_id}",
            json=update_body
        )
        
        return {"status": "success", "message": "Incident closed and recorded."}
