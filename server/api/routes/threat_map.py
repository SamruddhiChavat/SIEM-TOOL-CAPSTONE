from fastapi import APIRouter, HTTPException
import httpx
import os
import json
import redis.asyncio as redis
from datetime import datetime, timedelta

router = APIRouter()

ES_HOST = os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

redis_client = redis.from_url(REDIS_URL, decode_responses=True)

@router.get("/data")
async def get_threat_map_data():
    now = datetime.utcnow()
    past_24h = now - timedelta(hours=24)
    past_30d = now - timedelta(days=30)
    
    async with httpx.AsyncClient() as client:
        try:
            # 1. Fetch 30-day country risk scores
            country_query = {
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": past_30d.isoformat() + "Z"}}},
                "aggs": {
                    "by_country": {"terms": {"field": "geoip.country_name.keyword", "size": 100}}
                }
            }
            country_res = await client.post(f"{ES_HOST}/siem-logs-*/_search?ignore_unavailable=true", json=country_query)
            country_data = country_res.json() if country_res.status_code == 200 else {}
            country_risk = {b["key"]: b["doc_count"] for b in country_data.get("aggregations", {}).get("by_country", {}).get("buckets", [])}

            # 2. Fetch recent alerts/events for arcs and clusters
            events_query = {
                "size": 500, # Limit for performance
                "query": {"range": {"timestamp": {"gte": past_24h.isoformat() + "Z"}}},
                "sort": [{"timestamp": {"order": "asc"}}]
            }
            events_res = await client.post(f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true", json=events_query)
            events_data = events_res.json() if events_res.status_code == 200 else {}
            
            raw_events = []
            ips_to_check = set()
            for hit in events_data.get("hits", {}).get("hits", []):
                src = hit["_source"]
                sip = src.get("source_ip")
                dip = src.get("destination_ip")
                if sip: ips_to_check.add(sip)
                
                raw_events.append({
                    "id": hit["_id"],
                    "timestamp": src.get("timestamp"),
                    "source_ip": sip,
                    "destination_ip": dip,
                    "tactic": src.get("mitre_tactic", "Unknown"),
                    "severity": src.get("severity", "medium"),
                    "rule_name": src.get("rule_name", "Detection"),
                    "geo": src.get("geoip", {}).get("location", {"lat": 0, "lon": 0})
                })
                
            # 3. Pull threat intel from Redis
            reputations = {}
            if ips_to_check:
                pipe = redis_client.pipeline()
                for ip in ips_to_check:
                    pipe.get(f"ti:{ip}")
                results = await pipe.execute()
                for ip, res in zip(ips_to_check, results):
                    if res:
                        try:
                            reputations[ip] = json.loads(res)
                        except:
                            reputations[ip] = {"malicious": False}
                    else:
                        reputations[ip] = {"malicious": False}

            return {
                "country_risk": country_risk,
                "events": raw_events,
                "reputations": reputations
            }

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
