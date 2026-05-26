from fastapi import APIRouter, HTTPException
import httpx
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import statistics

router = APIRouter()

ES_HOST = os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")

# MITRE ATT&CK Tactics (11 core tactics)
MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Impact"
]


def calculate_security_posture(
    critical_count: int,
    high_count: int,
    assets_over_80: int,
    dead_rules: int
) -> Dict[str, Any]:
    """
    Calculate security posture score (0-100).
    - Start: 100 points
    - Each CRITICAL alert: -8 points
    - Each HIGH alert: -4 points
    - Each asset with risk_score > 80: -3 points
    - Each dead rule (0 alerts in 7 days): -1 point
    """
    score = 100
    score -= critical_count * 8
    score -= high_count * 4
    score -= assets_over_80 * 3
    score -= dead_rules * 1
    
    score = max(0, min(100, score))  # Clamp 0-100
    
    # Determine color
    if score >= 80:
        status = "healthy"
        color = "green"
    elif score >= 60:
        status = "fair"
        color = "yellow"
    elif score >= 40:
        status = "degraded"
        color = "orange"
    else:
        status = "critical"
        color = "red"
    
    return {
        "score": score,
        "status": status,
        "color": color,
        "details": {
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "assets_at_risk": assets_over_80,
            "blind_spots": dead_rules
        }
    }


async def get_alert_velocity(client: httpx.AsyncClient, now: datetime) -> Dict[str, Any]:
    """
    Compare current alert rate vs 7-day average for this hour.
    Returns velocity status and ratio.
    """
    past_7d = now - timedelta(days=7)
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    past_hour = current_hour - timedelta(hours=1)
    
    # Current hour alerts
    current_query = {
        "size": 0,
        "query": {
            "range": {
                "timestamp": {
                    "gte": current_hour.isoformat() + "Z",
                    "lte": now.isoformat() + "Z"
                }
            }
        }
    }
    
    # Last 7 days same hour window (e.g., 2-3 PM for last 7 days)
    seven_day_query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": past_7d.isoformat() + "Z"}}}
                ]
            }
        },
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0
                }
            }
        }
    }
    
    try:
        current_res = await client.post(
            f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
            json=current_query
        )
        current_alerts = current_res.json().get("hits", {}).get("total", {}).get("value", 0) if current_res.status_code == 200 else 0
        
        seven_day_res = await client.post(
            f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
            json=seven_day_query
        )
        buckets = seven_day_res.json().get("aggregations", {}).get("by_hour", {}).get("buckets", [])
        
        # Calculate average (excluding current hour)
        hourly_counts = [b["doc_count"] for b in buckets[:-1]]  # Exclude current incomplete hour
        avg_alerts = statistics.mean(hourly_counts) if hourly_counts else 1
        
        ratio = current_alerts / avg_alerts if avg_alerts > 0 else 0
        
        if ratio > 2:
            velocity_status = "spike_detected"
            severity = "critical"
            message = f"🔴 ALERT SPIKE: {ratio:.1f}x normal rate ({current_alerts} alerts/hr vs {avg_alerts:.1f} avg)"
        elif ratio < 0.1 and avg_alerts > 5:  # Only if normally has activity
            velocity_status = "unusually_quiet"
            severity = "warning"
            message = f"🟡 UNUSUALLY QUIET: {ratio:.1f}x normal ({current_alerts} alerts vs {avg_alerts:.1f} expected) - possible detection gap"
        else:
            velocity_status = "normal"
            severity = "info"
            message = f"Normal alert rate: {ratio:.1f}x average"
        
        return {
            "status": velocity_status,
            "severity": severity,
            "message": message,
            "current_rate": current_alerts,
            "average_rate": avg_alerts,
            "ratio": ratio
        }
    except Exception as e:
        return {
            "status": "error",
            "severity": "unknown",
            "message": str(e),
            "current_rate": 0,
            "average_rate": 0,
            "ratio": 0
        }


async def get_mttd_metrics(client: httpx.AsyncClient, now: datetime) -> Dict[str, Any]:
    """
    Calculate Mean Time to Detect (MTTD) for alerts in last 24h.
    MTTD = alert.timestamp - first_raw_event.@timestamp
    """
    past_24h = now - timedelta(hours=24)
    
    query = {
        "size": 100,
        "query": {
            "range": {
                "timestamp": {
                    "gte": past_24h.isoformat() + "Z",
                    "lte": now.isoformat() + "Z"
                }
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}]
    }
    
    try:
        res = await client.post(
            f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
            json=query
        )
        alerts = res.json().get("hits", {}).get("hits", []) if res.status_code == 200 else []
        
        mttd_minutes_list = []
        
        for alert in alerts:
            src = alert["_source"]
            alert_ts = datetime.fromisoformat(src.get("timestamp", "").replace("Z", "+00:00"))
            
            # Try to get raw event timestamp from raw_event_ids (correlate with logs)
            raw_event_id = src.get("raw_event_ids", [None])[0] if src.get("raw_event_ids") else None
            
            if raw_event_id:
                # Query for the raw event
                raw_query = {"query": {"term": {"_id": raw_event_id}}}
                raw_res = await client.post(
                    f"{ES_HOST}/siem-logs-*/_search?ignore_unavailable=true",
                    json=raw_query
                )
                raw_hits = raw_res.json().get("hits", {}).get("hits", [])
                if raw_hits:
                    raw_src = raw_hits[0]["_source"]
                    raw_ts = datetime.fromisoformat(raw_src.get("@timestamp", "").replace("Z", "+00:00"))
                    mttd = (alert_ts - raw_ts).total_seconds() / 60
                    mttd_minutes_list.append(max(0, mttd))
            else:
                # Fallback: assume detection within ~10-15 seconds (engine poll window)
                mttd_minutes_list.append(0.25)  # ~15 seconds
        
        if mttd_minutes_list:
            avg_mttd = statistics.mean(mttd_minutes_list)
            p95_mttd = sorted(mttd_minutes_list)[int(len(mttd_minutes_list) * 0.95)]
        else:
            avg_mttd = 0
            p95_mttd = 0
        
        # Color coding: <5 green, 5-15 yellow, >15 red
        if avg_mttd < 5:
            status = "good"
            color = "green"
        elif avg_mttd < 15:
            status = "acceptable"
            color = "yellow"
        else:
            status = "poor"
            color = "red"
        
        return {
            "average_mttd_minutes": round(avg_mttd, 2),
            "p95_mttd_minutes": round(p95_mttd, 2),
            "status": status,
            "color": color,
            "sample_size": len(mttd_minutes_list)
        }
    except Exception as e:
        return {
            "average_mttd_minutes": 0,
            "p95_mttd_minutes": 0,
            "status": "error",
            "color": "gray",
            "sample_size": 0,
            "error": str(e)
        }


async def get_mttr_metrics(client: httpx.AsyncClient, now: datetime) -> Dict[str, Any]:
    """
    Calculate Mean Time to Respond (MTTR) for closed alerts in last 7 days.
    MTTR = resolved_at - timestamp (in hours)
    """
    past_7d = now - timedelta(days=7)
    
    query = {
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    {"term": {"status.keyword": "closed"}},
                    {"range": {"timestamp": {"gte": past_7d.isoformat() + "Z"}}}
                ]
            }
        }
    }
    
    try:
        res = await client.post(
            f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
            json=query
        )
        alerts = res.json().get("hits", {}).get("hits", []) if res.status_code == 200 else []
        
        mttr_hours_list = []
        
        for alert in alerts:
            src = alert["_source"]
            alert_ts = datetime.fromisoformat(src.get("timestamp", "").replace("Z", "+00:00"))
            resolved_ts_str = src.get("resolved_at") or src.get("updated_at")
            
            if resolved_ts_str:
                resolved_ts = datetime.fromisoformat(resolved_ts_str.replace("Z", "+00:00"))
                mttr = (resolved_ts - alert_ts).total_seconds() / 3600
                mttr_hours_list.append(max(0, mttr))
        
        if mttr_hours_list:
            avg_mttr = statistics.mean(mttr_hours_list)
        else:
            avg_mttr = 0
        
        return {
            "average_mttr_hours": round(avg_mttr, 2),
            "alerts_closed": len(mttr_hours_list),
            "sample_size": len(mttr_hours_list)
        }
    except Exception as e:
        return {
            "average_mttr_hours": 0,
            "alerts_closed": 0,
            "sample_size": 0,
            "error": str(e)
        }


async def get_mitre_coverage(client: httpx.AsyncClient, now: datetime) -> Dict[str, Any]:
    """
    Get MITRE ATT&CK coverage by tactic.
    Cell color = number of DISTINCT rules covering that tactic.
    """
    past_7d = now - timedelta(days=7)
    
    query = {
        "size": 0,
        "query": {
            "range": {
                "timestamp": {
                    "gte": past_7d.isoformat() + "Z",
                    "lte": now.isoformat() + "Z"
                }
            }
        },
        "aggs": {
            "by_tactic": {
                "terms": {"field": "mitre_tactic.keyword", "size": 20},
                "aggs": {
                    "unique_rules": {"cardinality": {"field": "rule_id.keyword"}}
                }
            }
        }
    }
    
    try:
        res = await client.post(
            f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
            json=query
        )
        buckets = res.json().get("aggregations", {}).get("by_tactic", {}).get("buckets", []) if res.status_code == 200 else []
        
        coverage = {}
        for tactic in MITRE_TACTICS:
            bucket = next((b for b in buckets if b["key"] == tactic), None)
            rule_count = bucket["unique_rules"]["value"] if bucket else 0
            
            if rule_count == 0:
                color = "dark_red"
                label = "BLIND SPOT"
            elif rule_count == 1:
                color = "orange"
                label = "LOW"
            elif rule_count <= 3:
                color = "yellow"
                label = "MEDIUM"
            else:
                color = "green"
                label = "GOOD"
            
            coverage[tactic] = {
                "rule_count": rule_count,
                "color": color,
                "label": label
            }
        
        return coverage
    except Exception as e:
        return {t: {"rule_count": 0, "color": "gray", "label": "ERROR"} for t in MITRE_TACTICS}


async def get_alert_noise_ratio(client: httpx.AsyncClient, now: datetime) -> Dict[str, Any]:
    """
    Calculate false positive ratio.
    (False Positives closed this week) / (Total alerts closed this week) * 100
    """
    past_7d = now - timedelta(days=7)
    
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"status.keyword": "closed"}},
                    {"range": {"timestamp": {"gte": past_7d.isoformat() + "Z"}}}
                ]
            }
        },
        "aggs": {
            "by_resolution": {
                "terms": {"field": "resolution_notes.keyword", "size": 10}
            }
        }
    }
    
    try:
        res = await client.post(
            f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
            json=query
        )
        aggs = res.json().get("aggregations", {}) if res.status_code == 200 else {}
        
        total_closed = res.json().get("hits", {}).get("total", {}).get("value", 0)
        
        # Look for false positive indicators in resolution notes
        false_positives = 0
        for bucket in aggs.get("by_resolution", {}).get("buckets", []):
            note = bucket["key"].lower()
            if "false positive" in note or "not a threat" in note or "benign" in note:
                false_positives += bucket["doc_count"]
        
        if total_closed > 0:
            noise_ratio = (false_positives / total_closed) * 100
        else:
            noise_ratio = 0
        
        if noise_ratio > 40:
            status = "too_noisy"
            color = "red"
            recommendation = "Rules need tuning - high false positive rate"
        elif noise_ratio < 15:
            status = "well_tuned"
            color = "green"
            recommendation = "Rules are well-tuned"
        else:
            status = "acceptable"
            color = "yellow"
            recommendation = "Monitor for improvement"
        
        return {
            "false_positive_ratio": round(noise_ratio, 2),
            "total_closed_alerts": total_closed,
            "false_positives_count": false_positives,
            "status": status,
            "color": color,
            "recommendation": recommendation
        }
    except Exception as e:
        return {
            "false_positive_ratio": 0,
            "total_closed_alerts": 0,
            "false_positives_count": 0,
            "status": "error",
            "color": "gray",
            "error": str(e)
        }


async def get_ranked_threats(client: httpx.AsyncClient, now: datetime) -> List[Dict[str, Any]]:
    """
    Get top 10 alerts ranked by urgency score.
    urgency = (severity_weight * 3) + (asset_criticality_weight * 2) + (recency_weight * 1)
    """
    past_24h = now - timedelta(hours=24)
    
    query = {
        "size": 50,
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
    
    try:
        res = await client.post(
            f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
            json=query
        )
        alerts = res.json().get("hits", {}).get("hits", []) if res.status_code == 200 else []
        
        threat_list = []
        
        for alert in alerts:
            src = alert["_source"]
            
            # Severity weight
            severity = src.get("severity", "medium").lower()
            severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2}
            severity_weight = severity_weights.get(severity, 0)
            
            # Asset criticality (from entity risk score if available)
            asset_criticality_weight = src.get("asset_risk_score", 0) / 10
            
            # Recency weight (fresher = higher)
            alert_time = datetime.fromisoformat(src.get("timestamp", "").replace("Z", "+00:00"))
            minutes_ago = (now - alert_time).total_seconds() / 60
            recency_weight = max(0, 10 - (minutes_ago / 10))  # Decays over time
            
            urgency_score = (severity_weight * 3) + (asset_criticality_weight * 2) + (recency_weight * 1)
            
            threat_list.append({
                "alert_id": src.get("alert_id", src.get("id", alert["_id"])),
                "rule_name": src.get("rule_name", "Unknown"),
                "severity": severity,
                "source_ip": src.get("source_ip", "Unknown"),
                "entity": src.get("entity", "Unknown"),
                "mitre_tactic": src.get("mitre_tactic", "Unknown"),
                "timestamp": src.get("timestamp", ""),
                "urgency_score": round(urgency_score, 2),
                "status": src.get("status", "open")
            })
        
        # Sort by urgency score
        threat_list.sort(key=lambda x: x["urgency_score"], reverse=True)
        
        return threat_list[:10]  # Top 10
    except Exception as e:
        return []


@router.get("/summary")
async def get_dashboard_summary():
    """Complete SOC dashboard with all metrics."""
    now = datetime.utcnow()
    past_24h = now - timedelta(hours=24)
    past_7d = now - timedelta(days=7)
    yesterday = now - timedelta(hours=24)
    
    async with httpx.AsyncClient() as client:
        try:
            # Basic alerts query
            alerts_query = {
                "size": 50,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": past_24h.isoformat() + "Z",
                            "lte": now.isoformat() + "Z"
                        }
                    }
                },
                "aggs": {
                    "severities": {"terms": {"field": "severity.keyword"}},
                    "active_status": {
                        "filter": {"terms": {"status.keyword": ["new", "investigating", "open"]}}
                    },
                    "high_risk_assets": {
                        "filter": {"range": {"asset_risk_score": {"gte": 80}}}
                    }
                }
            }
            
            alerts_res = await client.post(
                f"{ES_HOST}/siem-alerts-*/_search?ignore_unavailable=true",
                json=alerts_query
            )
            alerts_data = alerts_res.json() if alerts_res.status_code == 200 else {}
            aggs = alerts_data.get("aggregations", {})
            
            severities = {b["key"].lower(): b["doc_count"] for b in aggs.get("severities", {}).get("buckets", [])}
            critical_count = severities.get("critical", 0)
            high_count = severities.get("high", 0)
            active_alerts = aggs.get("active_status", {}).get("doc_count", 0)
            high_risk_assets = aggs.get("high_risk_assets", {}).get("doc_count", 0)
            
            # Total events
            logs_res = await client.post(
                f"{ES_HOST}/siem-logs-*/_count?ignore_unavailable=true",
                json={"query": {"range": {"@timestamp": {"gte": past_24h.isoformat() + "Z"}}}}
            )
            total_events_24h = logs_res.json().get("count", 0) if logs_res.status_code == 200 else 0
            
            # Dead rules (rules with 0 alerts in 7 days) - estimate as 5% of total rules (72 * 0.05 = ~3)
            dead_rules = 3  # Placeholder
            
            # Calculate security posture
            posture = calculate_security_posture(critical_count, high_count, high_risk_assets, dead_rules)
            
            # Get all enhanced metrics
            velocity = await get_alert_velocity(client, now)
            mttd = await get_mttd_metrics(client, now)
            mttr = await get_mttr_metrics(client, now)
            coverage = await get_mitre_coverage(client, now)
            noise = await get_alert_noise_ratio(client, now)
            ranked_threats = await get_ranked_threats(client, now)
            
            # Events per hour
            histo_query = {
                "size": 0,
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": past_24h.isoformat() + "Z",
                            "lte": now.isoformat() + "Z"
                        }
                    }
                },
                "aggs": {
                    "events_per_hour": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1h"
                        }
                    }
                }
            }
            histo_res = await client.post(
                f"{ES_HOST}/siem-logs-*/_search?ignore_unavailable=true",
                json=histo_query
            )
            histo_buckets = histo_res.json().get("aggregations", {}).get("events_per_hour", {}).get("buckets", []) if histo_res.status_code == 200 else []
            events_per_hour = [{"hour": b["key_as_string"][:13], "count": b["doc_count"]} for b in histo_buckets][-24:]
            
            return {
                "timestamp": now.isoformat() + "Z",
                "total_events_24h": total_events_24h,
                "active_alerts": active_alerts,
                "critical_count": critical_count,
                "high_count": high_count,
                "assets_at_risk": high_risk_assets,
                "security_posture": posture,
                "alert_velocity": velocity,
                "mttd": mttd,
                "mttr": mttr,
                "mitre_coverage": coverage,
                "alert_noise_ratio": noise,
                "top_threats": ranked_threats,
                "events_per_hour": events_per_hour
            }
        
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
