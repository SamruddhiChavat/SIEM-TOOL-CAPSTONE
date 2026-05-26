import json
import logging
from datetime import datetime
import uuid
import httpx
import os

logger = logging.getLogger(__name__)

class AlertGenerator:
    def __init__(self):
        self.fastapi_url = os.getenv("FASTAPI_URL", "http://backend:8000")
        
    def create_alert(self, rule, event, state_manager):
        """Generates an alert from a matched rule and event"""
        rule_id = rule.get("rule_id", "UNKNOWN-00")
        entity_key = event.get("source_ip", event.get("username", "unknown"))
        
        # Check suppression
        if state_manager and state_manager.is_suppressed(rule_id, entity_key):
            logger.info(f"Alert {rule_id} suppressed for {entity_key}")
            return None

        # Build Alert Object
        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
        severity = rule.get("severity", "medium").lower()
        
        alert_doc = {
            "alert_id": alert_id,
            "rule_id": rule_id,
            "rule_name": rule.get("name", "Unknown Rule"),
            "mitre_tactic": rule.get("mitre_tactic", "Unknown"),
            "mitre_technique": rule.get("mitre_technique", "Unknown"),
            "severity": severity,
            "entity": entity_key,
            "status": "new",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_event": event,
            "recommended_action": rule.get("response_action", "alert_only")
        }

        # Send to Backend API
        try:
            resp = httpx.post(f"{self.fastapi_url}/api/alerts", json=alert_doc, timeout=5.0)
            if resp.status_code in [200, 201]:
                logger.info(f"Successfully generated alert {alert_id} for {rule_id}")
                
                # Apply suppression (default 15 minutes to avoid spam from the exact same condition)
                if state_manager:
                    state_manager.suppress_alert(rule_id, entity_key, 900)
                return alert_doc
            else:
                logger.error(f"Failed to push alert to API: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"Error sending alert to backend: {e}")
            
        return None
