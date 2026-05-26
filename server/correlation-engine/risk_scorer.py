import json
import logging
import httpx
import os
import time

logger = logging.getLogger(__name__)

class RiskScorer:
    def __init__(self):
        self.fastapi_url = os.getenv("FASTAPI_URL", "http://backend:8000")

    def update_asset_score(self, alert_doc):
        """Updates and sends risk score to backend when new alert fires"""
        entity = alert_doc.get("entity")
        if not entity or entity == "unknown":
            return

        severity = alert_doc.get("severity", "low")
        weights = {"critical": 40, "high": 25, "medium": 10, "low": 5}
        added_risk = weights.get(severity.lower(), 5)

        # Asset payload
        asset_update = {
            "entity_id": entity,
            "added_risk": added_risk,
            "last_seen_alert": alert_doc.get("alert_id"),
            "mitre_technique_triggered": alert_doc.get("mitre_technique")
        }

        try:
            httpx.post(f"{self.fastapi_url}/api/assets/risk-update", json=asset_update, timeout=5.0)
        except Exception as e:
            logger.error(f"Failed to update asset risk score: {e}")
