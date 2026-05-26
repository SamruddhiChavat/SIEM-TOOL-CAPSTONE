import json
import logging
import os
import redis

logger = logging.getLogger(__name__)

class ResponseDispatcher:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.active = True
        except Exception as e:
            logger.error(f"Failed to connect to Redis for Response Dispatcher: {e}")
            self.active = False
            
    def dispatch(self, alert: dict):
        """
        Evaluate alert and dispatch active response playbook if configured.
        """
        if not self.active:
            return
            
        rule_playbook_mapping = {
            "SIEM-001": "PLAYBOOK-001", # Brute Force
            "SIEM-004": "PLAYBOOK-002", # Malware
            "SIEM-005": "PLAYBOOK-003", # Exfiltration
            "SIEM-007": "PLAYBOOK-004", # Insider Threat
            "SIEM-054": "PLAYBOOK-005", # Ransomware (Suspicious file extensions)
            "SIEM-060": "PLAYBOOK-006", # Web Shell
            "SIEM-066": "PLAYBOOK-007", # Privilege Escalation
            "SIEM-068": "PLAYBOOK-008", # Crypto Mining
            "SIEM-070": "PLAYBOOK-009", # Data Destruction Check
        }
        
        rule_id = alert.get("rule", {}).get("id")
        if rule_id in rule_playbook_mapping:
            playbook_id = rule_playbook_mapping[rule_id]
            target = alert.get("agent", {}).get("ip") or alert.get("agent", {}).get("id") or "unknown"
            
            # Additional logic to extract target IP if it's network-based rather than agent-based
            if "source_ip" in alert.get("event", {}):
                target = alert["event"]["source_ip"]
                
            task = {
                "playbook_id": playbook_id,
                "target": target,
                "alert_id": alert.get("id"),
                "rule_id": rule_id
            }
            
            try:
                self.redis_client.rpush("playbook_tasks", json.dumps(task))
                logger.info(f"Dispatched task to playbook_tasks queue: {playbook_id} for target {target}")
            except Exception as e:
                logger.error(f"Failed to dispatch playbook task: {e}")
