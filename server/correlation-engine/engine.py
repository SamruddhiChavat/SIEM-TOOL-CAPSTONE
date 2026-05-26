import time
import json
import os
import logging
import httpx
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from rule_loader import RuleLoader
from state_manager import StateManager
from alert_generator import AlertGenerator
from threat_intel import ThreatIntel
from risk_scorer import RiskScorer
from response_dispatcher import ResponseDispatcher
import psycopg2
from psycopg2.extras import DictCursor
import numpy as np
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

class HealthHandler(BaseHTTPRequestHandler):
    engine_ref = None

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            rules_count = len(self.engine_ref.rules) if self.engine_ref else 0
            last_poll = self.engine_ref.last_poll if self.engine_ref else 0
            
            response = {
                "status": "healthy",
                "rules_loaded": rules_count,
                "last_poll_time": last_poll,
                "uptime": time.time() - self.engine_ref.start_time if self.engine_ref else 0
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run_health_server(engine):
    HealthHandler.engine_ref = engine
    server = HTTPServer(('0.0.0.0', 8001), HealthHandler)
    logger.info("Health server listening on port 8001")
    server.serve_forever()

class CorrelationEngine:
    def __init__(self):
        self.rules = RuleLoader("rules").get_rules()
        self.state_manager = StateManager()
        self.alert_generator = AlertGenerator()
        self.threat_intel = ThreatIntel()
        self.risk_scorer = RiskScorer()
        self.response_dispatcher = ResponseDispatcher()
        
        # ES config
        self.es_host = os.getenv("ELASTICSEARCH_HOSTS", "http://localhost:9200")
        self.es_user = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
        self.es_pass = os.getenv("ELASTICSEARCH_PASSWORD", "")
        self.pg_dsn = "postgresql://siemuser:siempass123!@postgres:5432/siemdb"
        self.last_poll = time.time() - 30 # Start looking 30s in the past
        self.last_behavioral_check = time.time() - 60
        self.start_time = time.time()

    def query_elasticsearch(self):
        """Poll ES for new events marked as siem_detected_event by Logstash"""
        now = time.time()
        
        # Strict mapping to ensure we don't drop events. 
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"tags": "siem_detected_event"}},
                        {"range": {
                            "@timestamp": {
                                "gte": f"now-15s"
                            }
                        }}
                    ]
                }
            },
            "size": 1000
        }

        try:
            resp = httpx.post(
                f"{self.es_host}/siem-logs-*/_search",
                auth=(self.es_user, self.es_pass),
                json=query,
                timeout=10.0
            )
            if resp.status_code == 200:
                hits = resp.json().get("hits", {}).get("hits", [])
                self.last_poll = now
                return [h["_source"] for h in hits]
            else:
                logger.error(f"ES search failed: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            
        return []

    def evaluate_rules(self, event):
        """Matches the single event against loaded YAML rules"""
        for rule in self.rules:
            logic = rule.get("logic", {})
            field = logic.get("field")
            condition = logic.get("condition")
            value = logic.get("value")
            
            # Simple attribute extraction based on dot-notation
            def get_nested(data, key_path):
                keys = key_path.split('.')
                for k in keys:
                    data = data.get(k, {})
                    if not isinstance(data, dict):
                        return data
                return None

            event_val = get_nested(event, field) if field else None
            is_match = False

            if condition == "equals" and event_val == value:
                is_match = True
            elif condition == "exists" and event_val is not None:
                is_match = True
            elif condition == "contains" and event_val and value in str(event_val):
                is_match = True
            elif condition == "threshold":
                # Handle threshold state
                entity_field = get_nested(event, logic.get("group_by", "source_ip"))
                if not entity_field:
                    continue
                    
                threshold = logic.get("threshold", 5)
                window = logic.get("window", 120) # seconds
                import uuid
                unique_event_id = f"{event.get('@timestamp', time.time())}_{uuid.uuid4().hex[:8]}"
                count = self.state_manager.track_event(
                    threshold_key=f"{rule['rule_id']}:{entity_field}",
                    event_id=unique_event_id,
                    window_seconds=window
                )
                if count >= threshold:
                    is_match = True

            if is_match:
                entity_key = get_nested(event, logic.get("group_by", "source_ip")) or "global"
                if self.state_manager.is_suppressed(rule['rule_id'], entity_key):
                    logger.debug(f"Alert suppressed for rule {rule['rule_id']} on {entity_key}")
                    continue
                    
                logger.info(f"Event matched rule {rule['rule_id']}")
                alert = self.alert_generator.create_alert(rule, event, self.state_manager)
                if alert:
                    suppression_window = rule.get("suppression", 900)
                    self.state_manager.suppress_alert(rule['rule_id'], entity_key, timeframe_seconds=suppression_window)
                    self.risk_scorer.update_asset_score(alert)
                    self.response_dispatcher.dispatch(alert)

    def behavioral_detection_loop(self):
        """Runs every 60s to check past 60m of logs vs Behavioral Baselines."""
        now = time.time()
        if now - self.last_behavioral_check < 60:
            return
            
        self.last_behavioral_check = now
        logger.info("Running behavioral anomaly detection pass...")
        
        # Load baselines from DB
        try:
            conn = psycopg2.connect(self.pg_dsn)
            cursor = conn.cursor(cursor_factory=DictCursor)
            cursor.execute("SELECT * FROM behavioral_baselines")
            baselines = cursor.fetchall()
            cursor.close()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to load baselines from PG: {e}")
            return
            
        if not baselines:
            return
            
        # We need recent events from ES (last 60m)
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-60m"
                    }
                }
            },
            "size": 10000
        }
        
        try:
            resp = httpx.post(
                f"{self.es_host}/siem-logs-*/_search",
                auth=(self.es_user, self.es_pass),
                json=query,
                timeout=15.0
            )
            if resp.status_code == 200:
                hits = resp.json().get("hits", {}).get("hits", [])
                events = [h["_source"] for h in hits]
            else:
                return
        except Exception:
            return

        # Check Data Transfer anomalies
        for b in [x for x in baselines if x["dimension"] == "DATA_TRANSFER_MB" and x["host"]]:
            host = b["host"]
            # Sum up network bytes for this host
            vols = [e.get("network", {}).get("bytes", 0) for e in events if e.get("source", {}).get("ip") == host or e.get("source", {}).get("hostname") == host]
            total_mb = sum(vols) / (1024*1024)
            if total_mb > b["p99"] and total_mb > 0:
                self.fire_behavioral_alert(
                    f"BEHAV-002",
                    "Large Outbound Transfer",
                    "Exfiltration", "T1041",
                    "critical", host, None,
                    f"Host {host} transferred {total_mb:.1f} MB in last 60m, exceeding 99th percentile baseline of {b['p99']} MB."
                )

        # Check DNS anomalies
        for b in [x for x in baselines if x["dimension"] == "DNS_QUERY_RATE" and x["host"]]:
            host = b["host"]
            dns_count = len([e for e in events if "dns" in e.get("event", {}).get("category", []) and (e.get("source", {}).get("ip") == host or e.get("source", {}).get("hostname") == host)])
            # Project to a daily rate
            daily_rate = dns_count * 24
            if daily_rate > b["p99"] * 1.5 and dns_count > 10:
                self.fire_behavioral_alert(
                    f"BEHAV-005",
                    "DNS High-Frequency Queries",
                    "Command & Control", "T1071.004",
                    "critical", host, None,
                    f"Host {host} made {dns_count} DNS queries in 1 hour (projected {daily_rate}/day), exceeding baseline {b['p99']}."
                )
                
        # Check Unusual Hours
        hours_b = next((x for x in baselines if x["dimension"] == "WORKING_HOURS_START"), None)
        if hours_b:
            start_h = hours_b["mean"]
            end_h = 19 # Hardcoded for now
            current_hour = datetime.utcnow().hour
            if current_hour < start_h or current_hour > end_h:
                # Any auth success right now is anomalous
                auths = [e for e in events if "authentication" in e.get("event", {}).get("category", []) and e.get("event", {}).get("type") == ["info"]]
                for a in auths:
                    user = a.get("user", {}).get("name", "Unknown")
                    host = a.get("source", {}).get("ip", "Unknown")
                    # Suppress very spammy alerts
                    if not self.state_manager.is_suppressed("BEHAV-001", user):
                        self.fire_behavioral_alert(
                            "BEHAV-001",
                            "Unusual Hours Access",
                            "Initial Access", "T1078",
                            "high", host, user,
                            f"User {user} authenticated at {current_hour}:00, outside normal working hours ({start_h}:00-{end_h}:00)."
                        )

    def fire_behavioral_alert(self, rule_id, name, tactic, technique, severity, host, user, description):
        entity_key = user if user else host
        if self.state_manager.is_suppressed(rule_id, entity_key):
            return
            
        alert_doc = {
            "alert_id": f"ALT-{__import__('uuid').uuid4().hex[:8].upper()}",
            "rule_id": rule_id,
            "rule_name": name,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "severity": severity,
            "entity": entity_key,
            "status": "new",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_event": {"behavioral_anomaly": True, "description": description},
            "recommended_action": "Investigate Anomaly"
        }
        
        try:
            httpx.post(f"http://backend:8000/api/alerts", json=alert_doc, timeout=5.0)
            logger.warning(f"Fired behavioral alert: {name} for {entity_key}")
            self.state_manager.suppress_alert(rule_id, entity_key, timeframe_seconds=3600)
        except Exception as e:
            logger.error(f"Failed to post behavioral alert: {e}")

    def run(self):
        logger.info("Correlation Engine started. Polling every 10 seconds.")
        
        # Start health server in background thread
        health_thread = threading.Thread(target=run_health_server, args=(self,), daemon=True)
        health_thread.start()
        
        while True:
            try:
                events = self.query_elasticsearch()
                if events:
                    logger.info(f"Fetched {len(events)} siem-tagged events for evaluation.")
                    for event in events:
                        self.evaluate_rules(event)
                
                # Behavioral Detection
                self.behavioral_detection_loop()
                
            except Exception as e:
                logger.error(f"Crash in main loop: {e}")
                
            time.sleep(10)  # Poll every 10 seconds for near-real-time detection

if __name__ == "__main__":
    time.sleep(10) # Wait for other services to settle
    engine = CorrelationEngine()
    engine.run()
