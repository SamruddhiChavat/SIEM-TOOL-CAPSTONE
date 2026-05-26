"""
SecureWatch Correlation Engine — Behavioral Baseline

Learns normal behavior per agent over a 7-day rolling window
stored in Redis. Detects deviations from baseline patterns in
login times, process lists, and network peers.
"""

import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import redis
from loguru import logger


class BehavioralBaseline:
    """
    Maintains per-agent behavioral baselines in Redis and flags
    events that deviate from learned patterns.
    """

    BASELINE_TTL = 7 * 24 * 3600  # 7 days

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        try:
            self.redis = redis.from_url(redis_url, decode_responses=True)
            self.redis.ping()
            logger.info("Behavioral baseline connected to Redis")
        except Exception as e:
            logger.warning(f"Redis unavailable for baseline: {e}")
            self.redis = None

    def update_baseline(self, agent_id: str, event: Dict[str, Any]) -> None:
        """Update the behavioral baseline with a new event."""
        if not self.redis:
            return

        module = event.get("module", event.get("event", {}).get("module", ""))

        if "auth" in module or "login" in module or event.get("event_id") in ("4624", "4625"):
            self._update_login_baseline(agent_id, event)
        elif "process" in module:
            self._update_process_baseline(agent_id, event)
        elif "network" in module:
            self._update_network_baseline(agent_id, event)

    def check_deviation(self, agent_id: str, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if an event deviates from the baseline. Returns deviation info or None."""
        if not self.redis:
            return None

        module = event.get("module", event.get("event", {}).get("module", ""))

        if "auth" in module or "login" in module or event.get("event_id") in ("4624", "4625"):
            return self._check_login_deviation(agent_id, event)
        elif "process" in module:
            return self._check_process_deviation(agent_id, event)
        elif "network" in module:
            return self._check_network_deviation(agent_id, event)

        return None

    # ─── Login Baseline ──────────────────────────────────

    def _update_login_baseline(self, agent_id: str, event: Dict[str, Any]) -> None:
        """Track login hours and users."""
        user = event.get("user", event.get("source", {}).get("user", ""))
        if not user:
            return

        hour = datetime.now(timezone.utc).hour
        key = f"baseline:login:{agent_id}"

        try:
            pipe = self.redis.pipeline()
            pipe.hincrby(key, f"hour:{hour}", 1)
            pipe.hincrby(key, f"user:{user}", 1)
            pipe.expire(key, self.BASELINE_TTL)
            pipe.execute()
        except Exception as e:
            logger.debug(f"Baseline update error: {e}")

    def _check_login_deviation(self, agent_id: str, event: Dict[str, Any]) -> Optional[Dict]:
        """Check if login occurs at unusual time or from unusual user."""
        key = f"baseline:login:{agent_id}"
        hour = datetime.now(timezone.utc).hour
        user = event.get("user", event.get("source", {}).get("user", ""))

        try:
            data = self.redis.hgetall(key)
            if not data:
                return None  # No baseline yet

            # Check unusual hour
            hour_count = int(data.get(f"hour:{hour}", 0))
            total_logins = sum(int(v) for k, v in data.items() if k.startswith("hour:"))

            if total_logins > 10 and hour_count == 0:
                return {
                    "type": "abnormal_login_time",
                    "description": f"Login at unusual hour {hour}:00 UTC (never seen in baseline)",
                    "severity": "medium",
                    "agent_id": agent_id,
                    "user": user,
                    "hour": hour,
                }

            # Check first-time user
            if user and int(data.get(f"user:{user}", 0)) == 0 and total_logins > 5:
                return {
                    "type": "first_time_user",
                    "description": f"First login by user '{user}' on this agent",
                    "severity": "medium",
                    "agent_id": agent_id,
                    "user": user,
                }

        except Exception as e:
            logger.debug(f"Baseline check error: {e}")

        return None

    # ─── Process Baseline ────────────────────────────────

    def _update_process_baseline(self, agent_id: str, event: Dict[str, Any]) -> None:
        """Track seen processes per agent."""
        process = event.get("process", event.get("process_name", ""))
        if not process:
            return

        key = f"baseline:process:{agent_id}"
        try:
            self.redis.sadd(key, process)
            self.redis.expire(key, self.BASELINE_TTL)
        except Exception:
            pass

    def _check_process_deviation(self, agent_id: str, event: Dict[str, Any]) -> Optional[Dict]:
        """Check if a never-before-seen process is running."""
        process = event.get("process", event.get("process_name", ""))
        if not process:
            return None

        key = f"baseline:process:{agent_id}"
        try:
            known = self.redis.scard(key)
            if known > 20 and not self.redis.sismember(key, process):
                return {
                    "type": "unknown_process",
                    "description": f"Never-before-seen process '{process}' detected",
                    "severity": "medium",
                    "agent_id": agent_id,
                    "process": process,
                }
        except Exception:
            pass

        return None

    # ─── Network Baseline ────────────────────────────────

    def _update_network_baseline(self, agent_id: str, event: Dict[str, Any]) -> None:
        """Track network peers (destination IPs) per agent."""
        dst_ip = event.get("dest_ip", event.get("destination", {}).get("ip", ""))
        if not dst_ip:
            return

        key = f"baseline:network:{agent_id}"
        try:
            self.redis.sadd(key, dst_ip)
            self.redis.expire(key, self.BASELINE_TTL)
        except Exception:
            pass

    def _check_network_deviation(self, agent_id: str, event: Dict[str, Any]) -> Optional[Dict]:
        """Check if agent is communicating with a never-before-seen IP."""
        dst_ip = event.get("dest_ip", event.get("destination", {}).get("ip", ""))
        if not dst_ip:
            return None

        key = f"baseline:network:{agent_id}"
        try:
            known = self.redis.scard(key)
            if known > 10 and not self.redis.sismember(key, dst_ip):
                return {
                    "type": "unknown_network_peer",
                    "description": f"Communication with new IP {dst_ip} (not in baseline)",
                    "severity": "low",
                    "agent_id": agent_id,
                    "dest_ip": dst_ip,
                }
        except Exception:
            pass

        return None

    def get_baseline_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get a summary of the baseline for an agent."""
        if not self.redis:
            return {}

        try:
            login_data = self.redis.hgetall(f"baseline:login:{agent_id}")
            process_count = self.redis.scard(f"baseline:process:{agent_id}")
            network_count = self.redis.scard(f"baseline:network:{agent_id}")

            login_hours = {k.split(":")[1]: int(v) for k, v in login_data.items() if k.startswith("hour:")}
            login_users = {k.split(":")[1]: int(v) for k, v in login_data.items() if k.startswith("user:")}

            return {
                "agent_id": agent_id,
                "login_hours": login_hours,
                "login_users": login_users,
                "known_processes": process_count,
                "known_network_peers": network_count,
            }
        except Exception:
            return {}
