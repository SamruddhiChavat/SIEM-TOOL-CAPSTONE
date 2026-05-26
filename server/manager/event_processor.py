"""
SecureWatch Manager — Event Processor

Normalizes raw agent events into a unified schema, enriches with
GeoIP and MITRE ATT&CK tags, then indexes into Elasticsearch.
"""

import json
import re
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import httpx
from loguru import logger


# ─── Normalized Event Schema ────────────────────────────────────

def normalize_event(raw: Dict[str, Any], agent_id: str = "", agent_hostname: str = "") -> Dict[str, Any]:
    """
    Convert a raw event from any agent collector into the unified
    SecureWatch event schema for Elasticsearch indexing.
    """
    now = datetime.now(timezone.utc).isoformat()

    normalized = {
        "@timestamp": raw.get("timestamp", now),
        "agent": {
            "id": agent_id or raw.get("agent_id", "unknown"),
            "hostname": agent_hostname or raw.get("hostname", "unknown"),
        },
        "event": {
            "module": raw.get("module", "unknown"),
            "category": classify_event_category(raw),
            "action": raw.get("action", raw.get("event_type", "")),
            "severity": raw.get("severity", "low"),
            "risk_score": int(raw.get("risk_score", 0)),
            "original": json.dumps(raw) if len(json.dumps(raw)) < 8192 else "[truncated]",
        },
        "source": {
            "ip": raw.get("src_ip", raw.get("source_ip", "")),
            "port": raw.get("src_port", 0),
            "user": raw.get("user", raw.get("username", "")),
        },
        "destination": {
            "ip": raw.get("dst_ip", raw.get("dest_ip", "")),
            "port": raw.get("dst_port", 0),
        },
        "process": {
            "name": raw.get("process_name", raw.get("process", "")),
            "pid": raw.get("pid", 0),
            "parent_pid": raw.get("ppid", 0),
            "command_line": raw.get("command_line", raw.get("cmdline", "")),
        },
        "file": {
            "path": raw.get("file_path", raw.get("path", "")),
            "hash": raw.get("file_hash", raw.get("sha256", "")),
            "action": raw.get("file_action", ""),
        },
        "network": {
            "protocol": raw.get("protocol", ""),
            "bytes_sent": raw.get("bytes_sent", 0),
            "bytes_received": raw.get("bytes_recv", 0),
        },
        "rule": {
            "id": raw.get("rule_id", ""),
            "name": raw.get("rule_name", ""),
            "mitre_tactic": raw.get("mitre_tactic", raw.get("mitre.tactic", "")),
            "mitre_technique_id": raw.get("mitre_technique_id", raw.get("mitre.technique_id", "")),
            "mitre_technique_name": raw.get("mitre_technique_name", raw.get("mitre.technique_name", "")),
        },
        "vulnerability": {
            "cve_id": raw.get("cve_id", ""),
            "cvss_score": raw.get("cvss_score", 0),
            "package": raw.get("package", ""),
        },
        "compliance": {
            "framework": raw.get("framework", ""),
            "check_id": raw.get("check_id", ""),
            "result": raw.get("result", ""),
        },
        "tags": raw.get("tags", ["securewatch_event"]),
    }

    # Enrich with MITRE if module provides hints
    if not normalized["rule"]["mitre_tactic"] and normalized["event"]["module"]:
        mitre = infer_mitre_from_module(normalized["event"]["module"], raw)
        normalized["rule"].update(mitre)

    return normalized


def classify_event_category(raw: Dict[str, Any]) -> str:
    """Classify event into a standard category."""
    module = raw.get("module", "").lower()
    event_type = raw.get("event_type", "").lower()

    category_map = {
        "syslog": "system",
        "auth": "authentication",
        "login": "authentication",
        "process": "process",
        "network": "network",
        "fim": "file",
        "file_integrity": "file",
        "vulnerability": "vulnerability",
        "rootkit": "malware",
        "compliance": "compliance",
        "sca": "configuration",
        "windows_event": "system",
        "dns": "network",
        "firewall": "network",
    }

    for key, category in category_map.items():
        if key in module or key in event_type:
            return category

    return "other"


def infer_mitre_from_module(module: str, raw: Dict[str, Any]) -> Dict[str, str]:
    """Infer MITRE ATT&CK tactic from module context if not already tagged."""
    mitre_hints = {
        "rootkit": {"mitre_tactic": "Defense Evasion", "mitre_technique_id": "T1014", "mitre_technique_name": "Rootkit"},
        "fim": {"mitre_tactic": "Impact", "mitre_technique_id": "T1565", "mitre_technique_name": "Data Manipulation"},
        "process": {"mitre_tactic": "Execution", "mitre_technique_id": "T1059", "mitre_technique_name": "Command and Scripting Interpreter"},
        "network": {"mitre_tactic": "Exfiltration", "mitre_technique_id": "T1041", "mitre_technique_name": "Exfiltration Over C2 Channel"},
        "vulnerability": {"mitre_tactic": "Initial Access", "mitre_technique_id": "T1190", "mitre_technique_name": "Exploit Public-Facing Application"},
    }

    for key, mapping in mitre_hints.items():
        if key in module.lower():
            return mapping

    return {"mitre_tactic": "", "mitre_technique_id": "", "mitre_technique_name": ""}


class EventProcessor:
    """Processes, normalizes, and indexes agent events into Elasticsearch."""

    def __init__(self, es_hosts: str = "http://localhost:9200", index_prefix: str = "securewatch"):
        self.es_hosts = es_hosts
        self.index_prefix = index_prefix
        self.buffer: List[Dict[str, Any]] = []
        self.buffer_limit = 500
        self.client = httpx.AsyncClient(timeout=15.0)
        self._total_processed = 0

    async def process_batch(self, events: List[Dict[str, Any]], agent_id: str, agent_hostname: str) -> int:
        """Normalize a batch of raw events and index to Elasticsearch."""
        normalized = []
        for raw in events:
            try:
                event = normalize_event(raw, agent_id, agent_hostname)
                normalized.append(event)
            except Exception as e:
                logger.error(f"Event normalization failed: {e}")

        if normalized:
            await self._bulk_index(normalized)
            self._total_processed += len(normalized)

        return len(normalized)

    async def _bulk_index(self, events: List[Dict[str, Any]]) -> None:
        """Bulk index events into Elasticsearch."""
        if not events:
            return

        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        bulk_body = ""

        for event in events:
            module = event.get("event", {}).get("module", "general")
            index_name = f"{self.index_prefix}-{module}-{today}"
            bulk_body += json.dumps({"index": {"_index": index_name}}) + "\n"
            bulk_body += json.dumps(event) + "\n"

        try:
            resp = await self.client.post(
                f"{self.es_hosts}/_bulk",
                content=bulk_body,
                headers={"Content-Type": "application/x-ndjson"}
            )
            if resp.status_code in (200, 201):
                result = resp.json()
                errors = result.get("errors", False)
                if errors:
                    error_items = [i for i in result.get("items", []) if "error" in i.get("index", {})]
                    logger.warning(f"Bulk index completed with {len(error_items)} errors")
                else:
                    logger.debug(f"Indexed {len(events)} events to Elasticsearch")
            else:
                logger.error(f"Bulk index failed: HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"Elasticsearch connection error: {e}")

    @property
    def total_processed(self) -> int:
        return self._total_processed

    async def close(self) -> None:
        await self.client.aclose()
