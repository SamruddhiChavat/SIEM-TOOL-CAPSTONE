"""
sandbox.py — Attack Sandbox API routes (synced with frontend orgTopology.ts)

Endpoints:
  POST /api/sandbox/simulate   — inject a synthetic attack log into ES and broadcast via WebSocket
  GET  /api/sandbox/topology   — return the live org network topology graph
  GET  /api/sandbox/devices    — return the device list for the C2 dropdown
"""

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid
import random
import os
import httpx
import logging

from services.socket_manager import manager

logger = logging.getLogger(__name__)
router = APIRouter()

ES_HOST: str = os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")
ES_INDEX: str = "siem-logs-sandbox"

# ──────────────────────────────────────────────
# Topology — mirrors frontend orgTopology.ts exactly
# ──────────────────────────────────────────────
TOPOLOGY_NODES: List[Dict[str, Any]] = [
    # Attackers (external)
    {"id": "atk-ru",   "label": "APT-29 (Russia)",    "type": "attacker",    "ip": "185.220.101.34", "os": "Kali Linux",          "dept": "ATTACKER",    "x": 280,  "y": 100, "external": True},
    {"id": "atk-cn",   "label": "APT-41 (China)",      "type": "attacker",    "ip": "203.78.103.11",  "os": "Ubuntu / Custom",     "dept": "ATTACKER",    "x": 900,  "y": 100, "external": True},
    {"id": "internet", "label": "Internet",             "type": "internet",    "ip": "0.0.0.0",        "os": "—",                   "dept": "INTERNET",    "x": 1800, "y": 100, "external": True},
    {"id": "atk-us",   "label": "Rogue Insider",        "type": "attacker",    "ip": "198.51.100.77",  "os": "Windows 10",          "dept": "ATTACKER",    "x": 2700, "y": 100, "external": True},
    {"id": "atk-anon", "label": "Anonymous Botnet",     "type": "attacker",    "ip": "91.108.4.100",   "os": "Linux / Botnet",      "dept": "ATTACKER",    "x": 3320, "y": 100, "external": True},
    # Perimeter
    {"id": "vpn-gw",      "label": "VPN Gateway",      "type": "vpn",         "ip": "10.0.0.2",  "os": "OpenVPN AS 2.11",     "dept": "PERIMETER", "x": 1200, "y": 330},
    {"id": "fw-edge",     "label": "Edge Firewall",     "type": "fw",          "ip": "10.0.0.1",  "os": "FortiGate 100F",      "dept": "PERIMETER", "x": 1800, "y": 330},
    {"id": "fw-dmz",      "label": "DMZ Firewall",      "type": "fw",          "ip": "10.0.0.3",  "os": "pfSense 2.7",         "dept": "PERIMETER", "x": 2400, "y": 330},
    # Core
    {"id": "router-core", "label": "Core Router",       "type": "router",      "ip": "10.0.0.4",  "os": "Cisco IOS 17.x",      "dept": "PERIMETER", "x": 1800, "y": 550},
    # Dept switches
    {"id": "sw-eng",  "label": "Eng Switch",       "type": "switch", "ip": "10.2.0.1", "os": "HP ProCurve 2920",   "dept": "ENGINEERING", "x": 300,  "y": 760},
    {"id": "sw-hr",   "label": "HR Switch",         "type": "switch", "ip": "10.3.0.1", "os": "TP-Link TL-SG3428", "dept": "HR",          "x": 900,  "y": 760},
    {"id": "sw-it",   "label": "IT Switch",         "type": "switch", "ip": "10.1.0.1", "os": "Cisco Catalyst 9300","dept": "IT",          "x": 1500, "y": 760},
    {"id": "sw-fin",  "label": "Finance Switch",    "type": "switch", "ip": "10.4.0.1", "os": "Cisco Catalyst 2960","dept": "FINANCE",     "x": 2200, "y": 760},
    {"id": "sw-exec", "label": "Exec Switch",       "type": "switch", "ip": "10.5.0.1", "os": "Cisco SG350",       "dept": "EXECUTIVE",   "x": 2800, "y": 760},
    {"id": "sw-sec",  "label": "Security Switch",   "type": "switch", "ip": "10.6.0.1", "os": "Cisco Nexus 3000",  "dept": "SECURITY",    "x": 3320, "y": 760},
    # Servers
    {"id": "srv-git",       "label": "GitLab Server",     "type": "server",      "ip": "10.2.0.20",  "os": "Ubuntu 22.04",        "dept": "ENGINEERING", "x": 160,  "y": 980},
    {"id": "srv-build",     "label": "CI/CD Build",        "type": "server",      "ip": "10.2.0.21",  "os": "Rocky Linux 9",       "dept": "ENGINEERING", "x": 440,  "y": 980},
    {"id": "srv-hrdb",      "label": "HR Database",        "type": "server",      "ip": "10.3.0.20",  "os": "PostgreSQL / Ubuntu", "dept": "HR",          "x": 900,  "y": 980},
    {"id": "printer-it",    "label": "IT Printer",         "type": "printer",     "ip": "10.1.0.50",  "os": "Embedded RTOS",       "dept": "IT",          "x": 1180, "y": 980},
    {"id": "srv-ad",        "label": "Active Directory",   "type": "server",      "ip": "10.1.0.10",  "os": "Windows Server 2022", "dept": "IT",          "x": 1380, "y": 980},
    {"id": "srv-dns",       "label": "DNS / DHCP",         "type": "server",      "ip": "10.1.0.11",  "os": "Ubuntu 22.04",        "dept": "IT",          "x": 1560, "y": 980},
    {"id": "srv-mail",      "label": "Mail Server",        "type": "server",      "ip": "10.1.0.12",  "os": "Exchange 2019",       "dept": "IT",          "x": 1740, "y": 980},
    {"id": "nas-backup",    "label": "NAS / Backup",       "type": "nas",         "ip": "10.1.0.30",  "os": "Synology DSM 7",      "dept": "IT",          "x": 1920, "y": 980},
    {"id": "srv-findb",     "label": "Finance DB",         "type": "server",      "ip": "10.4.0.20",  "os": "Oracle DB / RHEL",    "dept": "FINANCE",     "x": 2080, "y": 980},
    {"id": "srv-erp",       "label": "ERP (SAP)",          "type": "server",      "ip": "10.4.0.21",  "os": "SAP on RHEL",         "dept": "FINANCE",     "x": 2320, "y": 980},
    {"id": "siem",          "label": "SecureWatch SIEM",   "type": "siem",        "ip": "10.6.0.10",  "os": "Docker / Linux",      "dept": "SECURITY",    "x": 3200, "y": 980},
    {"id": "edr-samruddhi", "label": "EDR: Samruddhi",    "type": "edr",         "ip": "10.6.0.20",  "os": "CrowdStrike Falcon",  "dept": "SECURITY",    "x": 3380, "y": 980},
    {"id": "edr-corp",      "label": "Corp EDR Agent",     "type": "edr",         "ip": "10.6.0.21",  "os": "SentinelOne",         "dept": "SECURITY",    "x": 3520, "y": 980},
    # Endpoints
    {"id": "ws-jesal",     "label": "Jesal's MacBook",   "type": "workstation", "ip": "10.2.0.101", "os": "macOS Sequoia",        "dept": "ENGINEERING", "x": 120,  "y": 1190},
    {"id": "ws-harsh",     "label": "Harsh's Windows",   "type": "workstation", "ip": "10.2.0.102", "os": "Windows 11",           "dept": "ENGINEERING", "x": 300,  "y": 1190},
    {"id": "ws-nikhita",   "label": "Nikhita's Ubuntu",  "type": "workstation", "ip": "10.2.0.103", "os": "Ubuntu 22.04",         "dept": "ENGINEERING", "x": 480,  "y": 1190},
    {"id": "ws-samruddhi", "label": "Samruddhi's Mac",   "type": "workstation", "ip": "10.3.0.101", "os": "macOS Ventura + EDR",  "dept": "HR",          "x": 740,  "y": 1190},
    {"id": "ws-priya",     "label": "Priya's Windows",   "type": "workstation", "ip": "10.3.0.102", "os": "Windows 10",           "dept": "HR",          "x": 900,  "y": 1190},
    {"id": "ws-rahul",     "label": "Rahul's Windows",   "type": "workstation", "ip": "10.3.0.103", "os": "Windows 10",           "dept": "HR",          "x": 1060, "y": 1190},
    {"id": "ws-kavya",     "label": "Kavya's Windows",   "type": "workstation", "ip": "10.4.0.101", "os": "Windows 11",           "dept": "FINANCE",     "x": 2080, "y": 1190},
    {"id": "ws-arjun",     "label": "Arjun's MacBook",   "type": "workstation", "ip": "10.4.0.102", "os": "macOS Monterey",       "dept": "FINANCE",     "x": 2320, "y": 1190},
    {"id": "ws-ceo",       "label": "CEO's MacBook Pro", "type": "workstation", "ip": "10.5.0.101", "os": "macOS Sonoma",         "dept": "EXECUTIVE",   "x": 2620, "y": 1190},
    {"id": "ws-cto",       "label": "CTO's MacBook",     "type": "workstation", "ip": "10.5.0.102", "os": "macOS Sequoia",        "dept": "EXECUTIVE",   "x": 2800, "y": 1190},
    {"id": "ws-cfo",       "label": "CFO's Windows",     "type": "workstation", "ip": "10.5.0.103", "os": "Windows 11",           "dept": "EXECUTIVE",   "x": 2980, "y": 1190},
]

TOPOLOGY_EDGES: List[Dict[str, str]] = [
    {"source": "atk-ru",      "target": "internet"},
    {"source": "atk-cn",      "target": "internet"},
    {"source": "atk-us",      "target": "internet"},
    {"source": "atk-anon",    "target": "internet"},
    {"source": "internet",    "target": "fw-edge"},
    {"source": "internet",    "target": "vpn-gw"},
    {"source": "internet",    "target": "fw-dmz"},
    {"source": "fw-edge",     "target": "router-core"},
    {"source": "vpn-gw",      "target": "router-core"},
    {"source": "fw-dmz",      "target": "router-core"},
    {"source": "router-core", "target": "sw-eng"},
    {"source": "router-core", "target": "sw-hr"},
    {"source": "router-core", "target": "sw-it"},
    {"source": "router-core", "target": "sw-fin"},
    {"source": "router-core", "target": "sw-exec"},
    {"source": "router-core", "target": "sw-sec"},
    {"source": "sw-eng",  "target": "srv-git"},
    {"source": "sw-eng",  "target": "srv-build"},
    {"source": "sw-eng",  "target": "ws-jesal"},
    {"source": "sw-eng",  "target": "ws-harsh"},
    {"source": "sw-eng",  "target": "ws-nikhita"},
    {"source": "sw-hr",   "target": "srv-hrdb"},
    {"source": "sw-hr",   "target": "ws-samruddhi"},
    {"source": "sw-hr",   "target": "ws-priya"},
    {"source": "sw-hr",   "target": "ws-rahul"},
    {"source": "sw-it",   "target": "printer-it"},
    {"source": "sw-it",   "target": "srv-ad"},
    {"source": "sw-it",   "target": "srv-dns"},
    {"source": "sw-it",   "target": "srv-mail"},
    {"source": "sw-it",   "target": "nas-backup"},
    {"source": "sw-fin",  "target": "srv-findb"},
    {"source": "sw-fin",  "target": "srv-erp"},
    {"source": "sw-fin",  "target": "ws-kavya"},
    {"source": "sw-fin",  "target": "ws-arjun"},
    {"source": "sw-exec", "target": "ws-ceo"},
    {"source": "sw-exec", "target": "ws-cto"},
    {"source": "sw-exec", "target": "ws-cfo"},
    {"source": "sw-sec",  "target": "siem"},
    {"source": "sw-sec",  "target": "edr-samruddhi"},
    {"source": "sw-sec",  "target": "edr-corp"},
]

# ──────────────────────────────────────────────
# MITRE mapping — matches attackDefs.ts id values
# ──────────────────────────────────────────────
ATTACK_META: Dict[str, Dict[str, str]] = {
    "port_scan": {
        "mitre_tactic": "Discovery", "mitre_technique": "T1046",
        "severity": "medium", "rule_id": "NET-007",
    },
    "brute_force": {
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001",
        "severity": "high", "rule_id": "AUTH-003",
    },
    "ddos": {
        "mitre_tactic": "Impact", "mitre_technique": "T1498.001",
        "severity": "critical", "rule_id": "NET-015",
    },
    "sql_injection": {
        "mitre_tactic": "Initial Access", "mitre_technique": "T1190",
        "severity": "critical", "rule_id": "APP-002",
    },
    "file_exfiltration": {
        "mitre_tactic": "Exfiltration", "mitre_technique": "T1041",
        "severity": "critical", "rule_id": "BEHAV-002",
    },
    "lateral_movement": {
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1550.002",
        "severity": "high", "rule_id": "BEHAV-003",
    },
    "dns_c2": {
        "mitre_tactic": "Command & Control", "mitre_technique": "T1071.004",
        "severity": "critical", "rule_id": "BEHAV-005",
    },
    "ransomware": {
        "mitre_tactic": "Impact", "mitre_technique": "T1486",
        "severity": "critical", "rule_id": "MALWARE-001",
    },
    "phishing": {
        "mitre_tactic": "Initial Access", "mitre_technique": "T1566.001",
        "severity": "high", "rule_id": "EMAIL-004",
    },
}

# Dept → switch mapping for path resolution
DEPT_SWITCH: Dict[str, str] = {
    "ENGINEERING": "sw-eng", "HR": "sw-hr", "IT": "sw-it",
    "FINANCE": "sw-fin", "EXECUTIVE": "sw-exec", "SECURITY": "sw-sec",
    "PERIMETER": "fw-edge", "INTERNET": "internet", "ATTACKER": "internet",
}

_NODE_MAP: Dict[str, Dict] = {n["id"]: n for n in TOPOLOGY_NODES}


def _resolve_path(src_id: str, dst_id: str) -> List[str]:
    """Build a realistic hop path through the topology."""
    dst = _NODE_MAP.get(dst_id, {})
    dept = dst.get("dept", "IT")
    sw = DEPT_SWITCH.get(dept, "sw-it")
    return [src_id, "internet", "fw-edge", "router-core", sw, dst_id]


# ──────────────────────────────────────────────
# Pydantic models
# ──────────────────────────────────────────────
class SimulateRequest(BaseModel):
    attack_type:   str = Field(..., description="Attack id from attackDefs.ts (e.g. brute_force, ddos)")
    source_device: str = Field(..., description="Source device node id (attacker)")
    target_device: str = Field(..., description="Target device node id (victim)")
    parameters:    Dict[str, Any] = Field(default_factory=dict)


def _build_es_doc(req: SimulateRequest, alert_id: str, meta: Dict[str, str]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    src = _NODE_MAP.get(req.source_device, {"label": req.source_device, "ip": "0.0.0.0", "os": "Unknown"})
    dst = _NODE_MAP.get(req.target_device, {"label": req.target_device, "ip": "10.0.0.0", "os": "Unknown"})
    p = req.parameters

    attack_name = req.attack_type.replace("_", " ").title()
    msg = f"[{attack_name}] {src['label']} ({src['ip']}) → {dst['label']} ({dst['ip']})"

    if req.attack_type == "file_exfiltration":
        msg = f"Data exfiltration: {src['label']} transferred {p.get('file_size_mb', 600)}MB to {p.get('destination', '185.220.101.34')} via {p.get('protocol', 'HTTPS')}"
    elif req.attack_type == "brute_force":
        msg = f"Brute force: {p.get('attempts', 500)} {p.get('service', 'SSH')} login attempts from {src['ip']} against {dst['label']} ({dst['ip']})"
    elif req.attack_type == "ddos":
        msg = f"DDoS {p.get('attack_type', 'SYN Flood')}: {p.get('bandwidth', 40)}Gbps flood from {p.get('botnet_size', 5000)} botnet nodes against {dst['ip']}"
    elif req.attack_type == "sql_injection":
        msg = f"SQL Injection ({p.get('technique', 'Union-Based')}) on {dst['label']} ({dst['ip']}) endpoint {p.get('endpoint', '/api/login')}"
    elif req.attack_type == "lateral_movement":
        _account = p.get('account', 'CORP\\svc_backup')
        msg = f"Lateral movement (PtH): {src['label']} pivoting to {dst['label']} ({dst['ip']}) via SMB, account {_account}"
    elif req.attack_type == "dns_c2":
        msg = f"DNS C2 tunneling from {dst['label']} ({dst['ip']}) to {p.get('domain', 'c2.evil-corp.net')} at {p.get('query_rate', 50)}qps"
    elif req.attack_type == "ransomware":
        msg = f"Ransomware ({p.get('variant', 'LockBit 3.0')}) deployed on {dst['label']} ({dst['ip']}) — encrypting {p.get('extensions', '*.docx,*.xlsx')}"
    elif req.attack_type == "phishing":
        msg = f"Spear-phishing ({p.get('template', 'IT Password Reset')}) sent to {dst['label']} — payload: {p.get('payload', 'Macro VBA')}"

    return {
        "@timestamp":           now.isoformat(),
        "sandbox.alert_id":     alert_id,
        "sandbox.simulated":    True,
        "event.kind":           "alert",
        "event.category":       ["network"],
        "source.ip":            src["ip"],
        "source.hostname":      src["label"],
        "destination.ip":       dst["ip"],
        "destination.hostname": dst["label"],
        "rule.id":              meta["rule_id"],
        "rule.name":            attack_name,
        "mitre.tactic":         meta["mitre_tactic"],
        "mitre.technique":      meta["mitre_technique"],
        "log.level":            meta["severity"].upper(),
        "message":              msg,
        "host.os.name":         src.get("os", "Unknown"),
        "network.bytes":        random.randint(500_000, 2_000_000_000),
        "network.protocol":     req.parameters.get("protocol", "tcp").lower(),
        "agent.type":           "sandbox-simulator",
        "tags":                 ["sandbox", "simulated", req.attack_type],
    }


async def _index_to_es(doc: Dict[str, Any], alert_id: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{ES_HOST}/{ES_INDEX}/_doc/{alert_id}",
                json=doc, headers={"Content-Type": "application/json"},
            )
            if resp.status_code not in (200, 201):
                logger.warning("ES index failed: %s — %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.error("ES indexing error: %s", exc)


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────
@router.post("/simulate")
async def simulate_attack(req: SimulateRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Inject a synthetic attack into ES and broadcast to all connected SIEM WebSocket clients."""
    meta = ATTACK_META.get(req.attack_type, {
        "mitre_tactic": "Unknown", "mitre_technique": "T0000",
        "severity": "medium", "rule_id": "SANDBOX-000",
    })

    alert_id = str(uuid.uuid4())
    doc      = _build_es_doc(req, alert_id, meta)

    background_tasks.add_task(_index_to_es, doc, alert_id)

    path = _resolve_path(req.source_device, req.target_device)

    ws_payload = {
        "event":         "sandbox_attack",
        "attack_type":   req.attack_type,
        "source_ip":     doc["source.ip"],
        "source_node":   req.source_device,
        "target_ip":     doc["destination.ip"],
        "target_node":   req.target_device,
        "severity":      meta["severity"],
        "technique_id":  meta["mitre_technique"],
        "mitre_tactic":  meta["mitre_tactic"],
        "alert_id":      alert_id,
        "timestamp":     doc["@timestamp"],
        "message":       doc["message"],
        "graph_data":    {"source_node": req.source_device, "target_node": req.target_device, "path": path},
    }
    background_tasks.add_task(manager.broadcast, ws_payload)

    return {
        "status":                 "injected",
        "alert_id":               alert_id,
        "estimated_detection_ms": random.randint(800, 3500),
        "message":                doc["message"],
    }


@router.get("/topology")
async def get_topology() -> Dict[str, Any]:
    return {"nodes": TOPOLOGY_NODES, "edges": TOPOLOGY_EDGES}


@router.get("/devices")
async def get_devices() -> List[Dict[str, Any]]:
    return [
        {"id": n["id"], "label": n["label"], "ip": n["ip"], "os": n["os"],
         "type": n["type"], "dept": n.get("dept", "")}
        for n in TOPOLOGY_NODES
        if n["type"] not in ("internet",) and not n.get("external", False)
    ]
