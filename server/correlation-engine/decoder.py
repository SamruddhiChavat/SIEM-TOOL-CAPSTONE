"""
SecureWatch Correlation Engine — Log Decoder

Parses raw log formats (syslog, Windows XML events, JSON beats,
CEF) into the normalized SecureWatch event schema. This is the
first stage of the event processing pipeline.
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from loguru import logger


# ─── Syslog RFC 3164 / 5424 Parser ──────────────────────────────

SYSLOG_3164_PATTERN = re.compile(
    r'^<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+(?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)'
)

SYSLOG_5424_PATTERN = re.compile(
    r'^<(?P<priority>\d+)>\d+\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+'
    r'(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s*'
    r'(?:\[(?P<structured_data>[^\]]*)\])?\s*(?P<message>.*)'
)

# ─── Windows Event XML Parser ───────────────────────────────────

WINDOWS_EVENT_FIELDS = re.compile(
    r'<Data Name="(?P<name>[^"]+)">(?P<value>[^<]*)</Data>'
)

# ─── CEF Parser (Common Event Format) ───────────────────────────

CEF_PATTERN = re.compile(
    r'CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|'
    r'(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extensions>.*)'
)


class Decoder:
    """
    Multi-format log decoder. Detects format automatically and
    normalizes into a consistent event dictionary.
    """

    def decode(self, raw: str) -> Optional[Dict[str, Any]]:
        """
        Decode a raw log line into a normalized event dict.
        Auto-detects format: JSON, syslog, Windows XML, CEF.
        Returns None if decoding fails.
        """
        if not raw or not raw.strip():
            return None

        raw = raw.strip()

        # Try JSON first (beats, agent JSON)
        if raw.startswith("{"):
            return self._decode_json(raw)

        # Try CEF
        if "CEF:" in raw[:20]:
            return self._decode_cef(raw)

        # Try Windows XML
        if "<Event" in raw or "<EventData>" in raw:
            return self._decode_windows_xml(raw)

        # Try syslog
        if raw.startswith("<"):
            return self._decode_syslog(raw)

        # Fallback: treat as plain text
        return self._decode_plaintext(raw)

    def decode_batch(self, raw_lines: List[str]) -> List[Dict[str, Any]]:
        """Decode multiple raw log lines."""
        results = []
        for line in raw_lines:
            decoded = self.decode(line)
            if decoded:
                results.append(decoded)
        return results

    # ─── Format-Specific Decoders ────────────────────────

    def _decode_json(self, raw: str) -> Optional[Dict[str, Any]]:
        """Decode JSON-formatted events (Beats, agent output)."""
        try:
            data = json.loads(raw)
            return {
                "@timestamp": data.get("@timestamp", data.get("timestamp", datetime.now(timezone.utc).isoformat())),
                "source_ip": data.get("source", {}).get("ip", data.get("src_ip", "")),
                "dest_ip": data.get("destination", {}).get("ip", data.get("dst_ip", "")),
                "user": data.get("user", {}).get("name", data.get("user", "")),
                "hostname": data.get("host", {}).get("name", data.get("hostname", "")),
                "process": data.get("process", {}).get("name", data.get("process_name", "")),
                "pid": data.get("process", {}).get("pid", data.get("pid", 0)),
                "event_id": str(data.get("event", {}).get("code", data.get("event_id", ""))),
                "event_action": data.get("event", {}).get("action", data.get("action", "")),
                "message": data.get("message", ""),
                "module": data.get("event", {}).get("module", data.get("module", "json")),
                "severity": data.get("event", {}).get("severity", data.get("severity", "info")),
                "raw": raw,
                "decoder": "json",
                "tags": data.get("tags", []),
                "_original": data,
            }
        except json.JSONDecodeError:
            return None

    def _decode_syslog(self, raw: str) -> Optional[Dict[str, Any]]:
        """Decode syslog RFC 3164 or 5424 messages."""
        # Try RFC 5424 first
        match = SYSLOG_5424_PATTERN.match(raw)
        if match:
            d = match.groupdict()
            return {
                "@timestamp": d.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "hostname": d.get("hostname", ""),
                "process": d.get("app_name", ""),
                "pid": int(d.get("proc_id", 0)) if d.get("proc_id", "").isdigit() else 0,
                "message": d.get("message", ""),
                "module": "syslog",
                "severity": self._syslog_severity(int(d.get("priority", 14))),
                "event_id": d.get("msg_id", ""),
                "source_ip": self._extract_ip(d.get("message", "")),
                "user": self._extract_user(d.get("message", "")),
                "decoder": "syslog_5424",
                "raw": raw,
                "tags": ["syslog"],
            }

        # Try RFC 3164
        match = SYSLOG_3164_PATTERN.match(raw)
        if match:
            d = match.groupdict()
            return {
                "@timestamp": self._parse_syslog_timestamp(d.get("timestamp", "")),
                "hostname": d.get("hostname", ""),
                "process": d.get("program", ""),
                "pid": int(d.get("pid", 0)) if d.get("pid", "").isdigit() else 0,
                "message": d.get("message", ""),
                "module": "syslog",
                "severity": self._syslog_severity(int(d.get("priority", 14))),
                "source_ip": self._extract_ip(d.get("message", "")),
                "user": self._extract_user(d.get("message", "")),
                "decoder": "syslog_3164",
                "raw": raw,
                "tags": ["syslog"],
            }

        return None

    def _decode_windows_xml(self, raw: str) -> Optional[Dict[str, Any]]:
        """Decode Windows Event Log XML format."""
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "module": "windows_event",
            "decoder": "windows_xml",
            "raw": raw,
            "tags": ["windows"],
        }

        # Extract EventID
        eid_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', raw)
        if eid_match:
            event["event_id"] = eid_match.group(1)

        # Extract TimeCreated
        time_match = re.search(r'SystemTime="([^"]+)"', raw)
        if time_match:
            event["@timestamp"] = time_match.group(1)

        # Extract Computer
        comp_match = re.search(r'<Computer>([^<]+)</Computer>', raw)
        if comp_match:
            event["hostname"] = comp_match.group(1)

        # Extract Channel
        chan_match = re.search(r'<Channel>([^<]+)</Channel>', raw)
        if chan_match:
            event["channel"] = chan_match.group(1)

        # Extract all Data Name fields
        data_fields = {}
        for m in WINDOWS_EVENT_FIELDS.finditer(raw):
            data_fields[m.group("name")] = m.group("value")

        event["source_ip"] = data_fields.get("IpAddress", data_fields.get("SourceAddress", ""))
        event["user"] = data_fields.get("TargetUserName", data_fields.get("SubjectUserName", ""))
        event["process"] = data_fields.get("ProcessName", data_fields.get("NewProcessName", ""))
        event["message"] = data_fields.get("Message", str(data_fields))
        event["severity"] = self._windows_severity(event.get("event_id", ""))
        event["_data_fields"] = data_fields

        return event

    def _decode_cef(self, raw: str) -> Optional[Dict[str, Any]]:
        """Decode Common Event Format (CEF) messages."""
        match = CEF_PATTERN.search(raw)
        if not match:
            return None

        d = match.groupdict()
        extensions = self._parse_cef_extensions(d.get("extensions", ""))

        return {
            "@timestamp": extensions.get("rt", extensions.get("end", datetime.now(timezone.utc).isoformat())),
            "source_ip": extensions.get("src", ""),
            "dest_ip": extensions.get("dst", ""),
            "source_port": int(extensions.get("spt", 0)),
            "dest_port": int(extensions.get("dpt", 0)),
            "user": extensions.get("suser", extensions.get("duser", "")),
            "message": d.get("name", ""),
            "module": f"cef_{d.get('vendor', 'unknown').lower()}",
            "severity": self._cef_severity(d.get("severity", "5")),
            "event_id": d.get("sig_id", ""),
            "hostname": extensions.get("dhost", extensions.get("shost", "")),
            "process": extensions.get("app", ""),
            "decoder": "cef",
            "raw": raw,
            "tags": ["cef", d.get("vendor", "").lower()],
            "_extensions": extensions,
        }

    def _decode_plaintext(self, raw: str) -> Dict[str, Any]:
        """Fallback decoder for unrecognized formats."""
        return {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "message": raw,
            "module": "unknown",
            "severity": "info",
            "source_ip": self._extract_ip(raw),
            "user": self._extract_user(raw),
            "decoder": "plaintext",
            "raw": raw,
            "tags": ["unclassified"],
        }

    # ─── Helpers ─────────────────────────────────────────

    @staticmethod
    def _syslog_severity(priority: int) -> str:
        """Map syslog priority to severity label."""
        severity = priority % 8
        severity_map = {
            0: "critical",  # Emergency
            1: "critical",  # Alert
            2: "critical",  # Critical
            3: "high",      # Error
            4: "medium",    # Warning
            5: "low",       # Notice
            6: "info",      # Informational
            7: "info",      # Debug
        }
        return severity_map.get(severity, "info")

    @staticmethod
    def _windows_severity(event_id: str) -> str:
        """Map Windows event IDs to severity levels."""
        critical_ids = {"4625", "4648", "4672", "4720", "4732", "4698", "1102", "7045"}
        high_ids = {"4688", "4768", "4769", "4771", "4776"}
        if event_id in critical_ids:
            return "high"
        if event_id in high_ids:
            return "medium"
        return "low"

    @staticmethod
    def _cef_severity(severity_str: str) -> str:
        """Map CEF severity (0-10) to label."""
        try:
            sev = int(severity_str)
        except ValueError:
            return "info"
        if sev >= 9:
            return "critical"
        if sev >= 7:
            return "high"
        if sev >= 4:
            return "medium"
        return "low"

    @staticmethod
    def _extract_ip(text: str) -> str:
        """Extract first IPv4 address from text."""
        match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        return match.group(1) if match else ""

    @staticmethod
    def _extract_user(text: str) -> str:
        """Extract username from common log patterns."""
        patterns = [
            r'user[=\s]+(\S+)',
            r'User\s+(\S+)',
            r'for\s+(\S+)',
            r'session\s+\w+\s+for\s+user\s+(\S+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                user = match.group(1).strip("'\"")
                if user and user not in ("invalid", "unknown", "root"):
                    return user
        return ""

    @staticmethod
    def _parse_syslog_timestamp(ts: str) -> str:
        """Parse syslog RFC 3164 timestamp to ISO format."""
        try:
            now = datetime.now(timezone.utc)
            dt = datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_cef_extensions(ext_str: str) -> Dict[str, str]:
        """Parse CEF extension key=value pairs."""
        extensions = {}
        # CEF extensions are space-delimited key=value, values can contain spaces
        parts = re.findall(r'(\w+)=((?:[^ =]| (?!\w+=))*)', ext_str)
        for key, value in parts:
            extensions[key] = value.strip()
        return extensions
