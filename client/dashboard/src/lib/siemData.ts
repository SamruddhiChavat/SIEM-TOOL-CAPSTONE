// Mock SIEM data store + helpers
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type IncidentStatus = "New" | "Investigating" | "Contained" | "Resolved";
export type AlertStatus = "New" | "Investigating" | "Resolved";

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "hsl(var(--sev-critical))",
  high: "hsl(var(--sev-high))",
  medium: "hsl(var(--sev-medium))",
  low: "hsl(var(--sev-low))",
  info: "hsl(var(--sev-info))",
};

// ─────────────────────────────────────────────────────────────
// ASSETS — mirrors orgTopology.ts exactly (IPs must match for SOC sync)
// ─────────────────────────────────────────────────────────────
export const ASSETS = [
  // ── Engineering Dept (sw-eng: 10.2.0.x) ─────────────────
  { id: "ws-jesal",     hostname: "Jesal's MacBook",     ip: "10.2.0.101", os: "macOS Sequoia",        type: "laptop",   dept: "Engineering", status: "online", alerts: 0 },
  { id: "ws-harsh",     hostname: "Harsh's Windows",     ip: "10.2.0.102", os: "Windows 11",           type: "desktop",  dept: "Engineering", status: "online", alerts: 0 },
  { id: "ws-arjuna",    hostname: "Arjuna Desktop",      ip: "10.2.0.103", os: "Linux Mint",           type: "desktop",  dept: "Engineering", status: "online", alerts: 0 },
  { id: "srv-git",      hostname: "GitLab Server",       ip: "10.2.0.20",  os: "Ubuntu 22.04",         type: "server",   dept: "Engineering", status: "online", alerts: 0 },
  // ── IT & Exec Dept (sw-it: 10.1.0.x) ────────────────────
  { id: "ws-ceo",       hostname: "CEO's MacBook Pro",   ip: "10.1.0.101", os: "macOS Sonoma",         type: "laptop",   dept: "IT",          status: "online", alerts: 0 },
  { id: "ws-nikhiti",   hostname: "Nikhiti's Windows",   ip: "10.1.0.102", os: "Windows 11",           type: "desktop",  dept: "IT",          status: "online", alerts: 0 },
  { id: "ws-samruddhi", hostname: "Samruddhi's MacBook", ip: "10.1.0.103", os: "macOS Sonoma",         type: "laptop",   dept: "IT",          status: "online", alerts: 0 },
  { id: "srv-ad",       hostname: "Active Directory",    ip: "10.1.0.10",  os: "Windows Server 2022",  type: "server",   dept: "IT",          status: "online", alerts: 0 },
  { id: "srv-dns",      hostname: "DNS / DHCP",          ip: "10.1.0.11",  os: "Ubuntu 22.04",         type: "server",   dept: "IT",          status: "online", alerts: 0 },
  { id: "srv-mail",     hostname: "Mail Server",         ip: "10.1.0.12",  os: "Exchange 2019",        type: "server",   dept: "IT",          status: "online", alerts: 0 },
  { id: "nas-backup",   hostname: "NAS / Backup",        ip: "10.1.0.30",  os: "Synology DSM 7",       type: "server",   dept: "IT",          status: "online", alerts: 0 },
  { id: "printer-it",   hostname: "IT Printer",          ip: "10.1.0.50",  os: "Embedded RTOS",        type: "server",   dept: "IT",          status: "online", alerts: 0 },
  // ── Security / SOC (sw-sec: 10.6.0.x) ───────────────────
  { id: "siem",         hostname: "SecureWatch SIEM",    ip: "10.6.0.10",  os: "Docker / Linux",       type: "siem",     dept: "Security",    status: "online", alerts: 0 },
  { id: "edr-corp",     hostname: "Corp EDR Agent",      ip: "10.6.0.21",  os: "SentinelOne",          type: "server",   dept: "Security",    status: "online", alerts: 0 },
  // ── Perimeter / Network ───────────────────────────────────
  { id: "fw-edge",      hostname: "Edge Firewall",       ip: "10.0.0.1",   os: "FortiGate 100F",       type: "firewall", dept: "Perimeter",   status: "online", alerts: 0 },
  { id: "router-core",  hostname: "Core Router",         ip: "10.0.0.4",   os: "Cisco IOS 17.x",       type: "router",   dept: "Perimeter",   status: "online", alerts: 0 },
];

export const COUNTRIES = [
  { code: "RU", name: "Russia",       lat: 60, lng: 90,  flag: "🇷🇺" },
  { code: "CN", name: "China",        lat: 35, lng: 105, flag: "🇨🇳" },
  { code: "KP", name: "North Korea",  lat: 40, lng: 127, flag: "🇰🇵" },
  { code: "RO", name: "Romania",      lat: 46, lng: 25,  flag: "🇷🇴" },
  { code: "BR", name: "Brazil",       lat: -10, lng: -55, flag: "🇧🇷" },
  { code: "NG", name: "Nigeria",      lat: 9,  lng: 8,   flag: "🇳🇬" },
  { code: "US", name: "United States",lat: 39, lng: -98, flag: "🇺🇸" },
  { code: "DE", name: "Germany",      lat: 51, lng: 10,  flag: "🇩🇪" },
];

export const TARGET = { name: "India", lat: 22, lng: 78 };

const ATTACK_TYPES = ["Brute Force", "SQL Injection", "Port Scan", "DDoS", "Lateral Movement", "C2 Beacon", "Phishing", "Malware Drop", "Credential Stuffing"];
const EVENT_TYPES = ["auth.login.failed", "auth.login.success", "net.conn.blocked", "net.scan.detected", "edr.process.suspicious", "edr.file.encrypted", "dns.query.suspicious", "ids.alert", "fw.deny", "ad.priv.escalation"];

export function randomIp(external = false) {
  if (external) {
    const ranges = [[192,0,2],[198,51,100],[203,0,113]];
    const r = ranges[Math.floor(Math.random()*ranges.length)];
    return `${r[0]}.${r[1]}.${r[2]}.${Math.floor(Math.random()*254)+1}`;
  }
  return `192.168.1.${Math.floor(Math.random()*254)+1}`;
}

export function randomSeverity(): Severity {
  const r = Math.random();
  if (r < 0.08) return "critical";
  if (r < 0.25) return "high";
  if (r < 0.55) return "medium";
  if (r < 0.85) return "low";
  return "info";
}

export function pickAsset() {
  return ASSETS[Math.floor(Math.random() * ASSETS.length)];
}

export function pickCountry() {
  return COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)];
}

export function pickAttackType() {
  return ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
}

export function pickEventType() {
  return EVENT_TYPES[Math.floor(Math.random() * EVENT_TYPES.length)];
}

export interface LogEntry {
  id: string;
  ts: number;
  severity: Severity;
  host: string;
  eventId: string;
  message: string;
  srcIp: string;
  dstIp: string;
  format: "syslog" | "json" | "cef" | "winevt";
  raw: string;
}

let _logId = 0;
export function makeLog(): LogEntry {
  _logId++;
  const sev = randomSeverity();
  const asset = pickAsset();
  const src = Math.random() < 0.6 ? randomIp(true) : randomIp();
  const dst = asset.ip;
  const evt = pickEventType();
  const eventId = `EVT-${4000 + Math.floor(Math.random() * 5999)}`;
  const ts = Date.now();
  const formats: LogEntry["format"][] = ["syslog", "json", "cef", "winevt"];
  const fmt = formats[Math.floor(Math.random() * formats.length)];
  const msg = `${evt} on ${asset.hostname} from ${src}`;
  let raw = "";
  if (fmt === "syslog") {
    raw = `<${130 + Math.floor(Math.random()*20)}>${new Date(ts).toISOString()} ${asset.hostname.replace(/\s+/g,"-")} securewatch[${1000+_logId}]: ${evt} src=${src} dst=${dst} severity=${sev} eventid=${eventId}`;
  } else if (fmt === "json") {
    raw = JSON.stringify({ ts: new Date(ts).toISOString(), host: asset.hostname, event: evt, src_ip: src, dst_ip: dst, severity: sev, event_id: eventId, message: msg });
  } else if (fmt === "cef") {
    raw = `CEF:0|Secure Watch|SIEM|2.1|${eventId}|${evt}|${sev === "critical" ? 10 : sev === "high" ? 8 : sev === "medium" ? 5 : 3}|src=${src} dst=${dst} dhost=${asset.hostname} act=${Math.random()<0.5?"blocked":"detected"}`;
  } else {
    raw = `EventID=${eventId} Channel=Security TimeCreated=${new Date(ts).toISOString()} Computer=${asset.hostname} SourceIP=${src} DestIP=${dst} Severity=${sev} Message="${msg}"`;
  }
  return { id: `L${_logId}`, ts, severity: sev, host: asset.hostname, eventId, message: msg, srcIp: src, dstIp: dst, format: fmt, raw };
}

export interface AlertEntry {
  id: string;
  ts: number;
  title: string;
  severity: Severity;
  src: string;
  dst: string;
  status: AlertStatus;
  rule: string;
  rawLog: string;
  recommendation: string;
}

const RULES = [
  "Brute Force SSH Detected", "Impossible Travel Login", "C2 Beacon Pattern",
  "Data Exfiltration Volume Threshold", "Ransomware File Rename Pattern",
  "PowerShell Encoded Command", "DNS Tunneling Detection", "Lateral Movement SMB",
  "Credential Dump LSASS", "Privilege Escalation UAC Bypass"
];

let _alertId = 0;
export function makeAlert(): AlertEntry {
  _alertId++;
  const asset = pickAsset();
  const src = randomIp(true);
  const sev = randomSeverity();
  const rule = RULES[Math.floor(Math.random()*RULES.length)];
  return {
    id: `INC-${10240 + _alertId}`,
    ts: Date.now(),
    title: rule,
    severity: sev,
    src,
    dst: asset.hostname,
    status: "New",
    rule,
    rawLog: makeLog().raw,
    recommendation: sev === "critical" || sev === "high"
      ? `Isolate ${asset.hostname} immediately and block source ${src}.`
      : `Investigate logs around this event and verify with the user.`,
  };
}

export const SEED_ALERTS: AlertEntry[] = Array.from({ length: 14 }, () => {
  const a = makeAlert();
  a.ts = Date.now() - Math.floor(Math.random() * 1000 * 60 * 60 * 6);
  a.status = (["New","Investigating","Resolved"] as AlertStatus[])[Math.floor(Math.random()*3)];
  return a;
}).sort((a,b) => b.ts - a.ts);

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  assignee: string;
  affected: number;
  created: number;
  updated: number;
  description: string;
  attackVector: string;
  mitre: string;
  affectedHosts: string[];
}

const ANALYSTS = ["Jesal Pavaskar", "Samruddhi Rao", "Harsh Mehta", "Nikhita Sharma", "Arjuna Patel"];
export const INCIDENTS: Incident[] = Array.from({ length: 22 }, (_, i) => {
  const sev = randomSeverity();
  const statuses: IncidentStatus[] = ["New", "Investigating", "Contained", "Resolved"];
  const created = Date.now() - Math.floor(Math.random() * 1000 * 60 * 60 * 24 * 5);
  const hosts = Array.from({ length: 1 + Math.floor(Math.random()*3) }, () => pickAsset().hostname);
  return {
    id: `INC-${10000 + i}`,
    title: RULES[i % RULES.length] + ` on ${hosts[0]}`,
    severity: sev,
    status: statuses[Math.floor(Math.random()*statuses.length)],
    assignee: ANALYSTS[Math.floor(Math.random()*ANALYSTS.length)],
    affected: hosts.length,
    created,
    updated: created + Math.floor(Math.random()*1000*60*120),
    description: `Detection rule "${RULES[i % RULES.length]}" matched ${5 + Math.floor(Math.random()*40)} events. Investigation required.`,
    attackVector: ["Network", "Endpoint", "Identity", "Email"][Math.floor(Math.random()*4)],
    mitre: ["T1110 Brute Force", "T1059 Command Execution", "T1071 C2 Channel", "T1486 Data Encrypted for Impact", "T1078 Valid Accounts"][i % 5],
    affectedHosts: hosts,
  };
});

export type RuleCondition = {
  id: number;
  field: string;
  operator: string;
  value: string;
};

export type RuleAction = {
  key: string;
  label: string;
  enabled: boolean;
};

export interface RuleDef {
  id: string;
  name: string;
  category: "Authentication" | "Network" | "Endpoint" | "Malware" | "Insider Threat";
  severity: Severity;
  enabled: boolean;
  triggers7d: number;
  lastTriggered: number;
  description: string;
  mitreTactic: string;
  mitreId: string;
  matchType: "ALL" | "ANY" | "SEQUENCE";
  conditions: RuleCondition[];
  threshold: number;
  timeframe: number;
  timeUnit: "seconds" | "minutes" | "hours";
  groupBy: string;
  actions: RuleAction[];
}

export const RULES_LIB: RuleDef[] = [
  {
    id: "R001", name: "Port Scan Sweep (Nmap)",
    category: "Network", severity: "medium", enabled: true,
    triggers7d: 78, lastTriggered: Date.now()-1000*60*4,
    mitreTactic: "Discovery", mitreId: "T1046",
    description: "Detects a single source IP rapidly probing 20+ distinct ports on internal hosts — a classic Nmap reconnaissance sweep before exploitation.",
    matchType: "ALL",
    conditions: [
      { id: 1, field: "Event ID / Action", operator: "contains",        value: "net.scan.detected" },
      { id: 2, field: "Destination Port",  operator: "is greater than", value: "20" },
    ],
    threshold: 50, timeframe: 60, timeUnit: "seconds", groupBy: "Source IP",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: false },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: false },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: true  },
    ],
  },
  {
    id: "R002", name: "Brute Force (SSH/RDP)",
    category: "Authentication", severity: "high", enabled: true,
    triggers7d: 142, lastTriggered: Date.now()-1000*60*8,
    mitreTactic: "Credential Access", mitreId: "T1110.001",
    description: "Fires when 50+ authentication failures originate from the same source IP within 5 minutes, indicating a credential stuffing or dictionary attack.",
    matchType: "ALL",
    conditions: [
      { id: 1, field: "Event ID / Action", operator: "contains", value: "auth.login.failed" },
      { id: 2, field: "Event Severity",    operator: "equals",   value: "high" },
    ],
    threshold: 50, timeframe: 5, timeUnit: "minutes", groupBy: "Source IP",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: true  },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: false },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: true  },
    ],
  },
  {
    id: "R003", name: "Volumetric DDoS Flood",
    category: "Network", severity: "critical", enabled: true,
    triggers7d: 2, lastTriggered: Date.now()-1000*60*60*22,
    mitreTactic: "Impact", mitreId: "T1498.001",
    description: "Identifies a SYN/UDP/ICMP packet flood exceeding 1M packets/sec from distributed sources, causing service unavailability on the target host.",
    matchType: "ALL",
    conditions: [
      { id: 1, field: "Event ID / Action", operator: "contains", value: "ids.alert" },
      { id: 2, field: "Event ID / Action", operator: "contains", value: "flood" },
      { id: 3, field: "Event Severity",    operator: "equals",   value: "critical" },
    ],
    threshold: 1000, timeframe: 10, timeUnit: "seconds", groupBy: "Destination IP",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: true  },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: false },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: true  },
    ],
  },
  {
    id: "R004", name: "SQL Injection Pattern",
    category: "Network", severity: "critical", enabled: true,
    triggers7d: 27, lastTriggered: Date.now()-1000*60*42,
    mitreTactic: "Initial Access", mitreId: "T1190",
    description: "Detects UNION-based, boolean-blind, or error-based SQL injection payloads in HTTP request logs targeting web application endpoints.",
    matchType: "ANY",
    conditions: [
      { id: 1, field: "Event ID / Action", operator: "contains", value: "sql_injection" },
      { id: 2, field: "Event ID / Action", operator: "contains", value: "UNION SELECT" },
      { id: 3, field: "Event ID / Action", operator: "contains", value: "OR 1=1" },
    ],
    threshold: 3, timeframe: 1, timeUnit: "minutes", groupBy: "Source IP",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: true  },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: true  },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: true  },
    ],
  },
  {
    id: "R005", name: "Data Exfiltration Staging",
    category: "Insider Threat", severity: "high", enabled: true,
    triggers7d: 5, lastTriggered: Date.now()-1000*60*60*5,
    mitreTactic: "Exfiltration", mitreId: "T1041",
    description: "Detects outbound data transfers exceeding 500MB to unknown external IPs via HTTPS or DNS tunnel within a 10-minute window.",
    matchType: "ALL",
    conditions: [
      { id: 1, field: "Event ID / Action",      operator: "contains",        value: "net.conn.blocked" },
      { id: 2, field: "Destination IP Address", operator: "does not contain", value: "10." },
      { id: 3, field: "Event ID / Action",      operator: "contains",        value: "exfiltrat" },
    ],
    threshold: 5, timeframe: 10, timeUnit: "minutes", groupBy: "Source IP",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: true  },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: true  },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: true  },
    ],
  },
  {
    id: "R006", name: "Lateral Movement (PtH)",
    category: "Endpoint", severity: "high", enabled: true,
    triggers7d: 14, lastTriggered: Date.now()-1000*60*60*2,
    mitreTactic: "Lateral Movement", mitreId: "T1550.002",
    description: "Flags Pass-the-Hash: the same NTLM credential hash used to authenticate against 2+ distinct internal hosts within 10 minutes.",
    matchType: "ALL",
    conditions: [
      { id: 1, field: "Event ID / Action", operator: "contains", value: "auth.login.success" },
      { id: 2, field: "Process Name",      operator: "contains", value: "mimikatz" },
      { id: 3, field: "Hostname",          operator: "contains", value: "10." },
    ],
    threshold: 2, timeframe: 10, timeUnit: "minutes", groupBy: "Username",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: true  },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: true  },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: false },
    ],
  },
  {
    id: "R007", name: "Ransomware Mass Encryption",
    category: "Malware", severity: "critical", enabled: true,
    triggers7d: 1, lastTriggered: Date.now()-1000*60*60*30,
    mitreTactic: "Impact", mitreId: "T1486",
    description: "Triggers when 100+ file rename events with suspicious extensions (.locked, .encrypted) occur on a single host within 60 seconds.",
    matchType: "ALL",
    conditions: [
      { id: 1, field: "Event ID / Action", operator: "contains", value: "edr.file.encrypted" },
      { id: 2, field: "File Path",         operator: "contains", value: ".locked" },
      { id: 3, field: "Event Severity",    operator: "equals",   value: "critical" },
    ],
    threshold: 100, timeframe: 60, timeUnit: "seconds", groupBy: "Host",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: true  },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: true  },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: true  },
    ],
  },
  {
    id: "R008", name: "Spear Phishing Attachment",
    category: "Malware", severity: "high", enabled: true,
    triggers7d: 18, lastTriggered: Date.now()-1000*60*32,
    mitreTactic: "Initial Access", mitreId: "T1566.001",
    description: "Detects a macro-enabled Office document spawning child processes (cmd.exe, powershell.exe) — the hallmark of spear phishing payload execution.",
    matchType: "SEQUENCE",
    conditions: [
      { id: 1, field: "Event ID / Action", operator: "contains", value: "phishing" },
      { id: 2, field: "Process Name",      operator: "contains", value: "powershell.exe" },
      { id: 3, field: "Event Severity",    operator: "equals",   value: "high" },
    ],
    threshold: 1, timeframe: 5, timeUnit: "minutes", groupBy: "Host",
    actions: [
      { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
      { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
      { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: true  },
      { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: true  },
      { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: false },
    ],
  },
];

export const SUSPICIOUS_IPS = COUNTRIES.map((c, i) => ({
  ip: randomIp(true),
  country: c.name,
  flag: c.flag,
  events: 200 + Math.floor(Math.random() * 4800),
  threat: 40 + Math.floor(Math.random() * 60),
  lastSeen: Date.now() - Math.floor(Math.random() * 1000 * 60 * 60 * 4),
}));

export const UEBA_USERS = [
  { user: "harsh.mehta",    dept: "Engineering", anomaly: "Off-hours login",          risk: "high",     ts: Date.now()-1000*60*22 },
  { user: "rohan.k",        dept: "Finance",     anomaly: "Mass download (4.2GB)",    risk: "critical", ts: Date.now()-1000*60*9 },
  { user: "priya.s",        dept: "HR",          anomaly: "Privilege escalation attempt", risk: "high", ts: Date.now()-1000*60*48 },
  { user: "karan.w",        dept: "Sales",       anomaly: "Login from new geo",       risk: "medium",   ts: Date.now()-1000*60*60 },
  { user: "nikhita.s",      dept: "Marketing",   anomaly: "Unusual file access pattern", risk: "low",   ts: Date.now()-1000*60*120 },
  { user: "arjuna.p",       dept: "Engineering", anomaly: "Multiple failed MFA",      risk: "medium",   ts: Date.now()-1000*60*15 },
];

// MITRE ATT&CK simplified
export const MITRE_TACTICS = [
  "Reconnaissance", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"
];
export const MITRE_TECHNIQUES: Record<string, { id: string; name: string; status: "none"|"covered"|"triggered" }[]> = {};
MITRE_TACTICS.forEach((t, i) => {
  MITRE_TECHNIQUES[t] = Array.from({ length: 4 + (i % 3) }, (_, j) => {
    const r = Math.random();
    return {
      id: `T${1000 + i*10 + j}`,
      name: `${t.split(" ")[0]} Technique ${j+1}`,
      status: r < 0.15 ? "triggered" : r < 0.7 ? "covered" : "none",
    };
  });
});

export function fmtTime(ts: number) {
  return new Date(ts).toLocaleTimeString("en-IN", { hour12: false, timeZone: "Asia/Kolkata" });
}
export function fmtDateTime(ts: number) {
  return new Date(ts).toLocaleString("en-IN", { hour12: false, timeZone: "Asia/Kolkata" });
}
export function relTime(ts: number) {
  const d = Math.floor((Date.now() - ts) / 1000);
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  if (d < 86400) return `${Math.floor(d/3600)}h ago`;
  return `${Math.floor(d/86400)}d ago`;
}

// 24h hourly event volume seed
export function seedEventTimeline() {
  const now = Date.now();
  return Array.from({ length: 24 }, (_, i) => {
    const hour = new Date(now - (23 - i) * 3600 * 1000);
    const base = 200 + Math.floor(Math.sin(i / 3) * 80) + Math.floor(Math.random() * 100);
    return {
      time: hour.getHours().toString().padStart(2, "0") + ":00",
      auth: base + Math.floor(Math.random() * 80),
      net: 150 + Math.floor(Math.random() * 200),
      edr: 80 + Math.floor(Math.random() * 120),
      attack: [5, 12, 18].includes(i),
    };
  });
}
