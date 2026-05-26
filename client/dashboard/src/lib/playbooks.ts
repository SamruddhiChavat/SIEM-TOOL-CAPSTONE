// ─── Playbook definitions mapped to MITRE attack types ───────────────────────

export type PlaybookStep = {
  id: number;
  task: string;
  detail: string;         // what actually happens
  action?: string;        // backend action key
  autoTrigger?: boolean;  // triggered automatically by response action
};

export type PlaybookDef = {
  id: string;
  name: string;
  mitreTactic: string;
  steps: PlaybookStep[];
};

// Map event type → playbook
const PLAYBOOKS: Record<string, PlaybookDef> = {

  // ── Brute Force / Credential Access ──────────────────────────────────────
  BRUTE_FORCE: {
    id: "PB-001",
    name: "Brute Force Credential Attack Response",
    mitreTactic: "Credential Access · T1110.001",
    steps: [
      { id: 1, task: "Verify alert: confirm >10 failed logins from same source IP", detail: "Query ES for auth failures from source_ip in last 5 min. Threshold: 10+", autoTrigger: true },
      { id: 2, task: "Block source IP at perimeter firewall", detail: "POST /api/response/block-ip → pushes rule to relay → logs BLOCK event to SIEM", action: "BLOCK_IP" },
      { id: 3, task: "Lock targeted user accounts", detail: "POST /api/response/disable-account → disables AD account, logs to SIEM", action: "DISABLE_ACCOUNT" },
      { id: 4, task: "Enable Account Lockout Policy (min 5 attempts)", detail: "Confirms lockout policy is active on domain controller via log check" },
      { id: 5, task: "Check for any successful login from blocked IP", detail: "Pivot search in Log Explorer: source_ip=<ip> AND event=auth_success" },
      { id: 6, task: "Capture forensic snapshot of targeted host", detail: "POST /api/response/snapshot → EDR captures memory + process list", action: "CAPTURE_SNAPSHOT" },
      { id: 7, task: "Close incident with root cause analysis", detail: "Mark incident Resolved. Asset status restored to Online.", action: "CLOSE_INCIDENT" },
    ],
  },

  "BRUTE-FORCE": { id: "PB-001", name: "Brute Force Credential Attack Response", mitreTactic: "Credential Access · T1110.001", steps: [] },

  // ── Port Scan / Reconnaissance ────────────────────────────────────────────
  PORT_SCAN: {
    id: "PB-002",
    name: "Network Reconnaissance Detection Response",
    mitreTactic: "Discovery · T1046",
    steps: [
      { id: 1, task: "Confirm port scan activity: >100 unique ports from single source", detail: "Query SIEM logs for SYN packets per source_ip. Threshold: 100+ ports in 60s", autoTrigger: true },
      { id: 2, task: "Identify source IP geolocation and reputation", detail: "Check Threat Intel panel for IP risk score. Mark as suspicious." },
      { id: 3, task: "Block scanning IP at edge firewall", detail: "POST /api/response/block-ip → pushes perimeter block rule", action: "BLOCK_IP" },
      { id: 4, task: "Review which internal services were probed", detail: "Log Explorer: filter by dest_port and group by service name" },
      { id: 5, task: "Check for follow-on exploitation attempts", detail: "Pivot: same IP → subsequent connection attempts to open ports" },
      { id: 6, task: "Close incident and update asset exposure notes", detail: "Confirm no exploitation occurred. Restore asset status.", action: "CLOSE_INCIDENT" },
    ],
  },

  "PORT-SCAN": { id: "PB-002", name: "Network Reconnaissance Detection Response", mitreTactic: "Discovery · T1046", steps: [] },

  // ── SQL Injection ─────────────────────────────────────────────────────────
  SQL_INJECTION: {
    id: "PB-003",
    name: "SQL Injection / Web Exploitation Response",
    mitreTactic: "Initial Access · T1190",
    steps: [
      { id: 1, task: "Verify: confirm SQL injection payload in request logs", detail: "Log Explorer: filter event.type=web_request AND message=UNION|OR 1=1", autoTrigger: true },
      { id: 2, task: "Isolate web server from internal network", detail: "POST /api/response/isolate → quarantines host in SIEM + EDR", action: "ISOLATE_HOST" },
      { id: 3, task: "Block source IP immediately", detail: "POST /api/response/block-ip → firewall rule + SIEM log", action: "BLOCK_IP" },
      { id: 4, task: "Check DB query logs for data exfiltration", detail: "DB audit log review: SELECT * on sensitive tables from web app user" },
      { id: 5, task: "Capture web server forensic snapshot", detail: "POST /api/response/snapshot → EDR process and file capture", action: "CAPTURE_SNAPSHOT" },
      { id: 6, task: "Patch SQL endpoint and deploy WAF rule", detail: "Parameterized query patch confirmed. WAF rule deployed for payload pattern." },
      { id: 7, task: "Restore asset and close incident", detail: "Patch confirmed. Asset status restored to Online.", action: "CLOSE_INCIDENT" },
    ],
  },

  "SQL-INJECTION": { id: "PB-003", name: "SQL Injection / Web Exploitation Response", mitreTactic: "Initial Access · T1190", steps: [] },

  // ── DDoS ─────────────────────────────────────────────────────────────────
  DDOS: {
    id: "PB-004",
    name: "DDoS / Volumetric Flood Response",
    mitreTactic: "Impact · T1498.001",
    steps: [
      { id: 1, task: "Confirm volumetric flood: >1M packets/sec or service unresponsive", detail: "Check network interface stats. Confirm target service uptime.", autoTrigger: true },
      { id: 2, task: "Enable rate-limiting and geo-blocking at edge", detail: "POST /api/response/block-ip for top attacker IPs (batch)", action: "BLOCK_IP" },
      { id: 3, task: "Divert traffic to scrubbing center / null route", detail: "Notify ISP or CDN team. Simulate: log DIVERT_TRAFFIC action." },
      { id: 4, task: "Monitor service recovery — confirm uptime restored", detail: "Check target host health every 30s. Log to SIEM." },
      { id: 5, task: "Capture traffic PCAP for attribution", detail: "POST /api/response/snapshot on edge router for PCAP sample", action: "CAPTURE_SNAPSHOT" },
      { id: 6, task: "Post-incident review: update DDoS threshold baseline", detail: "Update correlation rule thresholds in SIEM. Close incident.", action: "CLOSE_INCIDENT" },
    ],
  },

  DOS: { id: "PB-004", name: "DDoS / Volumetric Flood Response", mitreTactic: "Impact · T1498.001", steps: [] },

  // ── Data Exfiltration ─────────────────────────────────────────────────────
  FILE_EXFILTRATION: {
    id: "PB-005",
    name: "Data Exfiltration Response",
    mitreTactic: "Exfiltration · T1041",
    steps: [
      { id: 1, task: "Confirm: large outbound transfer (>100MB) to unknown external IP", detail: "Log Explorer: filter dest=external AND bytes_out>100MB. Confirm.", autoTrigger: true },
      { id: 2, task: "Block destination IP at perimeter immediately", detail: "POST /api/response/block-ip → firewall block + SIEM audit log", action: "BLOCK_IP" },
      { id: 3, task: "Isolate source host to prevent further exfiltration", detail: "POST /api/response/isolate → EDR network quarantine", action: "ISOLATE_HOST" },
      { id: 4, task: "Identify which files were accessed/transferred", detail: "File audit log: process=<source_exe> AND event=file_read, sort by size desc" },
      { id: 5, task: "Disable user account associated with the host", detail: "POST /api/response/disable-account → AD account suspended", action: "DISABLE_ACCOUNT" },
      { id: 6, task: "Capture forensic snapshot for legal hold", detail: "POST /api/response/snapshot → full disk image queued", action: "CAPTURE_SNAPSHOT" },
      { id: 7, task: "Notify DPO / Compliance: potential data breach", detail: "Email notification drafted for GDPR 72hr reporting requirement." },
      { id: 8, task: "Remediate and restore asset after clean forensics", detail: "Forensics confirmed. Restore asset status to Online.", action: "CLOSE_INCIDENT" },
    ],
  },

  // ── Lateral Movement ──────────────────────────────────────────────────────
  LATERAL_MOVEMENT: {
    id: "PB-006",
    name: "Lateral Movement (Pass-the-Hash) Response",
    mitreTactic: "Lateral Movement · T1550.002",
    steps: [
      { id: 1, task: "Confirm: NTLM hash reuse detected across multiple hosts", detail: "SIEM correlation: same credential hash used on >2 hosts within 10 min", autoTrigger: true },
      { id: 2, task: "Isolate initial compromise host immediately", detail: "POST /api/response/isolate on source host → network quarantine", action: "ISOLATE_HOST" },
      { id: 3, task: "Disable compromised service account", detail: "POST /api/response/disable-account → suspend service account in AD", action: "DISABLE_ACCOUNT" },
      { id: 4, task: "Identify all hosts accessed with compromised credential", detail: "Pivot search: auth.hash=<ntlm_hash> across all siem-logs-* in last 24h" },
      { id: 5, task: "Isolate all additional compromised hosts", detail: "POST /api/response/isolate for each identified lateral host" },
      { id: 6, task: "Force password reset for all affected accounts", detail: "AD bulk password reset. Purge Kerberos ticket cache on DCs." },
      { id: 7, task: "Capture memory dumps from affected hosts", detail: "POST /api/response/snapshot → EDR Mimikatz artifact detection", action: "CAPTURE_SNAPSHOT" },
      { id: 8, task: "Restore hosts after clean reimaging", detail: "Confirm all hosts clean. Restore asset status.", action: "CLOSE_INCIDENT" },
    ],
  },

  // ── Ransomware ────────────────────────────────────────────────────────────
  RANSOMWARE: {
    id: "PB-007",
    name: "Ransomware Containment & Recovery",
    mitreTactic: "Impact · T1486",
    steps: [
      { id: 1, task: "CRITICAL: Confirm file encryption in progress on host", detail: "EDR alert: mass file rename with .locked/.encrypted extension", autoTrigger: true },
      { id: 2, task: "IMMEDIATELY isolate affected host from all networks", detail: "POST /api/response/isolate → cut all network + USB access via EDR", action: "ISOLATE_HOST" },
      { id: 3, task: "Block all known C2 IPs associated with ransomware variant", detail: "POST /api/response/block-ip for all identified C2 endpoints", action: "BLOCK_IP" },
      { id: 4, task: "Disable all user accounts that were active on the host", detail: "POST /api/response/disable-account → bulk AD account suspension", action: "DISABLE_ACCOUNT" },
      { id: 5, task: "Preserve memory dump BEFORE remediation", detail: "POST /api/response/snapshot → critical for decryption key extraction", action: "CAPTURE_SNAPSHOT" },
      { id: 6, task: "Identify ransomware entry point (email, RDP, exploit)", detail: "Trace backward: review email gateway, VPN logs, and RDP auth logs" },
      { id: 7, task: "Scan all network shares for encrypted files", detail: "List encrypted files across SMB shares. Identify blast radius." },
      { id: 8, task: "Restore from clean backup (pre-infection snapshot)", detail: "Restore from verified backup. Confirm no reinfection." },
      { id: 9, task: "Reset all credentials, re-image host, and restore", detail: "Full credential rotation. Reimage confirmed. Asset restored.", action: "CLOSE_INCIDENT" },
    ],
  },

  // ── Phishing ──────────────────────────────────────────────────────────────
  PHISHING: {
    id: "PB-008",
    name: "Spear Phishing / Malicious Email Response",
    mitreTactic: "Initial Access · T1566.001",
    steps: [
      { id: 1, task: "Confirm malicious email delivery and user interaction", detail: "Email gateway logs: attachment opened or link clicked. Confirm beacon received.", autoTrigger: true },
      { id: 2, task: "Pull and quarantine the malicious email from all mailboxes", detail: "Email admin: search by sender/subject → bulk quarantine action" },
      { id: 3, task: "Isolate host where user clicked the link/attachment", detail: "POST /api/response/isolate → network quarantine via EDR", action: "ISOLATE_HOST" },
      { id: 4, task: "Capture memory snapshot to find running payload", detail: "POST /api/response/snapshot → look for macro-spawned child processes", action: "CAPTURE_SNAPSHOT" },
      { id: 5, task: "Disable user account pending investigation", detail: "POST /api/response/disable-account → suspend in AD", action: "DISABLE_ACCOUNT" },
      { id: 6, task: "Block sender domain and C2 IP at email gateway + firewall", detail: "POST /api/response/block-ip for payload C2. Block sender at email gateway.", action: "BLOCK_IP" },
      { id: 7, task: "Notify all users: phishing awareness alert", detail: "Push security awareness notification to all staff via email." },
      { id: 8, task: "Restore clean host and re-enable user account", detail: "Re-image confirmed. Account re-enabled with MFA enforced.", action: "CLOSE_INCIDENT" },
    ],
  },
};

// Fill in empty refs
PLAYBOOKS["BRUTE-FORCE"].steps = PLAYBOOKS["BRUTE_FORCE"].steps;
PLAYBOOKS["PORT-SCAN"].steps  = PLAYBOOKS["PORT_SCAN"].steps;
PLAYBOOKS["SQL-INJECTION"].steps = PLAYBOOKS["SQL_INJECTION"].steps;
PLAYBOOKS["DOS"].steps = PLAYBOOKS["DDOS"].steps;

// Default fallback
const DEFAULT_PLAYBOOK: PlaybookDef = {
  id: "PB-000",
  name: "Generic Security Incident Response",
  mitreTactic: "Unknown",
  steps: [
    { id: 1, task: "Verify and classify the incident severity", detail: "Review alert details, source IP, and affected host", autoTrigger: true },
    { id: 2, task: "Isolate affected host if actively compromised", detail: "POST /api/response/isolate → EDR network quarantine", action: "ISOLATE_HOST" },
    { id: 3, task: "Block attacker source IP at perimeter", detail: "POST /api/response/block-ip → firewall rule", action: "BLOCK_IP" },
    { id: 4, task: "Capture forensic snapshot", detail: "POST /api/response/snapshot → memory and disk", action: "CAPTURE_SNAPSHOT" },
    { id: 5, task: "Review logs and determine root cause", detail: "Log Explorer pivot: filter by source_ip and affected host" },
    { id: 6, task: "Close incident with documented root cause", detail: "Mark Resolved. Restore asset status.", action: "CLOSE_INCIDENT" },
  ],
};

export function getPlaybook(eventType: string, mitreTactic?: string): PlaybookDef {
  const key = (eventType || "").toUpperCase().replace(/^ATTACK_/, "").replace(/ /g, "_");
  
  if (PLAYBOOKS[key]) return PLAYBOOKS[key];
  
  // Try matching by mitre tactic
  if (mitreTactic) {
    const tac = mitreTactic.toUpperCase();
    if (tac.includes("CREDENTIAL")) return PLAYBOOKS["BRUTE_FORCE"];
    if (tac.includes("DISCOVERY")) return PLAYBOOKS["PORT_SCAN"];
    if (tac.includes("INITIAL ACCESS")) return PLAYBOOKS["SQL_INJECTION"];
    if (tac.includes("IMPACT")) return PLAYBOOKS["DDOS"];
    if (tac.includes("EXFILTRATION")) return PLAYBOOKS["FILE_EXFILTRATION"];
    if (tac.includes("LATERAL")) return PLAYBOOKS["LATERAL_MOVEMENT"];
    if (tac.includes("RANSOMWARE") || tac.includes("T1486")) return PLAYBOOKS["RANSOMWARE"];
  }
  
  return DEFAULT_PLAYBOOK;
}
