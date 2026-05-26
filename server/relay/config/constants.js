module.exports = {
  PORT: process.env.PORT || 4000,
  MAX_LOGS: 2000,
  ATTACK_MITRE: {
    // with ATTACK_ prefix (legacy)
    'ATTACK_BRUTE_FORCE':          { tactic: 'Credential Access',  technique: 'T1110',     name: 'Brute Force' },
    'ATTACK_BRUTE-FORCE':          { tactic: 'Credential Access',  technique: 'T1110',     name: 'Brute Force' },
    'ATTACK_DDOS':                 { tactic: 'Impact',             technique: 'T1498',     name: 'Network DoS' },
    'ATTACK_DOS':                  { tactic: 'Impact',             technique: 'T1499',     name: 'Endpoint DoS' },
    'ATTACK_SQL_INJECTION':        { tactic: 'Initial Access',     technique: 'T1190',     name: 'SQL Injection' },
    'ATTACK_SQL-INJECTION':        { tactic: 'Initial Access',     technique: 'T1190',     name: 'SQL Injection' },
    'ATTACK_PORT_SCAN':            { tactic: 'Discovery',          technique: 'T1046',     name: 'Network Service Scan' },
    'ATTACK_PORT-SCAN':            { tactic: 'Discovery',          technique: 'T1046',     name: 'Network Service Scan' },
    'ATTACK_PHISHING':             { tactic: 'Initial Access',     technique: 'T1566',     name: 'Phishing' },
    'ATTACK_PRIVILEGE_ESCALATION': { tactic: 'Privilege Esc.',     technique: 'T1548',     name: 'Abuse Elevation Control' },
    'ATTACK_PRIVILEGE-ESCALATION': { tactic: 'Privilege Esc.',     technique: 'T1548',     name: 'Abuse Elevation Control' },
    'ATTACK_RANSOMWARE':           { tactic: 'Impact',             technique: 'T1486',     name: 'Data Encrypted for Impact' },
    'ATTACK_INSIDER_THREAT':       { tactic: 'Exfiltration',       technique: 'T1052',     name: 'Exfiltration Over Physical Medium' },
    'ATTACK_INSIDER-THREAT':       { tactic: 'Exfiltration',       technique: 'T1052',     name: 'Exfiltration Over Physical Medium' },
    'ATTACK_MITM':                 { tactic: 'Collection',         technique: 'T1557',     name: 'Adversary-in-the-Middle' },
    // sandbox attack IDs (no prefix) — matches attackDefs.ts ids uppercased
    'BRUTE_FORCE':                 { tactic: 'Credential Access',  technique: 'T1110.001', name: 'Brute Force' },
    'DDOS':                        { tactic: 'Impact',             technique: 'T1498.001', name: 'Network DoS' },
    'SQL_INJECTION':               { tactic: 'Initial Access',     technique: 'T1190',     name: 'SQL Injection' },
    'PORT_SCAN':                   { tactic: 'Discovery',          technique: 'T1046',     name: 'Network Service Scan' },
    'FILE_EXFILTRATION':           { tactic: 'Exfiltration',       technique: 'T1041',     name: 'Data Exfiltration' },
    'LATERAL_MOVEMENT':            { tactic: 'Lateral Movement',   technique: 'T1550.002', name: 'Pass-the-Hash' },
    'DNS_C2':                      { tactic: 'Command & Control',  technique: 'T1071.004', name: 'DNS C2 Tunneling' },
    'RANSOMWARE':                  { tactic: 'Impact',             technique: 'T1486',     name: 'Ransomware Deploy' },
    'PHISHING':                    { tactic: 'Initial Access',     technique: 'T1566.001', name: 'Spear Phishing' },
    // Response events
    'RESPONSE_ISOLATE':            { tactic: 'Response',           technique: 'N/A',       name: 'Host Isolation' },
    'RESPONSE_REMEDIATE':          { tactic: 'Response',           technique: 'N/A',       name: 'Host Remediation' },
    'RESPONSE_BLOCK_IP':           { tactic: 'Response',           technique: 'N/A',       name: 'IP Block' },
  }
};
