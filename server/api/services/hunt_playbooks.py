HUNT_PLAYBOOKS = [
    {
        "id": "HUNT-001",
        "name": "Suspicious PowerShell Execution (Encoded)",
        "description": "Finds PowerShell instances potentially executing Base64 encoded commands.",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001",
        "query_string": "process.name:powershell.exe AND process.command_line:(*-enc* OR *-ec* OR *-EncodedCommand*)",
        "index_pattern": "siem-logs-endpoint-*"
    },
    {
        "id": "HUNT-002",
        "name": "RDP Connection to External IP",
        "description": "Identifies internal hosts establishing RDP connections (3389) out to the internet.",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071",
        "query_string": "network.transport:tcp AND destination.port:3389 AND NOT destination.ip:(10.0.0.0/8 OR 192.168.0.0/16 OR 172.16.0.0/12)",
        "index_pattern": "siem-logs-network-*"
    },
    {
        "id": "HUNT-003",
        "name": "LSASS Memory Dump",
        "description": "Hunts for processes that might be dumping lsass.exe memory for credential theft.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.001",
        "query_string": "process.name:procdump*.exe AND process.command_line:*lsass.exe*",
        "index_pattern": "siem-logs-endpoint-*"
    },
    {
        "id": "HUNT-004",
        "name": "Suspicious WMI Execution",
        "description": "Detects Wmic.exe being used for reconnaissance or lateral movement.",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1047",
        "query_string": "process.name:wmic.exe AND process.command_line:(*process call create* OR *node:*)",
        "index_pattern": "siem-logs-endpoint-*"
    },
    {
        "id": "HUNT-005",
        "name": "Linux Sudoers File Modification",
        "description": "Hunts for manual editing of the sudoers file on Linux hosts via bash history or FIM.",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548.003",
        "query_string": "(process.name:visudo OR process.command_line:*/etc/sudoers*) OR (event_type:file_modified AND file_path:*/etc/sudoers*)",
        "index_pattern": "siem-*"
    },
    {
        "id": "HUNT-006",
        "name": "Large Data Exfiltration via DNS",
        "description": "Hunts for exceptionally long DNS queries that might indicate data tunneling.",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048.003",
        "query_string": "network.protocol:dns AND dns.question.name:/.*{50,}/",
        "index_pattern": "siem-logs-network-*"
    },
    {
        "id": "HUNT-007",
        "name": "Clearing Windows Event Logs",
        "description": "Detects usage of wevtutil to clear security, system, or application event logs.",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001",
        "query_string": "process.name:wevtutil.exe AND process.command_line:(*cl* OR *clear-log*)",
        "index_pattern": "siem-logs-endpoint-*"
    },
    {
        "id": "HUNT-008",
        "name": "Execution from Temporary Directories",
        "description": "Identifies executables launched from common malware staging areas.",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1204.002",
        "query_string": "process.executable:(*\\\\Temp\\\\* OR *\\\\Tmp\\\\* OR *\\\\AppData\\\\Local\\\\Temp\\\\*) AND process.name:*.exe",
        "index_pattern": "siem-logs-endpoint-*"
    },
    {
        "id": "HUNT-009",
        "name": "Web Shell Activity (Suspicious Process Tree)",
        "description": "Hunts for web servers spawning unnatural shells (cmd.exe, bash).",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1505.003",
        "query_string": "process.parent.name:(w3wp.exe OR httpd OR nginx OR apache2) AND process.name:(cmd.exe OR powershell.exe OR bash OR sh)",
        "index_pattern": "siem-logs-endpoint-*"
    },
    {
        "id": "HUNT-010",
        "name": "Scheduled Task Creation",
        "description": "Hunts for persistence established via Windows schtasks.",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.005",
        "query_string": "process.name:schtasks.exe AND process.command_line:*\\/create*",
        "index_pattern": "siem-logs-endpoint-*"
    }
]
