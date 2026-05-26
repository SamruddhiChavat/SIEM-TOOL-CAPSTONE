export type NodeStatus = 'GREEN' | 'YELLOW' | 'RED' | 'GREY';

export interface DeviceNode {
  id: string;
  hostname: string;
  ip: string;
  os: 'macOS' | 'Windows 10' | 'Windows 11' | 'Ubuntu' | 'Windows Server 2019' | 'pfSense' | 'Appliance';
  role: string;
  status: NodeStatus;
  group: 'endpoints' | 'servers' | 'security' | 'network';
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  status: 'normal' | 'active' | 'blocked';
}

export type LogSeverity = 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL';

export interface LogEntry {
  id: string;
  timestamp: number;
  srcIp: string;
  dstIp: string;
  eventType: string;
  severity: LogSeverity;
  message: string;
}

export type AttackType = 
  | 'brute-force'
  | 'ddos'
  | 'dos'
  | 'sql-injection'
  | 'port-scan'
  | 'phishing'
  | 'privilege-escalation'
  | 'ransomware'
  | 'insider-threat'
  | 'mitm';

export interface Alert {
  id: string;
  timestamp: number;
  ruleName: string;
  srcDevice: string;
  dstDevice: string;
  severity: LogSeverity;
  status: 'Open' | 'Investigating' | 'Resolved';
}

export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  matchCount: number;
  severity: LogSeverity;
  timestamp: number;
}
