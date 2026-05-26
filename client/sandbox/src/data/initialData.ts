import { DeviceNode, NetworkEdge } from '../types';

export const initialNodes: DeviceNode[] = [
  { id: 'jesal-mac', hostname: "Jesal's MacBook Pro", ip: '192.168.1.101', os: 'macOS', role: 'Security Analyst', status: 'GREEN', group: 'endpoints' },
  { id: 'sam-mac', hostname: "Samruddhi's MacBook Air", ip: '192.168.1.102', os: 'macOS', role: 'HR', status: 'GREEN', group: 'endpoints' },
  { id: 'harsh-win', hostname: 'Harsh Windows', ip: '192.168.1.103', os: 'Windows 10', role: 'Developer', status: 'GREEN', group: 'endpoints' },
  { id: 'nikhita-win', hostname: 'Nikhita Windows', ip: '192.168.1.104', os: 'Windows 10', role: 'Finance', status: 'GREEN', group: 'endpoints' },
  { id: 'arjuna-win', hostname: 'Arjuna Windows', ip: '192.168.1.105', os: 'Windows 11', role: 'Developer', status: 'GREEN', group: 'endpoints' },
  { id: 'rohan-win', hostname: 'Rohan Windows', ip: '192.168.1.106', os: 'Windows 10', role: 'IT Support', status: 'GREEN', group: 'endpoints' },
  { id: 'priya-lin', hostname: 'Priya Linux', ip: '192.168.1.107', os: 'Ubuntu', role: 'DevOps', status: 'GREEN', group: 'endpoints' },
  { id: 'karan-win', hostname: 'Karan Windows', ip: '192.168.1.108', os: 'Windows 10', role: 'Intern', status: 'GREEN', group: 'endpoints' },
  
  { id: 'edr-1', hostname: 'EDR Server 1', ip: '10.0.0.10', os: 'Appliance', role: 'CrowdStrike-style', status: 'GREEN', group: 'security' },
  { id: 'edr-2', hostname: 'EDR Server 2', ip: '10.0.0.11', os: 'Appliance', role: 'Carbon Black-style', status: 'GREEN', group: 'security' },
  { id: 'fw-1', hostname: 'Firewall Server 1', ip: '10.0.0.1', os: 'pfSense', role: 'Perimeter Firewall', status: 'GREEN', group: 'security' },
  { id: 'fw-2', hostname: 'Firewall Server 2', ip: '10.0.0.2', os: 'Appliance', role: 'Internal Firewall', status: 'GREEN', group: 'security' },
  { id: 'siem', hostname: 'SIEM Server', ip: '10.0.0.20', os: 'Appliance', role: 'Log Aggregator', status: 'GREEN', group: 'servers' },
  { id: 'web-server', hostname: 'Web Server', ip: '172.16.0.10', os: 'Ubuntu', role: 'DMZ Apache', status: 'GREEN', group: 'servers' },
  { id: 'dc', hostname: 'Domain Controller', ip: '10.0.0.5', os: 'Windows Server 2019', role: 'Active Directory', status: 'GREEN', group: 'servers' },
  { id: 'internet', hostname: 'Internet', ip: '0.0.0.0', os: 'Appliance', role: 'External', status: 'GREEN', group: 'network' }
];

export const initialEdges: NetworkEdge[] = [
  { id: 'e-inet-fw1', source: 'internet', target: 'fw-1', status: 'normal' },
  { id: 'e-fw1-web', source: 'fw-1', target: 'web-server', status: 'normal' },
  { id: 'e-fw1-fw2', source: 'fw-1', target: 'fw-2', status: 'normal' },
  { id: 'e-fw2-dc', source: 'fw-2', target: 'dc', status: 'normal' },
  { id: 'e-fw2-siem', source: 'fw-2', target: 'siem', status: 'normal' },
  { id: 'e-fw2-edr1', source: 'fw-2', target: 'edr-1', status: 'normal' },
  { id: 'e-fw2-edr2', source: 'fw-2', target: 'edr-2', status: 'normal' },
  
  // Endpoint connections to internal firewall
  { id: 'e-jesal-fw2', source: 'jesal-mac', target: 'fw-2', status: 'normal' },
  { id: 'e-sam-fw2', source: 'sam-mac', target: 'fw-2', status: 'normal' },
  { id: 'e-harsh-fw2', source: 'harsh-win', target: 'fw-2', status: 'normal' },
  { id: 'e-nikhita-fw2', source: 'nikhita-win', target: 'fw-2', status: 'normal' },
  { id: 'e-arjuna-fw2', source: 'arjuna-win', target: 'fw-2', status: 'normal' },
  { id: 'e-rohan-fw2', source: 'rohan-win', target: 'fw-2', status: 'normal' },
  { id: 'e-priya-fw2', source: 'priya-lin', target: 'fw-2', status: 'normal' },
  { id: 'e-karan-fw2', source: 'karan-win', target: 'fw-2', status: 'normal' }
];
