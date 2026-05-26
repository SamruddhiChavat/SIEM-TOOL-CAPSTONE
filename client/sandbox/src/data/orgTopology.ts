// ═══════════════════════════════════════════════════════════
// SecureWatch — Organization Topology
// Canvas: 3600 × 1300  (pan+zoom — loads auto-fitted)
// ═══════════════════════════════════════════════════════════

export type NodeType =
  | 'internet' | 'fw' | 'router' | 'switch' | 'vpn'
  | 'workstation' | 'server' | 'nas' | 'printer'
  | 'siem' | 'edr' | 'attacker';

export type Department =
  | 'INTERNET' | 'ATTACKER' | 'PERIMETER'
  | 'IT' | 'ENGINEERING' | 'HR' | 'FINANCE' | 'EXECUTIVE' | 'SECURITY';

export interface OrgNode {
  id: string;
  label: string;
  type: NodeType;
  ip: string;
  os: string;
  dept: Department;
  x: number;
  y: number;
  external?: boolean;
}

export interface OrgEdge { source: string; target: string; }

// ─────────────────────────────────────────────────────────────
// NODES  (canvas 3600 × 1300)
// ─────────────────────────────────────────────────────────────
export const ORG_NODES: OrgNode[] = [

  // ── External / Attackers ────────────────
  { id:'atk-ru',   label:'APT-29 (Russia)',    type:'attacker',   ip:'185.220.101.34', os:'Kali Linux',           dept:'ATTACKER',    x:1000, y:100, external:true },
  { id:'atk-cn',   label:'APT-41 (China)',     type:'attacker',   ip:'203.78.103.11',  os:'Ubuntu / Custom',      dept:'ATTACKER',    x:1800, y:100, external:true },
  { id:'atk-us',   label:'Rogue Insider',      type:'attacker',   ip:'198.51.100.77',  os:'Windows 10',           dept:'ATTACKER',    x:2600, y:100, external:true },
  
  { id:'internet', label:'Internet',           type:'internet',   ip:'0.0.0.0',        os:'—',                    dept:'INTERNET',    x:1800, y:250, external:true },

  // ── Perimeter ───────────────────────────
  { id:'fw-edge',     label:'Edge Firewall',   type:'fw',     ip:'10.0.0.1', os:'FortiGate 100F',   dept:'PERIMETER', x:1800, y:400 },
  { id:'router-core', label:'Core Router',     type:'router', ip:'10.0.0.4', os:'Cisco IOS 17.x',   dept:'PERIMETER', x:1800, y:550 },

  // ── Switches ───────────────────────
  { id:'sw-eng',  label:'Eng Switch',       type:'switch', ip:'10.2.0.1', os:'HP ProCurve 2920',    dept:'ENGINEERING', x:900,  y:760 },
  { id:'sw-it',   label:'IT Switch',        type:'switch', ip:'10.1.0.1', os:'Cisco Catalyst 9300', dept:'IT',          x:1800, y:760 },
  { id:'sw-sec',  label:'Security Switch',  type:'switch', ip:'10.6.0.1', os:'Cisco Nexus 3000',    dept:'SECURITY',    x:2700, y:760 },

  // ── Servers ─────────────────────────────
  { id:'srv-git',      label:'GitLab Server',     type:'server',  ip:'10.2.0.20', os:'Ubuntu 22.04',         dept:'ENGINEERING', x:700,  y:980 },
  { id:'srv-ad',       label:'Active Directory',  type:'server',  ip:'10.1.0.10', os:'Windows Server 2022',  dept:'IT',          x:1600, y:980 },
  { id:'siem',         label:'SecureWatch SIEM',  type:'siem',    ip:'10.6.0.10', os:'Docker / Linux',       dept:'SECURITY',    x:2600, y:980 },
  { id:'edr-corp',     label:'Corp EDR Agent',    type:'edr',     ip:'10.6.0.21', os:'SentinelOne',          dept:'SECURITY',    x:2800, y:980 },

  // ── Endpoints ──────────────────────────
  { id:'ws-jesal',     label:"Jesal's MacBook",   type:'workstation', ip:'10.2.0.101', os:'macOS Sequoia',        dept:'ENGINEERING', x:900,  y:1190 },
  { id:'ws-harsh',     label:"Harsh's Windows",   type:'workstation', ip:'10.2.0.102', os:'Windows 11',           dept:'ENGINEERING', x:1100, y:1190 },
  { id:'ws-arjuna',    label:"Arjuna Desktop",    type:'workstation', ip:'10.2.0.103', os:'Linux Mint',           dept:'ENGINEERING', x:700,  y:1190 },
  { id:'ws-ceo',       label:"CEO's MacBook Pro", type:'workstation', ip:'10.1.0.101', os:'macOS Sonoma',         dept:'IT',          x:1800, y:1190 },
  { id:'ws-nikhiti',   label:"Nikhiti's Windows", type:'workstation', ip:'10.1.0.102', os:'Windows 11',           dept:'IT',          x:1600, y:1190 },
  { id:'ws-samruddhi', label:"Samruddhi's MacBook", type:'workstation', ip:'10.1.0.103', os:'macOS Sonoma',       dept:'IT',          x:2000, y:1190 },
];

// ─────────────────────────────────────────────────────────────
// EDGES
// ─────────────────────────────────────────────────────────────
export const ORG_EDGES: OrgEdge[] = [
  { source:'atk-ru',     target:'internet' },
  { source:'atk-cn',     target:'internet' },
  { source:'atk-us',     target:'internet' },
  { source:'internet',   target:'fw-edge'  },
  { source:'fw-edge',    target:'router-core' },
  { source:'router-core',target:'sw-eng'  },
  { source:'router-core',target:'sw-it'   },
  { source:'router-core',target:'sw-sec'  },
  { source:'sw-eng', target:'srv-git'    },
  { source:'sw-eng', target:'ws-jesal'   },
  { source:'sw-eng', target:'ws-harsh'   },
  { source:'sw-eng', target:'ws-arjuna'  },
  { source:'sw-it',  target:'srv-ad'     },
  { source:'sw-it',  target:'ws-ceo'     },
  { source:'sw-it',  target:'ws-nikhiti' },
  { source:'sw-it',  target:'ws-samruddhi' },
  { source:'sw-sec', target:'siem'       },
  { source:'sw-sec', target:'edr-corp'   },
];

// ─────────────────────────────────────────────────────────────
// Dept zones
// ─────────────────────────────────────────────────────────────
export const DEPT_ZONES = [
  { dept:'ATTACKER',    label:'☠  THREAT ACTORS',    x:800,  y:40,  w:2000, h:135, dashed:true  },
  { dept:'INTERNET',    label:'INTERNET / WAN',       x:1430, y:200, w:740,  h:100, dashed:false },
  { dept:'PERIMETER',   label:'PERIMETER ZONE',       x:1430, y:350, w:740,  h:250, dashed:false },
  { dept:'ENGINEERING', label:'ENGINEERING',          x:500,  y:690, w:800,  h:580, dashed:false },
  { dept:'IT',          label:'IT & EXEC',            x:1400, y:690, w:800,  h:580, dashed:false },
  { dept:'SECURITY',    label:'SOC / SECURITY',       x:2300, y:690, w:800,  h:380, dashed:false },
];

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────
export const INTERNAL_TARGETS = ORG_NODES.filter(
  n => !n.external && n.type !== 'siem' && n.type !== 'edr'
    && n.type !== 'fw' && n.type !== 'router' && n.type !== 'switch'
);
export const ATTACKERS = ORG_NODES.filter(n => n.type === 'attacker');

export function resolveAttackPath(targetId: string): string[] {
  const target = ORG_NODES.find(n => n.id === targetId);
  if (!target) return ['internet','fw-edge','router-core'];
  const sw: Record<string,string> = {
    ENGINEERING:'sw-eng', IT:'sw-it', SECURITY:'sw-sec', PERIMETER:'fw-edge',
    INTERNET:'internet',  ATTACKER:'internet',
  };
  return ['internet','fw-edge','router-core', sw[target.dept] ?? 'sw-it', targetId];
}
