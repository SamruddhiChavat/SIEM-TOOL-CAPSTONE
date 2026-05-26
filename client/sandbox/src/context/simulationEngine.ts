import type { AttackType, DeviceNode, LogEntry, Alert, CorrelationRule } from '../types';

// ─── Relay server URL ─────────────────────────────────────────────────────────
const RELAY_URL = 'http://localhost:4000/api/logs';

async function forwardLogToSIEM(log: object) {
  try {
    await fetch(RELAY_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(log),
    });
  } catch (err) {
    console.warn('[Sandbox] Failed to forward log to relay:', err);
  }
}

const backgroundEvents = [
  'Connection established',
  'DNS query',
  'HTTP GET /',
  'TLS handshake completed',
  'Authentication successful',
  'Heartbeat sent',
  'File read',
];

export function generateBackgroundLog(nodes: DeviceNode[]): Omit<LogEntry, 'id'> {
  const activeNodes = nodes.filter(n => n.status !== 'GREY');

  const src  = activeNodes[Math.floor(Math.random() * activeNodes.length)];
  let   dest = activeNodes[Math.floor(Math.random() * activeNodes.length)];
  while (dest.id === src.id && activeNodes.length > 1) {
    dest = activeNodes[Math.floor(Math.random() * activeNodes.length)];
  }

  const event = backgroundEvents[Math.floor(Math.random() * backgroundEvents.length)];

  const log = {
    timestamp:   Date.now(),
    srcIp:       src.ip,
    dstIp:       dest.ip,
    srcHostname: src.hostname,
    dstHostname: dest.hostname,
    eventType:   event,
    severity:    'INFO',
    message:     `${event} from ${src.hostname} to ${dest.hostname}`,
  };

  forwardLogToSIEM(log);
  return log as Omit<LogEntry, 'id'>;
}

interface AttackContext {
  nodes:            DeviceNode[];
  updateNodeStatus: (id: string, status: DeviceNode['status']) => void;
  addLog:           (log: Omit<LogEntry, 'id'>) => void;
  addAlert:         (alert: Omit<Alert, 'id' | 'status'>) => void;
  addRule:          (rule: Omit<CorrelationRule, 'id' | 'timestamp'>) => void;
  setActiveAttacks: React.Dispatch<React.SetStateAction<AttackType[]>>;
}

// Map attack type → {attacker node id, target node id}
const ATTACK_MAP: Record<AttackType, [string, string]> = {
  'brute-force':          ['karan-win',   'siem'],
  'ddos':                 ['internet',    'web-server'],
  'dos':                  ['rohan-win',   'dc'],
  'sql-injection':        ['internet',    'web-server'],
  'port-scan':            ['harsh-win',   'fw-1'],
  'phishing':             ['nikhita-win', 'arjuna-win'],
  'privilege-escalation': ['priya-lin',   'edr-1'],
  'ransomware':           ['karan-win',   'arjuna-win'],
  'insider-threat':       ['sam-mac',     'siem'],
  'mitm':                 ['jesal-mac',   'dc'],
};

// Human-readable severity per attack
const ATTACK_SEVERITY: Record<AttackType, 'CRITICAL' | 'HIGH'> = {
  'brute-force':          'HIGH',
  'ddos':                 'CRITICAL',
  'dos':                  'HIGH',
  'sql-injection':        'CRITICAL',
  'port-scan':            'HIGH',
  'phishing':             'CRITICAL',
  'privilege-escalation': 'CRITICAL',
  'ransomware':           'CRITICAL',
  'insider-threat':       'HIGH',
  'mitm':                 'CRITICAL',
};

export function handleAttackLogic(type: AttackType, context: AttackContext) {
  const { nodes, updateNodeStatus, addLog, addAlert, setActiveAttacks } = context;

  const mapping = ATTACK_MAP[type];
  if (!mapping) return;

  const [attackerId, targetId] = mapping;
  const attackerNode = nodes.find(n => n.id === attackerId);
  const targetNode   = nodes.find(n => n.id === targetId);
  if (!attackerNode || !targetNode) return;

  const severity = ATTACK_SEVERITY[type] || 'CRITICAL';
  const eventType = `ATTACK_${type.toUpperCase().replace(/-/g, '_')}`;

  // Turn nodes RED
  updateNodeStatus(attackerNode.id, 'RED');
  updateNodeStatus(targetNode.id,   'RED');

  // Alert banner in sandbox UI
  addAlert({
    timestamp: Date.now(),
    ruleName:  `ATTACK DETECTED - ${type.toUpperCase()}`,
    srcDevice: attackerNode.hostname,
    dstDevice: targetNode.hostname,
    severity,
  });

  // Flood attack logs to both sandbox UI AND relay server
  let counter = 0;
  const logInterval = setInterval(() => {
    if (counter > 15) {
      clearInterval(logInterval);
      setActiveAttacks(prev => prev.filter(a => a !== type));
      return;
    }

    const attackLog = {
      timestamp:   Date.now(),
      srcIp:       attackerNode.ip,
      dstIp:       targetNode.ip,
      srcHostname: attackerNode.hostname,
      dstHostname: targetNode.hostname,
      eventType,
      severity,
      message: `[${type.toUpperCase()}] Malicious activity: ${attackerNode.hostname} (${attackerNode.ip}) → ${targetNode.hostname} (${targetNode.ip}) | Packet ${counter + 1}/16`,
    };

    addLog(attackLog as Omit<LogEntry, 'id'>);
    forwardLogToSIEM(attackLog);
    counter++;
  }, 300);
}
