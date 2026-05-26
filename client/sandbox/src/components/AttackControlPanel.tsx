import React, { useState, useCallback } from 'react';
import AttackStatusFeed, { StatusLine } from './AttackStatusFeed';
import { TopoNode, AttackEvent } from './NetworkTopologyGraph';

// ── Attack catalogue ─────────────────────────────────────────
interface AttackDef {
  id: string;
  name: string;
  mitre_id: string;
  mitre_tactic: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  color: string;
  params: ParamDef[];
}

interface ParamDef {
  key: string;
  label: string;
  type: 'slider' | 'select' | 'text' | 'time';
  options?: string[];
  min?: number;
  max?: number;
  default: string | number;
  unit?: string;
}

const ATTACKS: AttackDef[] = [
  {
    id: 'file_exfiltration',
    name: 'Large File Exfiltration',
    mitre_id: 'T1041',
    mitre_tactic: 'Exfiltration',
    severity: 'critical',
    color: '#ff3366',
    description: 'Simulates an endpoint sending >500 MB of data to an external destination.',
    params: [
      { key: 'file_size_mb',       label: 'File Size (MB)',     type: 'slider', min: 100, max: 2000, default: 600, unit: 'MB' },
      { key: 'destination_ip',     label: 'Destination IP',     type: 'text',                        default: '203.0.113.45' },
      { key: 'protocol',           label: 'Protocol',           type: 'select', options: ['HTTP','FTP','SMB'], default: 'HTTP' },
    ],
  },
  {
    id: 'unusual_hours',
    name: 'Unusual Hours Access',
    mitre_id: 'T1078',
    mitre_tactic: 'Initial Access',
    severity: 'high',
    color: '#ff6600',
    description: 'Simulates a user authenticating and accessing sensitive resources outside business hours.',
    params: [
      { key: 'target_resource',    label: 'Target Resource',    type: 'select', options: ['File Server','HR Database','Finance DB','Admin Panel'], default: 'Finance DB' },
      { key: 'user_account',       label: 'User Account',       type: 'text',                         default: 'j.smith' },
      { key: 'timestamp_override', label: 'Access Time',        type: 'time',                         default: '02:15' },
    ],
  },
  {
    id: 'lateral_movement',
    name: 'Lateral Movement — Port Scan',
    mitre_id: 'T1046',
    mitre_tactic: 'Discovery',
    severity: 'high',
    color: '#ff6600',
    description: 'Simulates an internal host scanning other hosts across multiple ports.',
    params: [
      { key: 'target_subnet',     label: 'Target Subnet',      type: 'text',                          default: '192.168.1.0/24' },
      { key: 'port_range',        label: 'Port Range',         type: 'text',                          default: '22-445' },
      { key: 'scan_speed',        label: 'Scan Speed',         type: 'select', options: ['Slow','Normal','Aggressive'], default: 'Normal' },
    ],
  },
  {
    id: 'credential_stuffing',
    name: 'Credential Stuffing',
    mitre_id: 'T1110.004',
    mitre_tactic: 'Credential Access',
    severity: 'critical',
    color: '#ff3366',
    description: 'Simulates rapid repeated failed login attempts against a service.',
    params: [
      { key: 'target_service',    label: 'Target Service',     type: 'select', options: ['SSH','RDP','Web App','VPN'], default: 'SSH' },
      { key: 'attempts_count',    label: 'Attempts',           type: 'slider', min: 10, max: 200, default: 50 },
      { key: 'time_window_sec',   label: 'Time Window (sec)',  type: 'slider', min: 10, max: 300, default: 60 },
    ],
  },
  {
    id: 'dns_anomaly',
    name: 'DNS Anomaly — High-Freq Queries',
    mitre_id: 'T1071.004',
    mitre_tactic: 'Command & Control',
    severity: 'critical',
    color: '#aa55ff',
    description: 'Simulates DNS tunneling or C2 beaconing via high-frequency subdomain queries.',
    params: [
      { key: 'base_domain',       label: 'Base Domain',        type: 'text',                          default: 'c2-beacon.net' },
      { key: 'query_rate_qps',    label: 'Query Rate (q/s)',   type: 'slider', min: 5, max: 200, default: 30 },
      { key: 'duration_sec',      label: 'Duration (sec)',     type: 'slider', min: 5, max: 120, default: 30 },
    ],
  },
];

// ── Script sequences per attack ───────────────────────────────
function buildScript(attack: AttackDef, params: Record<string, string | number>, srcLabel: string, dstLabel: string): Array<{ delay: number; text: string; type: StatusLine['type'] }> {
  const base = [
    { delay: 0,    text: `Initialising attack module: ${attack.name}`,      type: 'info' as const },
    { delay: 300,  text: `Source: ${srcLabel}`,                              type: 'info' as const },
    { delay: 600,  text: `Target: ${dstLabel}`,                             type: 'info' as const },
    { delay: 900,  text: `MITRE Technique: ${attack.mitre_id} (${attack.mitre_tactic})`, type: 'info' as const },
  ];

  const specific: Array<{ delay: number; text: string; type: StatusLine['type'] }> = (() => {
    switch (attack.id) {
      case 'file_exfiltration': return [
        { delay: 1200, text: `Opening ${params.protocol} channel to ${params.destination_ip}`, type: 'attack' },
        { delay: 1800, text: `Chunking ${params.file_size_mb} MB payload into 16 MB segments`, type: 'attack' },
        { delay: 2400, text: `→ Sending segment 1/16  [16 MB] …`, type: 'attack' },
        { delay: 2800, text: `→ Sending segment 4/16  [64 MB] …`, type: 'attack' },
        { delay: 3200, text: `→ Sending segment 8/16  [128 MB] …`, type: 'attack' },
        { delay: 3600, text: `→ Transfer complete: ${params.file_size_mb} MB exfiltrated`, type: 'attack' },
      ];
      case 'unusual_hours': return [
        { delay: 1200, text: `Forging auth token for user: ${params.user_account}`,          type: 'attack' },
        { delay: 1800, text: `Authenticating at ${params.timestamp_override} (outside hours)`, type: 'attack' },
        { delay: 2400, text: `→ Auth success — accessing: ${params.target_resource}`,        type: 'attack' },
        { delay: 2800, text: `→ Reading sensitive records …`,                                 type: 'attack' },
      ];
      case 'lateral_movement': return [
        { delay: 1200, text: `Initiating ${params.scan_speed} scan of ${params.target_subnet}`, type: 'attack' },
        { delay: 1800, text: `→ Probing port range ${params.port_range} on each host`,        type: 'attack' },
        { delay: 2200, text: `→ 192.168.1.10: 22/open  445/open`,                             type: 'attack' },
        { delay: 2600, text: `→ 192.168.1.11: 3389/open  135/open`,                           type: 'attack' },
        { delay: 3000, text: `→ Scan complete — ${Math.floor(Math.random()*10+5)} hosts mapped`, type: 'attack' },
      ];
      case 'credential_stuffing': return [
        { delay: 1200, text: `Loading credential list (${params.attempts_count} pairs)`,      type: 'attack' },
        { delay: 1800, text: `→ Auth attempt  1/${params.attempts_count}  [FAILED]`,           type: 'attack' },
        { delay: 2200, text: `→ Auth attempt 10/${params.attempts_count}  [FAILED]`,           type: 'attack' },
        { delay: 2600, text: `→ Auth attempt 25/${params.attempts_count}  [FAILED]`,           type: 'attack' },
        { delay: 3000, text: `→ ${params.attempts_count} attempts in ${params.time_window_sec}s window`, type: 'attack' },
      ];
      case 'dns_anomaly': return [
        { delay: 1200, text: `Starting DNS beacon to *.${params.base_domain}`,                type: 'attack' },
        { delay: 1800, text: `→ Rate: ${params.query_rate_qps} queries/s for ${params.duration_sec}s`, type: 'attack' },
        { delay: 2200, text: `→ Querying: a1b2c3.${params.base_domain}`,                      type: 'attack' },
        { delay: 2600, text: `→ Querying: x9y8z7.${params.base_domain}`,                      type: 'attack' },
        { delay: 3000, text: `→ ${Math.round(Number(params.query_rate_qps)*Number(params.duration_sec))} unique subdomain queries sent`, type: 'attack' },
      ];
      default: return [];
    }
  })();

  const tail = [
    { delay: 3600, text: `Injecting synthetic log into Elasticsearch…`,  type: 'info' as const },
    { delay: 4000, text: `Alert generated — forwarding to SIEM…`,        type: 'detect' as const },
    { delay: 4400, text: `✓ Simulation complete. Check Incident Feed.`,  type: 'ok' as const },
  ];

  return [...base, ...specific, ...tail];
}

// ── Props ─────────────────────────────────────────────────────
interface Props {
  devices: TopoNode[];
  onAttackLaunched: (event: AttackEvent) => void;
}

// ── Component ─────────────────────────────────────────────────
const AttackControlPanel: React.FC<Props> = ({ devices, onAttackLaunched }) => {
  const [selectedAttack, setSelectedAttack] = useState<AttackDef>(ATTACKS[0]);
  const [sourceDevice, setSourceDevice]     = useState<string>(devices[4]?.id ?? '');
  const [targetDevice, setTargetDevice]     = useState<string>(devices[7]?.id ?? '');
  const [params, setParams]                 = useState<Record<string, string|number>>({});
  const [feedLines, setFeedLines]           = useState<StatusLine[]>([]);
  const [isRunning, setIsRunning]           = useState(false);
  const [error, setError]                   = useState('');
  const API_BASE = '/api/sandbox';    // proxied through vite or nginx

  // Initialise params from defaults when attack changes
  const selectAttack = useCallback((a: AttackDef) => {
    setSelectedAttack(a);
    const defaults: Record<string, string|number> = {};
    a.params.forEach(p => { defaults[p.key] = p.default; });
    setParams(defaults);
    setError('');
  }, []);

  const setParam = (key: string, value: string | number) => {
    setParams(prev => ({ ...prev, [key]: value }));
  };

  const addLine = (line: Omit<StatusLine, 'id'>) => {
    setFeedLines(prev => [...prev, { ...line, id: crypto.randomUUID() }]);
  };

  const launchAttack = useCallback(async () => {
    if (isRunning) return;
    setIsRunning(true);
    setFeedLines([]);
    setError('');

    const srcNode  = devices.find(d => d.id === sourceDevice);
    const dstNode  = devices.find(d => d.id === targetDevice);
    const srcLabel = srcNode?.label  ?? sourceDevice;
    const dstLabel = dstNode?.label  ?? targetDevice;

    // Build the animated script
    const script = buildScript(selectedAttack, params, srcLabel, dstLabel);

    // Schedule script lines as timed events
    const timers: ReturnType<typeof setTimeout>[] = [];
    script.forEach(({ delay, text, type }) => {
      timers.push(setTimeout(() => addLine({ ts: Date.now(), text, type }), delay));
    });

    // POST to backend
    try {
      const body = {
        attack_type:    selectedAttack.id,
        source_device:  sourceDevice,
        target_device:  targetDevice,
        parameters:     params,
      };
      const resp = await fetch(`${API_BASE}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        const err = await resp.text();
        throw new Error(`Backend error ${resp.status}: ${err}`);
      }
      const result = await resp.json();

      // Notify parent graph
      onAttackLaunched({
        id:           result.alert_id,
        attack_type:  selectedAttack.id,
        source_node:  sourceDevice,
        target_node:  targetDevice,
        severity:     selectedAttack.severity,
        technique_id: selectedAttack.mitre_id,
        timestamp:    new Date().toISOString(),
        message:      result.message ?? selectedAttack.name,
      });
    } catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : String(e);
      setError(errMsg);
      addLine({ ts: Date.now(), text: `Backend error: ${errMsg}`, type: 'err' });
    }

    // Clear running after final script line
    const maxDelay = Math.max(...script.map(s => s.delay)) + 800;
    setTimeout(() => setIsRunning(false), maxDelay);

    return () => timers.forEach(clearTimeout);
  }, [isRunning, selectedAttack, params, sourceDevice, targetDevice, devices, onAttackLaunched]);

  const badgeClass = `badge badge-${selectedAttack.severity}`;

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      overflowY: 'auto',
      background: 'var(--bg-panel)',
      borderRight: '1px solid var(--border)',
    }}>
      {/* ── Panel header ── */}
      <div style={{
        padding: '14px 16px 10px',
        borderBottom: '1px solid var(--border)',
        flexShrink: 0,
      }}>
        <div className="font-display" style={{ color: '#00aaff', fontSize: 11, letterSpacing: '0.2em', fontWeight: 700, textTransform: 'uppercase', marginBottom: 2 }}>
          ⚡ Command & Control
        </div>
        <div style={{ color: 'var(--dim-text)', fontSize: 9 }}>Red Team Attack Simulator</div>
      </div>

      <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>
        {/* ── Device selectors ── */}
        <div>
          <div style={{ fontSize: 9, color: 'var(--dim-text)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Device Selection</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <div>
              <label style={{ fontSize: 9, color: 'var(--dim-text)', display: 'block', marginBottom: 3 }}>SOURCE (Attacker)</label>
              <select
                className="cyber-select"
                value={sourceDevice}
                onChange={e => setSourceDevice(e.target.value)}
              >
                {devices.map(d => (
                  <option key={d.id} value={d.id}>{d.label} [{d.ip}]</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 9, color: 'var(--dim-text)', display: 'block', marginBottom: 3 }}>TARGET (Victim)</label>
              <select
                className="cyber-select"
                value={targetDevice}
                onChange={e => setTargetDevice(e.target.value)}
              >
                {devices.map(d => (
                  <option key={d.id} value={d.id}>{d.label} [{d.ip}]</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* ── Attack cards ── */}
        <div>
          <div style={{ fontSize: 9, color: 'var(--dim-text)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Attack Type</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {ATTACKS.map(a => (
              <div
                key={a.id}
                className={`attack-card ${a.id === selectedAttack.id ? 'selected' : ''}`}
                onClick={() => selectAttack(a)}
                style={{ padding: '9px 12px' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 3 }}>
                  <div style={{ color: a.id === selectedAttack.id ? a.color : 'var(--neon-white)', fontWeight: 600, fontSize: 11 }}>
                    {a.name}
                  </div>
                  <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                </div>
                <div style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 8, color: '#aa55ff', background: 'rgba(170,85,255,0.1)', border: '1px solid rgba(170,85,255,0.25)', borderRadius: 3, padding: '1px 5px' }}>
                    {a.mitre_id}
                  </span>
                  <span style={{ fontSize: 8, color: 'var(--dim-text)' }}>{a.mitre_tactic}</span>
                </div>
                <div style={{ fontSize: 9, color: 'var(--dim-text)', lineHeight: 1.5 }}>{a.description}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Parameters ── */}
        <div>
          <div style={{ fontSize: 9, color: 'var(--dim-text)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
            Parameters — {selectedAttack.name}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {selectedAttack.params.map(p => (
              <div key={p.key}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <label style={{ fontSize: 9, color: 'var(--neon-white)' }}>{p.label}</label>
                  {p.type === 'slider' && (
                    <span style={{ fontSize: 9, color: 'var(--neon-blue)' }}>
                      {params[p.key] ?? p.default} {p.unit ?? ''}
                    </span>
                  )}
                </div>
                {p.type === 'slider' && (
                  <input
                    type="range"
                    min={p.min} max={p.max}
                    value={Number(params[p.key] ?? p.default)}
                    onChange={e => setParam(p.key, Number(e.target.value))}
                  />
                )}
                {p.type === 'select' && (
                  <select
                    className="cyber-select"
                    value={String(params[p.key] ?? p.default)}
                    onChange={e => setParam(p.key, e.target.value)}
                  >
                    {p.options?.map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                )}
                {(p.type === 'text' || p.type === 'time') && (
                  <input
                    type={p.type === 'time' ? 'time' : 'text'}
                    className="cyber-input"
                    value={String(params[p.key] ?? p.default)}
                    onChange={e => setParam(p.key, e.target.value)}
                  />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* ── Launch button ── */}
        <button
          className="btn-launch"
          onClick={launchAttack}
          disabled={isRunning}
          style={{ width: '100%', fontSize: 11, padding: '10px' }}
        >
          {isRunning ? '⚡ ATTACK IN PROGRESS…' : '⚡ LAUNCH ATTACK'}
        </button>

        {/* ── Error ── */}
        {error && (
          <div style={{ fontSize: 9, color: '#ff6600', background: 'rgba(255,102,0,0.08)', border: '1px solid rgba(255,102,0,0.3)', borderRadius: 4, padding: '6px 10px' }}>
            ✗ {error}
          </div>
        )}

        {/* ── Status feed ── */}
        <AttackStatusFeed lines={feedLines} isRunning={isRunning} />
      </div>
    </div>
  );
};

export default AttackControlPanel;
