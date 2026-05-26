import React, { useState, useEffect, useCallback, useRef } from 'react';
import { ATTACK_DEFS, AttackDef } from './data/attackDefs';
import {
  ORG_NODES, ORG_EDGES, INTERNAL_TARGETS, ATTACKERS,
  resolveAttackPath, OrgNode,
} from './data/orgTopology';
import TopologyPage from './pages/TopologyPage';
import C2Page from './pages/C2Page';
import SimulationPage from './pages/SimulationPage';

// ── Types ────────────────────────────────────────────────────
export interface LiveAttack {
  id: string;
  attackerId: string;       // external node id
  targetId: string;         // internal node id
  attackDef: AttackDef;
  path: string[];           // node-ids, layer by layer
  pathStep: number;         // which hop the packet is on
  status: 'propagating' | 'breached' | 'contained';
  startedAt: number;
  params: Record<string, string | number>;
  logLines: string[];
  alertId?: string;
}

type Tab = 'topology' | 'c2' | 'simulation';

// ── Main App ─────────────────────────────────────────────────
export default function App() {
  const [tab, setTab] = useState<Tab>('topology');
  const [attacks, setAttacks] = useState<LiveAttack[]>([]);
  const [compromised, setCompromised] = useState<Set<string>>(new Set());
  const [contained, setContained] = useState<Set<string>>(new Set());
  const [alertCount, setAlertCount] = useState(0);

  // ── Shared attacker/target selection (synced across Topology & C2 tabs) ──
  const [selectedAttackerId, setSelectedAttackerId] = useState<string>(ATTACKERS[0]?.id ?? '');
  const [selectedTargetId,   setSelectedTargetId]   = useState<string>(INTERNAL_TARGETS[0]?.id ?? '');

  // Interval refs for continuous looping
  const attackLoopRefs = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  // ── SSE: listen for SIEM isolate / remediate ────────────
  useEffect(() => {
    const es = new EventSource('/api/logs/stream');
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.eventType === 'RESPONSE_ISOLATE' || data.eventType === 'RESPONSE_REMEDIATE') {
          // Contain ALL active attacks — use functional updater to avoid stale closure
          setAttacks(prev => {
            const contained = prev.map(a =>
              a.status !== 'contained' ? { ...a, status: 'contained' as const } : a
            );
            // Also update the contained Set with current target IDs
            setContained(c => {
              const next = new Set(c);
              prev.forEach(a => next.add(a.targetId));
              return next;
            });
            return contained;
          });
        }
      } catch { /* ignore */ }
    };
    return () => es.close();
  }, []);
  // eslint-disable-line react-hooks/exhaustive-deps

  // ── Advance attack path step every 1.5s ─────────────────
  useEffect(() => {
    const tick = setInterval(() => {
      setAttacks(prev => prev.map(a => {
        if (a.status === 'contained') return a;
        const nextStep = a.pathStep + 1;
        if (nextStep >= a.path.length) {
          // Reached target — mark as breached, loop back to step 0
          setCompromised(c => new Set(c).add(a.targetId));
          return { ...a, pathStep: 0, status: 'breached' as const };
        }
        return { ...a, pathStep: nextStep };
      }));
    }, 1400);
    return () => clearInterval(tick);
  }, []);

  // ── Launch attack (called from C2Page) ──────────────────
  const launchAttack = useCallback(async (
    attackerId: string,
    targetId: string,
    def: AttackDef,
    params: Record<string, string | number>
  ) => {
    const path = ['internet', ...resolveAttackPath(targetId).slice(1)];
    // crypto.randomUUID() requires a secure context (HTTPS/localhost).
    // Fallback for LAN access over plain HTTP (e.g. http://192.168.x.x:5174).
    const id = (typeof crypto.randomUUID === 'function')
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}-${Math.random().toString(36).slice(2, 6)}`;


    const newAttack: LiveAttack = {
      id,
      attackerId,
      targetId,
      attackDef: def,
      path,
      pathStep: 0,
      status: 'propagating',
      startedAt: Date.now(),
      params,
      logLines: [],
    };

    setAttacks(prev => [...prev, newAttack]);
    setAlertCount(c => c + 1);

    const attacker = ORG_NODES.find(n => n.id === attackerId);
    const target   = ORG_NODES.find(n => n.id === targetId);

    // ── Emit live event to relay (SOC dashboard SSE) ────────
    const relayPayload = {
      eventType: def.id.toUpperCase().replace(/-/g, '_'),  // e.g. BRUTE_FORCE, DDOS, SQL_INJECTION
      severity: def.severity,
      srcIp: attacker?.ip ?? '0.0.0.0',
      srcHostname: attacker?.label ?? attackerId,
      dstIp: target?.ip ?? '10.0.0.0',
      dstHostname: target?.label ?? targetId,
      message: `[${def.name}] ${attacker?.label ?? attackerId} → ${target?.label ?? targetId} (${target?.ip ?? ''}) via ${def.id}`,
    };
    fetch('/api/logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(relayPayload),
    }).catch(() => {});

    // ── Also post to FastAPI backend for ES indexing (fire-and-forget) ──
    fetch('/api/sandbox/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        attack_type: def.id,
        source_device: attackerId,
        target_device: targetId,
        parameters: params,
      }),
    }).then(res => {
      if (res.ok) res.json().then(result => {
        setAttacks(prev => prev.map(a =>
          a.id === id ? { ...a, alertId: result.alert_id } : a
        ));
      }).catch(() => {});
    }).catch(() => { /* backend unavailable — animation runs regardless */ });

    // Append log lines one-by-one
    const steps = def.steps.map(s =>
      s.replace('{target_ip}', target?.ip ?? '10.x.x.x')
        .replace('{target_os}', target?.os ?? 'Unknown')
        .replace('{target_email}', `${target?.label.split("'")[0].toLowerCase()}@corp.local`)
        .replace('{attacker_ip}', attacker?.ip ?? '?')
    );
    steps.forEach((line, i) => {
      setTimeout(() => {
        setAttacks(prev => prev.map(a =>
          a.id === id ? { ...a, logLines: [...a.logLines, line] } : a
        ));
      }, i * 600);
    });
  }, []);

  // ── Contain specific attack ──────────────────────────────
  const containAttack = useCallback((attackId: string) => {
    setAttacks(prev => {
      const atk = prev.find(a => a.id === attackId);
      if (atk) {
        const target = ORG_NODES.find(n => n.id === atk.targetId);
        // Notify relay → SOC so asset flips to quarantined
        fetch('/api/logs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            eventType: 'RESPONSE_ISOLATE',
            severity: 'info',
            srcIp: '10.6.0.10',
            srcHostname: 'SecureWatch SIEM',
            dstIp: target?.ip ?? '',
            dstHostname: target?.label ?? atk.targetId,
            message: `[RESPONSE] Host ${target?.label ?? atk.targetId} isolated by SOC analyst`,
          }),
        }).catch(() => {});
      }
      return prev.map(a => a.id === attackId ? { ...a, status: 'contained' as const } : a);
    });
  }, []);

  // ── Clear all ────────────────────────────────────────────
  const clearAll = useCallback(() => {
    setAttacks([]);
    setCompromised(new Set());
    setContained(new Set());
    setAlertCount(0);
    // Clear relay store so SOC dashboard also resets
    fetch('/api/logs', { method: 'DELETE' }).catch(() => {});
  }, []);

  const activeAttacks = attacks.filter(a => a.status !== 'contained');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg-primary)', overflow: 'hidden' }}>
      {/* Fixed grid background */}
      <div className="grid-bg" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', opacity: 0.5, zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', height: '100%' }}>
        {/* ── Global Header ── */}
        <header style={{
          height: 50, flexShrink: 0, display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', padding: '0 20px',
          background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
          boxShadow: '0 1px 0 rgba(0,170,255,0.1)',
        }}>
          {/* Logo */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div className="font-display" style={{
              color: '#00ff88', fontSize: 13, fontWeight: 900,
              textShadow: '0 0 12px #00ff88', letterSpacing: '0.15em',
            }}>🛡 SECURE WATCH</div>
            <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 12,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
              color: 'var(--dim-text)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
              Attack Sandbox v3.0
            </div>
          </div>

          {/* Tab bar */}
          <nav style={{ display: 'flex', gap: 4 }}>
            {([
              { id: 'topology',   label: '🗺  NETWORK MAP' },
              { id: 'c2',         label: '⚡  ATTACK PANEL' },
              { id: 'simulation', label: '🎯  LIVE SIMULATION' },
            ] as { id: Tab; label: string }[]).map(t => (
              <button key={t.id} onClick={() => setTab(t.id)} style={{
                background: tab === t.id ? 'rgba(0,170,255,0.12)' : 'transparent',
                border: tab === t.id ? '1px solid rgba(0,170,255,0.4)' : '1px solid transparent',
                color: tab === t.id ? 'var(--neon-blue)' : 'var(--dim-text)',
                fontFamily: "'Orbitron', monospace", fontSize: 9, fontWeight: 700,
                letterSpacing: '0.12em', padding: '5px 14px', borderRadius: 4, cursor: 'pointer',
                transition: 'all 0.2s',
              }}>
                {t.label}
              </button>
            ))}
          </nav>

          {/* Right status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {activeAttacks.length > 0 && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                background: 'rgba(255,51,102,0.12)', border: '1px solid rgba(255,51,102,0.4)',
                borderRadius: 4, padding: '4px 10px', fontSize: 10,
                color: '#ff3366', fontFamily: "'Orbitron', monospace", fontWeight: 700,
              }}>
                <span className="dot-attack" />
                {activeAttacks.length} ACTIVE ATTACK{activeAttacks.length > 1 ? 'S' : ''}
              </div>
            )}
            <LiveClock />
            <a href={`http://${window.location.hostname}:3000`} target="_blank" rel="noopener noreferrer"
              className="btn-secondary" style={{ fontSize: 9, textDecoration: 'none', padding: '5px 12px' }}>
              → SOC Dashboard
            </a>
          </div>
        </header>

        {/* ── Page Content ── */}
        <div style={{ flex: 1, minHeight: 0, overflow: 'hidden' }}>
          {tab === 'topology' && (
            <TopologyPage
              nodes={ORG_NODES}
              edges={ORG_EDGES}
              attacks={attacks}
              compromised={compromised}
              contained={contained}
              selectedAttackerId={selectedAttackerId}
              selectedTargetId={selectedTargetId}
              onSelectAttacker={setSelectedAttackerId}
              onSelectTarget={setSelectedTargetId}
            />
          )}
          {tab === 'c2' && (
            <C2Page
              attackers={ATTACKERS}
              targets={INTERNAL_TARGETS}
              selectedAttackerId={selectedAttackerId}
              selectedTargetId={selectedTargetId}
              onSelectAttacker={setSelectedAttackerId}
              onSelectTarget={setSelectedTargetId}
              onLaunch={launchAttack}
              onClearAll={clearAll}
              activeAttacks={attacks}
              onContain={containAttack}
            />
          )}
          {tab === 'simulation' && (
            <SimulationPage
              attacks={attacks}
              nodes={ORG_NODES}
              onContain={containAttack}
              onClearAll={clearAll}
            />
          )}
        </div>
      </div>
    </div>
  );
}

const LiveClock: React.FC = () => {
  const [t, setT] = useState(new Date());
  useEffect(() => { const i = setInterval(() => setT(new Date()), 1000); return () => clearInterval(i); }, []);
  return (
    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: 'var(--dim-text)' }}>
      {t.toLocaleTimeString('en', { hour12: false })}
    </span>
  );
};
