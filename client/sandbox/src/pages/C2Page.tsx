import React, { useState, useCallback, useEffect } from 'react';
import { ATTACK_DEFS, AttackDef } from '../data/attackDefs';
import { OrgNode } from '../data/orgTopology';
import { LiveAttack } from '../App';

interface Props {
  attackers: OrgNode[];
  targets: OrgNode[];
  selectedAttackerId: string;
  selectedTargetId: string;
  onSelectAttacker: (id: string) => void;
  onSelectTarget: (id: string) => void;
  onLaunch: (attackerId: string, targetId: string, def: AttackDef, params: Record<string, string | number>) => void;
  onClearAll: () => void;
  activeAttacks: LiveAttack[];
  onContain: (id: string) => void;
}

function randomItem<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

export default function C2Page({ attackers, targets, selectedAttackerId, selectedTargetId, onSelectAttacker, onSelectTarget, onLaunch, onClearAll, activeAttacks, onContain }: Props) {
  const [selectedAttack, setSelectedAttack] = useState<AttackDef>(ATTACK_DEFS[0]);
  const [params, setParams]                 = useState<Record<string, string | number>>({});
  const [speed, setSpeed]                   = useState<number>(1.0);
  const [randomizing, setRandomizing]       = useState(false);

  // Use shared state from App
  const attackerId = selectedAttackerId;
  const targetId   = selectedTargetId;

  // Show current attacker/target labels
  const attackerNode = attackers.find(a => a.id === attackerId) || attackers[0];
  const targetNode   = targets.find(t => t.id === targetId)     || targets[0];

  const selectAttack = useCallback((a: AttackDef) => {
    setSelectedAttack(a);
    const defaults: Record<string, string | number> = {};
    a.params.forEach(p => { defaults[p.key] = p.default; });
    setParams(defaults);
  }, []);

  const pickRandom = useCallback(() => {
    setRandomizing(true);
    let count = 0;
    const interval = setInterval(() => {
      onSelectAttacker(randomItem(attackers).id);
      onSelectTarget(randomItem(targets).id);
      selectAttack(randomItem(ATTACK_DEFS));
      count++;
      if (count >= 8) {
        clearInterval(interval);
        const finalAttacker = randomItem(attackers);
        const finalTarget   = randomItem(targets.filter(t => t.id !== finalAttacker.id));
        const finalAttack   = randomItem(ATTACK_DEFS);
        onSelectAttacker(finalAttacker.id);
        onSelectTarget(finalTarget?.id || targets[0].id);
        selectAttack(finalAttack);
        setRandomizing(false);
      }
    }, 80);
  }, [attackers, targets, selectAttack, onSelectAttacker, onSelectTarget]);

  const runScenario = useCallback(async (def: AttackDef = selectedAttack) => {
    await onLaunch(attackerId, targetId, def, { ...params });
  }, [attackerId, targetId, selectedAttack, params, onLaunch]);

  const runRandom = useCallback(async () => {
    const ra = randomItem(attackers);
    const rt = randomItem(targets.filter(t => t.id !== ra.id));
    const rd = randomItem(ATTACK_DEFS);
    onSelectAttacker(ra.id);
    onSelectTarget(rt?.id || targets[0].id);
    selectAttack(rd);
    await new Promise(r => setTimeout(r, 150));
    await onLaunch(ra.id, rt?.id || targets[0].id, rd, {});
  }, [attackers, targets, selectAttack, onLaunch, onSelectAttacker, onSelectTarget]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg-primary)', overflowY: 'auto', padding: '0 32px 32px' }}>

      {/* ── Page Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '32px 0 24px' }}>
        <div>
          <h1 className="font-display" style={{ fontSize: 24, fontWeight: 700, color: 'var(--neon-white)', margin: '0 0 8px 0', textShadow: 'var(--glow-blue)' }}>ATTACK CONTROL PANEL</h1>
          <p style={{ color: 'var(--dim-text)', fontSize: 13, margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>Select a scenario, configure attacker/target, and launch — all events are forwarded live to the SIEM.</p>
        </div>
        {activeAttacks.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ff3366', display: 'inline-block', animation: 'pulse 1s infinite' }} />
            <span style={{ fontSize: 11, color: '#ff3366', fontFamily: 'monospace', fontWeight: 700 }}>{activeAttacks.length} ACTIVE ATTACK{activeAttacks.length > 1 ? 'S' : ''}</span>
          </div>
        )}
      </div>

      {/* ── Attack / Target Selectors ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        {/* Attacker */}
        <div className="cyber-panel" style={{ padding: 16 }}>
          <div style={{ fontSize: 9, color: 'var(--dim-text)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>⚡ ATTACKER (Source)</div>
          <select
            value={attackerId}
            onChange={e => onSelectAttacker(e.target.value)}
            style={{ width: '100%', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: 4, color: '#ff3366', fontSize: 13, fontWeight: 700, padding: '8px 10px', fontFamily: 'monospace', cursor: 'pointer' }}
          >
            {attackers.map(a => <option key={a.id} value={a.id} style={{ background: '#0a0a0f' }}>{a.label} ({a.ip})</option>)}
          </select>
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--dim-text)' }}>
            IP: <span style={{ color: '#ff3366', fontWeight: 600 }}>{attackerNode?.ip || '—'}</span>
            {' · '}Dept: <span style={{ color: 'var(--neon-white)' }}>{attackerNode?.dept || '—'}</span>
          </div>
        </div>

        {/* Target */}
        <div className="cyber-panel" style={{ padding: 16 }}>
          <div style={{ fontSize: 9, color: 'var(--dim-text)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>🎯 TARGET (Destination)</div>
          <select
            value={targetId}
            onChange={e => onSelectTarget(e.target.value)}
            style={{ width: '100%', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: 4, color: '#00aaff', fontSize: 13, fontWeight: 700, padding: '8px 10px', fontFamily: 'monospace', cursor: 'pointer' }}
          >
            {targets.map(t => <option key={t.id} value={t.id} style={{ background: '#0a0a0f' }}>{t.label} ({t.ip})</option>)}
          </select>
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--dim-text)' }}>
            IP: <span style={{ color: '#00aaff', fontWeight: 600 }}>{targetNode?.ip || '—'}</span>
            {' · '}Dept: <span style={{ color: 'var(--neon-white)' }}>{targetNode?.dept || '—'}</span>
          </div>
        </div>
      </div>

      {/* ── Scenario Library Grid (8 items, 4x2) ── */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ fontSize: 9, color: 'var(--dim-text)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 12 }}>SCENARIO LIBRARY</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
          {ATTACK_DEFS.map(def => {
            const isSelected = selectedAttack.id === def.id;
            return (
              <div
                key={def.id}
                onClick={() => selectAttack(def)}
                className={`cyber-card ${isSelected ? 'active' : ''}`}
                style={{
                  padding: 16, cursor: 'pointer',
                  display: 'flex', flexDirection: 'column',
                  background: isSelected ? 'rgba(0,170,255,0.07)' : 'var(--bg-panel)',
                  borderColor: isSelected ? 'rgba(0,170,255,0.5)' : undefined,
                  transition: 'all 0.15s',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                  <h3 style={{ fontSize: 12, fontWeight: 700, color: isSelected ? '#00aaff' : 'var(--neon-white)', margin: 0, paddingRight: 6 }}>{def.icon} {def.name}</h3>
                  <span className={`badge badge-${def.severity}`}>{def.severity}</span>
                </div>

                <p style={{ fontSize: 10, color: 'var(--dim-text)', margin: '0 0 12px 0', lineHeight: 1.4, flex: 1 }}>{def.description}</p>

                {/* Live source/target mini display */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 10 }}>
                  <div style={{ background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.25)', borderRadius: 4, padding: '5px 7px' }}>
                    <div style={{ fontSize: 8, color: 'rgba(255,51,102,0.7)', textTransform: 'uppercase', marginBottom: 2 }}>SRC</div>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#ff3366', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{attackerNode?.ip || '—'}</div>
                  </div>
                  <div style={{ background: 'rgba(0,170,255,0.08)', border: '1px solid rgba(0,170,255,0.25)', borderRadius: 4, padding: '5px 7px' }}>
                    <div style={{ fontSize: 8, color: 'rgba(0,170,255,0.7)', textTransform: 'uppercase', marginBottom: 2 }}>DST</div>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#00aaff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{targetNode?.ip || '—'}</div>
                  </div>
                </div>

                <button
                  onClick={e => {
                    e.stopPropagation();
                    selectAttack(def);
                    onLaunch(attackerId, targetId, def, { ...params });
                  }}
                  className="btn-launch"
                  style={{ padding: '7px', fontSize: 11, width: '100%', fontWeight: 700 }}
                >
                  ▶ LAUNCH
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Centered Simulation Controls ── */}
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <div className="cyber-panel" style={{ width: '100%', maxWidth: 660, borderRadius: 12, padding: 24, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div className="font-display" style={{ fontSize: 12, fontWeight: 700, color: 'var(--neon-blue)', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 20 }}>
            SIMULATION CONTROLS
          </div>

          <div style={{ display: 'flex', gap: 12, marginBottom: 20, width: '100%', justifyContent: 'center', flexWrap: 'wrap' }}>
            <button onClick={() => onLaunch(attackerId, targetId, selectedAttack, { ...params })} className="btn-launch" style={{ padding: '10px 20px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="none"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              START SCENARIO
            </button>

            <button
              onClick={pickRandom}
              disabled={randomizing}
              className="btn-secondary"
              style={{ padding: '10px 20px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8, opacity: randomizing ? 0.7 : 1 }}
            >
              🎲 {randomizing ? 'SELECTING...' : 'RANDOM PICK'}
            </button>

            <button
              onClick={runRandom}
              className="btn-secondary"
              style={{ padding: '10px 20px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8, borderColor: '#ff9900', color: '#ff9900' }}
            >
              ⚡ RANDOM ATTACK
            </button>

            <button onClick={onClearAll} className="btn-secondary" style={{ padding: '10px 20px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
              RESET ALL
            </button>
          </div>

          {/* Live Selection Display */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 20, width: '100%' }}>
            <div style={{ flex: 1, background: 'rgba(255,51,102,0.06)', border: '1px solid rgba(255,51,102,0.2)', borderRadius: 6, padding: '8px 12px', textAlign: 'center' }}>
              <div style={{ fontSize: 9, color: 'rgba(255,51,102,0.6)', textTransform: 'uppercase', marginBottom: 4 }}>Active Attacker</div>
              <div style={{ fontSize: 12, color: '#ff3366', fontWeight: 700, fontFamily: 'monospace' }}>{attackerNode?.label || '—'}</div>
              <div style={{ fontSize: 10, color: 'rgba(255,51,102,0.7)', fontFamily: 'monospace' }}>{attackerNode?.ip || '—'}</div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', fontSize: 18, color: 'var(--dim-text)' }}>→</div>
            <div style={{ flex: 1, background: 'rgba(0,170,255,0.06)', border: '1px solid rgba(0,170,255,0.2)', borderRadius: 6, padding: '8px 12px', textAlign: 'center' }}>
              <div style={{ fontSize: 9, color: 'rgba(0,170,255,0.6)', textTransform: 'uppercase', marginBottom: 4 }}>Active Target</div>
              <div style={{ fontSize: 12, color: '#00aaff', fontWeight: 700, fontFamily: 'monospace' }}>{targetNode?.label || '—'}</div>
              <div style={{ fontSize: 10, color: 'rgba(0,170,255,0.7)', fontFamily: 'monospace' }}>{targetNode?.ip || '—'}</div>
            </div>
          </div>

          {/* Speed control */}
          <div style={{ width: '100%', maxWidth: 400 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, color: 'var(--dim-text)', textTransform: 'uppercase' }}>Simulation Speed</span>
              <span style={{ fontSize: 12, color: 'var(--neon-white)', fontWeight: 600 }}>{speed.toFixed(1)}x</span>
            </div>
            <input
              type="range" min="0.5" max="3" step="0.5" value={speed}
              onChange={e => setSpeed(Number(e.target.value))}
              style={{ width: '100%' }}
            />
          </div>

          {/* Active attacks list */}
          {activeAttacks.length > 0 && (
            <div style={{ width: '100%', marginTop: 16, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
              <div style={{ fontSize: 9, color: 'var(--dim-text)', textTransform: 'uppercase', marginBottom: 8 }}>Active Attacks</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {activeAttacks.slice(0, 5).map(a => {
                  const srcNode = attackers.find(n => n.id === a.attackerId) || targets.find(n => n.id === a.attackerId);
                  const dstNode = targets.find(n => n.id === a.targetId) || attackers.find(n => n.id === a.targetId);
                  return (
                    <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(255,51,102,0.06)', border: '1px solid rgba(255,51,102,0.2)', borderRadius: 4, padding: '6px 10px' }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff3366', display: 'inline-block', flexShrink: 0, animation: 'pulse 1s infinite' }} />
                      <span style={{ fontSize: 11, color: 'var(--neon-white)', flex: 1 }}>{a.attackDef?.name || 'Unknown'}</span>
                      <span style={{ fontSize: 10, color: 'var(--dim-text)', fontFamily: 'monospace' }}>{srcNode?.ip || a.attackerId} → {dstNode?.ip || a.targetId}</span>
                      <button onClick={() => onContain(a.id)} style={{ fontSize: 10, color: '#00ff88', background: 'none', border: '1px solid rgba(0,255,136,0.3)', borderRadius: 3, padding: '2px 6px', cursor: 'pointer' }}>CONTAIN</button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
