import React from 'react';
import { LiveAttack } from '../App';
import { OrgNode } from '../data/orgTopology';

interface Props {
  attacks: LiveAttack[];
  nodes: OrgNode[];
  onContain: (id: string) => void;
  onClearAll: () => void;
}

const SEV_COLORS: Record<string, string> = {
  critical: '#ff3366', high: '#ff6600', medium: '#ffcc00',
};

export default function SimulationPage({ attacks, nodes, onContain, onClearAll }: Props) {
  const getNode = (id: string) => nodes.find(n => n.id === id);

  const active    = attacks.filter(a => a.status !== 'contained');
  const contained = attacks.filter(a => a.status === 'contained');
  const breached  = attacks.filter(a => a.status === 'breached');

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>

      {/* ── LEFT: KPIs + Active attacks ── */}
      <div style={{
        width: 340, flexShrink: 0, borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', background: 'var(--bg-panel)', overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <div className="font-display" style={{ color: '#ff3366', fontSize: 11, letterSpacing: '0.2em', fontWeight: 700 }}>
            🎯 LIVE SIMULATION
          </div>
        </div>

        {/* KPI row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 1, padding: '0', flexShrink: 0, borderBottom: '1px solid var(--border)' }}>
          {[
            { label: 'ACTIVE',    value: active.length,    color: '#ff6600' },
            { label: 'BREACHED',  value: breached.length,  color: '#ff3366' },
            { label: 'CONTAINED', value: contained.length, color: '#00aaff' },
          ].map(k => (
            <div key={k.label} style={{
              padding: '12px 8px', textAlign: 'center',
              background: 'var(--bg-card)', borderRight: '1px solid var(--border)',
            }}>
              <div style={{ color: k.color, fontSize: 22, fontWeight: 700, fontFamily: "'Orbitron', monospace" }}>{k.value}</div>
              <div style={{ color: 'var(--dim-text)', fontSize: 8, letterSpacing: '0.1em' }}>{k.label}</div>
            </div>
          ))}
        </div>

        {/* Active attack list */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px' }}>
          {attacks.length === 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#3a3a5a', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
              No attacks launched yet
            </div>
          ) : (
            attacks.map(a => {
              const target = getNode(a.targetId);
              const attacker = getNode(a.attackerId);
              const sevColor = SEV_COLORS[a.attackDef.severity] ?? '#ffcc00';
              return (
                <div key={a.id} style={{
                  background: 'var(--bg-card)',
                  border: `1px solid ${a.status === 'contained' ? 'rgba(0,170,255,0.3)' : a.status === 'breached' ? 'rgba(255,51,102,0.5)' : 'rgba(255,102,0,0.35)'}`,
                  borderRadius: 5, padding: '9px 10px', marginBottom: 7,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: a.attackDef.color, fontWeight: 600, fontSize: 10 }}>
                      {a.attackDef.icon} {a.attackDef.name}
                    </span>
                    <span className={`badge badge-${a.attackDef.severity}`}>{a.attackDef.severity}</span>
                  </div>

                  <div style={{ fontSize: 8, color: 'var(--dim-text)', marginBottom: 6, lineHeight: 1.7 }}>
                    <div>☠ <span style={{ color: '#ff3366' }}>{attacker?.label}</span> [{attacker?.ip}]</div>
                    <div>🎯 <span style={{ color: '#00aaff' }}>{target?.label}</span> [{target?.ip}]</div>
                    <div>📍 Dept: {target?.dept}</div>
                    <div style={{ color: '#3a3a5a' }}>
                      Started: {new Date(a.startedAt).toLocaleTimeString('en', { hour12: false })}
                    </div>
                  </div>

                  {/* Path progress */}
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 7, color: 'var(--dim-text)', marginBottom: 3 }}>
                      Hop {Math.min(a.pathStep + 1, a.path.length)}/{a.path.length}: {a.path[Math.min(a.pathStep, a.path.length - 1)]}
                    </div>
                    <div style={{ height: 3, background: '#1e1e3a', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%', borderRadius: 2,
                        width: `${(a.pathStep / Math.max(a.path.length - 1, 1)) * 100}%`,
                        background: a.status === 'contained' ? '#00aaff' : sevColor,
                        transition: 'width 0.4s ease',
                      }} />
                    </div>
                  </div>

                  {a.status !== 'contained' && (
                    <button onClick={() => onContain(a.id)} style={{
                      width: '100%', background: 'rgba(0,170,255,0.08)',
                      border: '1px solid rgba(0,170,255,0.3)', color: '#00aaff',
                      fontFamily: "'JetBrains Mono', monospace", fontSize: 8,
                      padding: '4px', borderRadius: 3, cursor: 'pointer',
                    }}>🔒 CONTAIN ATTACK</button>
                  )}
                </div>
              );
            })
          )}
        </div>

        <div style={{ padding: '8px', borderTop: '1px solid var(--border)', flexShrink: 0 }}>
          <button onClick={onClearAll} style={{
            width: '100%', background: 'transparent', border: '1px solid var(--border)',
            color: 'var(--dim-text)', fontFamily: "'JetBrains Mono', monospace",
            fontSize: 9, padding: '7px', borderRadius: 4, cursor: 'pointer',
          }}>🧹 Clear All</button>
        </div>
      </div>

      {/* ── RIGHT: Combined attack terminal ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-panel)', flexShrink: 0, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="font-display" style={{ color: '#00ff88', fontSize: 10, letterSpacing: '0.15em', fontWeight: 700 }}>
            ⌨ ATTACK TERMINAL
          </div>
          <span style={{ fontSize: 8, color: 'var(--dim-text)', fontFamily: "'JetBrains Mono', monospace" }}>
            Real-time simulation output
          </span>
        </div>

        <div style={{
          flex: 1, overflowY: 'auto', padding: '14px 16px',
          fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
          background: 'rgba(0,0,0,0.3)', lineHeight: 1.8,
        }}>
          {attacks.length === 0 && (
            <div style={{ color: '#3a3a5a' }}>
              <div>╔═══════════════════════════════════════════╗</div>
              <div>║  SecureWatch Attack Sandbox — Terminal    ║</div>
              <div>║  Go to C2 tab to launch attacks           ║</div>
              <div>╚═══════════════════════════════════════════╝</div>
            </div>
          )}
          {[...attacks].reverse().map(a => {
            const attacker = getNode(a.attackerId);
            const target   = getNode(a.targetId);
            return (
              <div key={a.id} style={{ marginBottom: 20 }}>
                {/* Operation header */}
                <div style={{ color: a.attackDef.color, marginBottom: 4, borderBottom: `1px solid ${a.attackDef.color}30`, paddingBottom: 4 }}>
                  ══════ {a.attackDef.icon} {a.attackDef.name.toUpperCase()} | {a.attackDef.mitre_id} ══════
                </div>
                <div style={{ color: '#3a3a5a', marginBottom: 6, fontSize: 9 }}>
                  Source: {attacker?.ip ?? a.attackerId} → Target: {target?.ip ?? a.targetId} | {new Date(a.startedAt).toLocaleTimeString('en', { hour12: false })}
                </div>

                {/* Layer-by-layer path */}
                <div style={{ marginBottom: 8, color: '#3a5a3a', fontSize: 9 }}>
                  {'> Traversal: '}
                  {a.path.map((step, i) => (
                    <span key={step}>
                      <span style={{
                        color: i <= a.pathStep ? '#00ff88' : '#1e3e1e',
                        fontWeight: i === Math.min(a.pathStep, a.path.length - 1) ? 700 : 400,
                      }}>
                        {step}
                      </span>
                      {i < a.path.length - 1 && <span style={{ color: '#1e3e1e' }}> → </span>}
                    </span>
                  ))}
                </div>

                {/* Log lines */}
                {a.logLines.map((l, i) => (
                  <div key={i} style={{
                    color: l.startsWith('> [+]') ? '#00ff88'
                          : l.startsWith('> [*]') ? '#00aaff'
                          : l.startsWith('> [FAIL') || l.startsWith('> [ERROR') ? '#ff6600'
                          : l.startsWith('> [FLOOD') || l.startsWith('> [ENCRYPT') || l.startsWith('> [TRANSFER') ? '#ff3366'
                          : l.startsWith('> //') ? '#3a3a5a'
                          : '#c8d1d9',
                    animation: 'log-in 0.2s ease-out',
                  }}>
                    {l}
                  </div>
                ))}

                {/* Status footer */}
                {a.status !== 'propagating' && (
                  <div style={{
                    marginTop: 6, color: a.status === 'contained' ? '#00aaff' : '#ff3366',
                    fontWeight: 700,
                  }}>
                    {a.status === 'contained'
                      ? '> [SIEM] 🔒 Attack contained — host isolated by SOC analyst'
                      : '> [!] 💀 TARGET BREACHED — system compromised'}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
