import React, { useRef, useEffect } from 'react';

export interface StatusLine {
  id: string;
  ts: number;
  text: string;
  type: 'info' | 'attack' | 'detect' | 'ok' | 'err';
}

interface Props {
  lines: StatusLine[];
  isRunning: boolean;
}

const COLOR: Record<string, string> = {
  info:   '#8888aa',
  attack: '#ff3366',
  detect: '#00aaff',
  ok:     '#00ff88',
  err:    '#ff6600',
};

const PREFIX: Record<string, string> = {
  info:   '  →',
  attack: '  ⚡',
  detect: '  🛡',
  ok:     '  ✓',
  err:    '  ✗',
};

const AttackStatusFeed: React.FC<Props> = ({ lines, isRunning }) => {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  return (
    <div style={{
      background: 'rgba(5,5,14,0.9)',
      border: '1px solid #1e1e3a',
      borderRadius: 6,
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 10,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '6px 12px',
        borderBottom: '1px solid #1e1e3a',
        background: 'rgba(10,10,20,0.6)',
      }}>
        <span style={{ color: '#8888aa', letterSpacing: '0.1em', fontSize: 9, textTransform: 'uppercase' }}>
          Attack Status Feed
        </span>
        {isRunning && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 5,
            background: 'rgba(255,51,102,0.12)',
            border: '1px solid rgba(255,51,102,0.3)',
            borderRadius: 3, padding: '2px 7px', fontSize: 8, color: '#ff3366',
            fontWeight: 700, letterSpacing: '0.1em',
          }}>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#ff3366', display: 'inline-block', animation: 'pulse-slow 1s ease-in-out infinite' }} />
            RUNNING
          </span>
        )}
      </div>

      {/* Log lines */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '8px 0',
        minHeight: 120,
        maxHeight: 160,
      }}>
        {lines.length === 0 ? (
          <div style={{ color: '#3a3a5a', padding: '16px 14px', textAlign: 'center', fontSize: 10 }}>
            — No attacks launched yet. Select an attack and click Launch. —
          </div>
        ) : (
          lines.map(line => (
            <div key={line.id} className="log-entry" style={{
              display: 'flex', gap: 10, padding: '2px 12px',
              borderLeft: `2px solid ${COLOR[line.type]}22`,
            }}>
              <span style={{ color: '#3a3a5a', minWidth: 70, flexShrink: 0 }}>
                {new Date(line.ts).toLocaleTimeString('en', { hour12: false })}
              </span>
              <span style={{ color: COLOR[line.type], minWidth: 24 }}>{PREFIX[line.type]}</span>
              <span style={{ color: line.type === 'ok' ? '#00ff88' : line.type === 'attack' ? '#ff3366' : '#d0d8f0' }}>
                {line.text}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};

export default AttackStatusFeed;
