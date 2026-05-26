import React from 'react';
import { useSimulation } from '../context/SimulationContext';
import { ShieldCheck, Skull, ServerCrash, CheckCircle, ShieldAlert } from 'lucide-react';

export default function AgentStatusPanel() {
  const { nodes } = useSimulation();

  const total       = nodes.length;
  const compromised = nodes.filter(n => n.status === 'RED').length;
  const suspicious  = nodes.filter(n => n.status === 'YELLOW').length;
  const healthy     = nodes.filter(n => n.status === 'GREEN').length;
  const offline     = nodes.filter(n => n.status === 'GREY').length;

  const pctCompromised = Math.round((compromised / total) * 100) || 0;
  const pctHealthy     = Math.round((healthy / total) * 100) || 0;

  const rows = [
    { label: 'Healthy',      count: healthy,     color: '#00ff88', icon: CheckCircle, subtitle: 'Normal operation' },
    { label: 'Suspicious',   count: suspicious,  color: '#ffaa00', icon: ServerCrash, subtitle: 'Anomalous telemetry' },
    { label: 'Compromised',  count: compromised, color: '#ff3355', icon: Skull,       subtitle: 'Active breach' },
    { label: 'Offline',      count: offline,     color: '#4d5562', icon: ShieldAlert, subtitle: 'No telemetry' },
  ];

  return (
    <div className="hud-card rounded-lg flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-3 py-2.5 border-b border-[#1e2d3d] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck size={13} className="text-[#00ff88]" />
          <span className="text-[10px] font-mono font-bold text-[#e8eaed] tracking-widest uppercase">Agent Health</span>
        </div>
        <span className="text-[9px] font-mono text-[#4d5562] bg-[#1a1f2e] border border-[#1e2d3d] px-2 py-0.5 rounded">
          {total} endpoints
        </span>
      </div>

      {/* Ring indicator */}
      <div className="px-4 py-3 flex items-center gap-4 border-b border-[#1e2d3d] bg-[#070b11]/40">
        {/* Mini donut-like bar */}
        <div className="relative w-14 h-14 shrink-0">
          <svg viewBox="0 0 56 56" className="-rotate-90 w-full h-full">
            <circle cx="28" cy="28" r="22" fill="none" stroke="#1e2d3d" strokeWidth="5" />
            <circle cx="28" cy="28" r="22" fill="none" stroke="#ff3355" strokeWidth="5"
              strokeDasharray={`${pctCompromised * 1.382} 138.2`}
              strokeLinecap="round"
              style={{ filter: 'drop-shadow(0 0 6px #ff3355)' }}
            />
            <circle cx="28" cy="28" r="22" fill="none" stroke="#00ff88" strokeWidth="5"
              strokeDasharray={`${pctHealthy * 1.382} 138.2`}
              strokeDashoffset={`${-pctCompromised * 1.382}`}
              strokeLinecap="round"
              style={{ filter: 'drop-shadow(0 0 4px #00ff88)' }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-[11px] font-mono font-bold text-[#c9d1d9]">{total}</span>
          </div>
        </div>

        <div className="flex flex-col gap-1 text-[9px] font-mono flex-1">
          <div className="flex justify-between">
            <span className="text-[#4d5562]">Healthy</span>
            <span className="text-[#00ff88]">{pctHealthy}%</span>
          </div>
          <div className="h-1 bg-[#1a1f2e] rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pctHealthy}%`, background: '#00ff88', boxShadow: '0 0 6px #00ff88' }} />
          </div>
          <div className="flex justify-between mt-0.5">
            <span className="text-[#4d5562]">Compromised</span>
            <span className="text-[#ff3355]">{pctCompromised}%</span>
          </div>
          <div className="h-1 bg-[#1a1f2e] rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pctCompromised}%`, background: '#ff3355', boxShadow: '0 0 6px #ff3355' }} />
          </div>
        </div>
      </div>

      {/* Agent rows */}
      <div className="flex-1 px-3 py-2 space-y-2 bg-[#070b11]/60">
        {rows.map(({ label, count, color, icon: Icon, subtitle }) => (
          <div key={label} className={`flex items-center gap-3 p-2 rounded border transition-all ${
            count > 0 ? 'border-opacity-30 bg-opacity-5' : 'border-transparent bg-transparent opacity-40'
          }`} style={count > 0 ? { borderColor: `${color}40`, backgroundColor: `${color}06` } : {}}>
            <div className="p-1.5 rounded shrink-0" style={count > 0 ? { background: `${color}15` } : { background: '#1a1f2e' }}>
              <Icon size={13} style={{ color: count > 0 ? color : '#4d5562' }} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[10px] font-bold font-mono" style={{ color: count > 0 ? '#c9d1d9' : '#4d5562' }}>{label}</div>
              <div className="text-[9px] text-[#4d5562]">{subtitle}</div>
            </div>
            <div className="text-base font-mono font-bold shrink-0 tabular-nums" style={{ color, textShadow: count > 0 ? `0 0 10px ${color}80` : 'none' }}>
              {count}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
