import React, { useEffect, useState, useMemo } from 'react';
import { useSimulation } from '../context/SimulationContext';
import { Activity, Zap, Server, Network, Cpu, TrendingUp, AlertOctagon } from 'lucide-react';

function MiniSparkline({ values, color = '#00d4ff' }: { values: number[]; color?: string }) {
  const max = Math.max(...values, 1);
  const w = 80, h = 30;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * w},${h - (v / max) * h}`).join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="overflow-visible">
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
      <polyline points={`0,${h} ${pts} ${w},${h}`} fill={`${color}20`} stroke="none" />
    </svg>
  );
}

function StatCard({
  icon: Icon, label, value, unit, color, sparkValues, suffix
}: {
  icon: React.ElementType; label: string; value: string | number; unit?: string; color: string; sparkValues?: number[]; suffix?: string;
}) {
  return (
    <div className="hud-card rounded-lg p-3 flex flex-col gap-1 relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/20 pointer-events-none" />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <Icon size={12} style={{ color }} />
          <span className="text-[9px] font-mono text-[#4d5562] uppercase tracking-widest">{label}</span>
        </div>
        {sparkValues && (
          <div className="opacity-60 group-hover:opacity-100 transition-opacity">
            <MiniSparkline values={sparkValues} color={color} />
          </div>
        )}
      </div>
      <div className="flex items-baseline gap-1">
        <span className="text-xl font-mono font-bold" style={{ color, textShadow: `0 0 12px ${color}60` }}>
          {value}
        </span>
        {unit && <span className="text-[9px] font-mono" style={{ color: `${color}80` }}>{unit}</span>}
        {suffix && <span className="text-[9px] font-mono text-[#4d5562]">{suffix}</span>}
      </div>
    </div>
  );
}

export default function TelemetryPanel() {
  const { logs, activeAttacks, nodes, alerts } = useSimulation();
  const [hist, setHist] = useState<number[]>(Array(12).fill(0));
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  const recentLogs = logs.filter(l => now - l.timestamp < 10000);
  const eps = Math.round(recentLogs.length / 10);

  // Update history
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHist(prev => [...prev.slice(1), eps]);
  }, [eps]);

  const critAlerts = useMemo(() => alerts.filter(a => a.severity === 'CRITICAL').length, [alerts]);
  const compromised = nodes.filter(n => n.status === 'RED').length;
  const suspicious = nodes.filter(n => n.status === 'YELLOW').length;

  return (
    <div className="hud-card rounded-lg flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-3 py-2.5 border-b border-[#1e2d3d] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity size={13} className="text-[#00d4ff]" />
          <span className="text-[10px] font-mono font-bold text-[#e8eaed] tracking-widest uppercase">Sandbox Telemetry</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="flex h-1.5 w-1.5 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff88] opacity-75" />
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#00ff88]" />
          </span>
          <span className="text-[8px] font-mono text-[#00ff88] tracking-widest">LIVE</span>
        </div>
      </div>

      {/* Stats grid */}
      <div className="flex-1 p-3 grid grid-cols-2 gap-2 bg-[#070b11]/60">
        <StatCard
          icon={Zap}
          label="Events/sec"
          value={eps}
          color="#00d4ff"
          sparkValues={hist}
        />
        <StatCard
          icon={Server}
          label="Total Events"
          value={logs.length > 999 ? `${(logs.length / 1000).toFixed(1)}k` : logs.length}
          color="#a855f7"
        />
        <StatCard
          icon={AlertOctagon}
          label="Critical Alerts"
          value={critAlerts}
          color="#ff3355"
        />
        <StatCard
          icon={Network}
          label="Attack Threads"
          value={activeAttacks.length}
          color="#ffaa00"
        />
        <StatCard
          icon={Cpu}
          label="Compromised"
          value={compromised}
          color={compromised > 0 ? '#ff3355' : '#4d5562'}
        />
        <StatCard
          icon={TrendingUp}
          label="Suspicious"
          value={suspicious}
          color={suspicious > 0 ? '#ffaa00' : '#4d5562'}
        />
      </div>

      {/* Active attack list */}
      {activeAttacks.length > 0 && (
        <div className="border-t border-[#1e2d3d] px-3 py-2 space-y-1 bg-[#0d1117]/80">
          <div className="text-[8px] font-mono text-[#4d5562] uppercase tracking-widest mb-1.5">Active Threads</div>
          {activeAttacks.map(a => (
            <div key={a} className="flex items-center gap-2 text-[9px] font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-[#ff3355] animate-ping shrink-0" />
              <span className="text-[#ff8899] uppercase tracking-wider truncate">{a.replace(/-/g, '_')}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
