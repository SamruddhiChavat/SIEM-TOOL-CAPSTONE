import React, { useEffect, useRef } from 'react';
import { useSimulation } from '../context/SimulationContext';
import { format } from 'date-fns';
import { Terminal, ArrowRight, AlertTriangle } from 'lucide-react';

const SEV_STYLE: Record<string, { row: string; badge: string; label: string }> = {
  CRITICAL: { row: 'bg-[#ff3355]/5 border-l-2 border-[#ff3355]/60',  badge: 'bg-[#ff3355]/15 text-[#ff6680] border-[#ff3355]/30', label: 'CRIT' },
  WARN:     { row: 'bg-[#ffaa00]/5 border-l-2 border-[#ffaa00]/40',  badge: 'bg-[#ffaa00]/10 text-[#ffcc44] border-[#ffaa00]/20', label: 'WARN' },
  INFO:     { row: '',                                                 badge: 'bg-[#1a1f2e] text-[#4d5562] border-[#1e2d3d]',       label: 'INFO' },
};

export default function LogStream() {
  const { logs } = useSimulation();
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const critCount = logs.filter(l => l.severity === 'CRITICAL').length;
  const warnCount = logs.filter(l => l.severity === 'WARN').length;

  return (
    <div className="h-52 border-t border-[#1e2d3d] bg-[#050810] flex flex-col shrink-0">
      {/* Header bar */}
      <div className="px-4 py-2 border-b border-[#1e2d3d] bg-[#0a0f1a] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <Terminal size={12} className="text-[#00d4ff]" />
          <span className="text-[9px] font-mono font-bold text-[#e8eaed] tracking-widest uppercase">Live Log Stream</span>
          <span className="text-[8px] font-mono text-[#4d5562]">// syslog pipeline</span>
        </div>
        <div className="flex items-center gap-4 text-[9px] font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#ff3355]" />
            <span className="text-[#ff6680]">{critCount} CRIT</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#ffaa00]" />
            <span className="text-[#ffcc44]">{warnCount} WARN</span>
          </div>
          <div className="text-[#4d5562]">
            {logs.length} events
          </div>
        </div>
      </div>

      {/* Log entries */}
      <div className="flex-1 overflow-y-auto px-2 py-1 space-y-0.5">
        {logs.slice(-80).map((log) => {
          const sev = log.severity as string;
          const s = SEV_STYLE[sev] || SEV_STYLE.INFO;
          const isAlert = sev === 'CRITICAL' || sev === 'WARN';

          return (
            <div
              key={log.id}
              className={`log-entry flex items-center gap-2 px-2 py-0.5 rounded-sm transition-colors hover:bg-[#0d1117] ${s.row}`}
            >
              {/* Timestamp */}
              <span className="text-[#2d3748] text-[9px] font-mono shrink-0 tabular-nums">
                {format(log.timestamp, 'HH:mm:ss.SSS')}
              </span>

              {/* Severity Badge */}
              <span className={`text-[8px] font-mono font-bold px-1 py-px rounded border shrink-0 ${s.badge}`}>
                {s.label}
              </span>

              {/* Protocol / event type */}
              {'protocol' in log && typeof log.protocol === 'string' && (
                <span className="text-[9px] font-mono text-[#a855f7]/80 shrink-0 hidden md:block">
                  {log.protocol}
                </span>
              )}

              {/* Source → Dest */}
              <div className="flex items-center gap-1 shrink-0">
                <span className="text-[9px] font-mono text-[#8b949e] tabular-nums">{log.srcIp}</span>
                <ArrowRight size={9} className="text-[#2d3748] shrink-0" />
                <span className={`text-[9px] font-mono tabular-nums ${isAlert ? 'text-[#c9d1d9] font-bold' : 'text-[#8b949e]'}`}>{log.dstIp}</span>
              </div>

              {/* Message */}
              <span className={`truncate text-[9px] font-mono flex-1 ${sev === 'CRITICAL' ? 'text-[#ff8899]' : sev === 'WARN' ? 'text-[#ffcc44]' : 'text-[#4d5562]'}`}>
                {log.message}
              </span>

              {/* Alert indicator */}
              {sev === 'CRITICAL' && (
                <AlertTriangle size={10} className="text-[#ff3355] shrink-0 animate-pulse" />
              )}
            </div>
          );
        })}
        <div ref={endRef} />
      </div>

      {/* Ticker */}
      <div className="border-t border-[#1e2d3d] bg-[#0a0f1a] py-1 overflow-hidden">
        <div className="flex gap-8 items-center font-mono text-[8px] text-[#2d3748] animate-marquee whitespace-nowrap">
          {[...Array(2)].flatMap(() => logs.slice(-10).map((l, i) => (
            <span key={`${l.id}-${i}`}>
              <span className={l.severity === 'CRITICAL' ? 'text-[#ff3355]' : l.severity === 'WARN' ? 'text-[#ffaa00]' : ''}>
                [{l.severity}]
              </span>{' '}
              {l.srcIp} → {l.dstIp}: {l.message.substring(0, 60)}
            </span>
          )))}
        </div>
      </div>
    </div>
  );
}
