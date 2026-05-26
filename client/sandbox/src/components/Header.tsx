import React from 'react';
import { useSimulation } from '../context/SimulationContext';
import { Shield, RotateCcw, Download, AlertTriangle, Wifi, Clock } from 'lucide-react';

export default function Header() {
  const { resetSimulation, activeAttacks, nodes } = useSimulation();

  const compromised = nodes.filter(n => n.status === 'RED').length;
  const suspicious = nodes.filter(n => n.status === 'YELLOW').length;
  const now = new Date();

  return (
    <header className="h-14 border-b border-[#1e2d3d] bg-[#070b11]/95 backdrop-blur flex items-center justify-between px-6 shrink-0 z-20 relative">
      {/* Left: brand + threat badge */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Shield className="text-[#00d4ff]" size={22} />
            {activeAttacks.length > 0 && (
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#ff3355] animate-ping" />
            )}
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-[13px] font-bold text-white tracking-[0.12em] font-mono">SECUREWATCH</span>
            <span className="text-[9px] font-mono text-[#00d4ff]/60 tracking-[0.2em] uppercase">Cyber Attack Sandbox</span>
          </div>
        </div>

        {/* Threat Level Indicator */}
        <div className={`ml-3 px-3 py-1 rounded border text-[10px] font-mono font-bold tracking-widest flex items-center gap-2 transition-all ${
          compromised > 0
            ? 'bg-[#ff3355]/10 border-[#ff3355]/50 text-[#ff3355] animate-pulse'
            : suspicious > 0
            ? 'bg-[#ffaa00]/10 border-[#ffaa00]/50 text-[#ffaa00]'
            : 'bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]'
        }`}>
          <AlertTriangle size={10} />
          {compromised > 0 ? `BREACH DETECTED · ${compromised} COMPROMISED` : suspicious > 0 ? `THREAT ACTIVE · ${suspicious} SUSPICIOUS` : 'SYSTEM SECURE'}
        </div>
      </div>

      {/* Center: Live status strip */}
      <div className="flex items-center gap-6 text-[10px] font-mono">
        <div className="flex items-center gap-2 text-[#8b949e]">
          <Wifi size={11} className="text-[#00ff88]" />
          <span className="text-[#00ff88]">RELAY CONNECTED</span>
        </div>
        <div className="flex items-center gap-2 text-[#8b949e]">
          <Clock size={11} />
          <span className="tabular-nums">{now.toLocaleTimeString('en-IN', { hour12: false })}</span>
        </div>
        <div className="h-4 w-px bg-[#30363d]" />
        <div className="text-[#8b949e]">
          ENDPOINTS: <span className="text-[#c9d1d9]">{nodes.length}</span>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-3">
        <button
          onClick={resetSimulation}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#161b22] hover:bg-[#1f2940] border border-[#30363d] hover:border-[#00d4ff]/40 rounded text-[11px] font-mono transition-all text-[#8b949e] hover:text-[#00d4ff]"
        >
          <RotateCcw size={12} />
          RESET
        </button>
        <button className="flex items-center gap-1.5 px-3 py-1.5 bg-[#161b22] hover:bg-[#161b22] border border-[#30363d] hover:border-[#00d4ff]/40 rounded text-[11px] font-mono transition-all text-[#8b949e] hover:text-[#00d4ff]">
          <Download size={12} />
          EXPORT
        </button>
      </div>
    </header>
  );
}
