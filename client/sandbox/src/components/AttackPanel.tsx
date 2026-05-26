import React from 'react';
import { useSimulation } from '../context/SimulationContext';
import { AttackType } from '../types';
import {
  Crosshair, Skull, UserX, Database, Lock, Globe, FileWarning,
  Cpu, Key, RadioTower, ShieldAlert
} from 'lucide-react';

interface Scenario {
  type: AttackType;
  name: string;
  desc: string;
  icon: React.ReactNode;
  mitre: string;
  severity: 'critical' | 'high' | 'medium';
  color: string;
}

const SCENARIOS: Scenario[] = [
  {
    type: 'brute-force',
    name: 'Brute Force SSH',
    desc: 'Karan Win → SIEM Server',
    icon: <Key size={16} />,
    mitre: 'T1110.001',
    severity: 'high',
    color: '#ffaa00',
  },
  {
    type: 'ddos',
    name: 'DDoS Attack',
    desc: 'External → Web Server',
    icon: <Globe size={16} />,
    mitre: 'T1498',
    severity: 'critical',
    color: '#ff3355',
  },
  {
    type: 'dos',
    name: 'DoS Attack',
    desc: 'Rohan Win → Domain Ctrl',
    icon: <Crosshair size={16} />,
    mitre: 'T1499',
    severity: 'critical',
    color: '#ff3355',
  },
  {
    type: 'sql-injection',
    name: 'SQL Injection',
    desc: 'External → Web Server',
    icon: <Database size={16} />,
    mitre: 'T1190',
    severity: 'high',
    color: '#ffaa00',
  },
  {
    type: 'port-scan',
    name: 'Port Scan / Recon',
    desc: 'Harsh Win → Firewall 1',
    icon: <RadioTower size={16} />,
    mitre: 'T1046',
    severity: 'medium',
    color: '#00d4ff',
  },
  {
    type: 'phishing',
    name: 'Phishing / Lateral',
    desc: 'Nikhita → Arjuna Win',
    icon: <FileWarning size={16} />,
    mitre: 'T1566',
    severity: 'high',
    color: '#ffaa00',
  },
  {
    type: 'privilege-escalation',
    name: 'Privilege Escalation',
    desc: 'Priya Linux → EDR Srv',
    icon: <Cpu size={16} />,
    mitre: 'T1068',
    severity: 'critical',
    color: '#ff3355',
  },
  {
    type: 'ransomware',
    name: 'Ransomware Spread',
    desc: 'Karan Win → Network',
    icon: <Lock size={16} />,
    mitre: 'T1486',
    severity: 'critical',
    color: '#ff3355',
  },
  {
    type: 'insider-threat',
    name: 'Insider Threat',
    desc: 'Samruddhi Mac → Leak',
    icon: <UserX size={16} />,
    mitre: 'T1078',
    severity: 'high',
    color: '#ffaa00',
  },
  {
    type: 'mitm',
    name: 'MITM / ARP Spoof',
    desc: 'Jesal Mac ↔ Domain Ctrl',
    icon: <Skull size={16} />,
    mitre: 'T1557',
    severity: 'critical',
    color: '#ff3355',
  },
];

const SEV_CONFIG = {
  critical: { label: 'CRITICAL', bg: 'bg-[#ff3355]/10', text: 'text-[#ff3355]', border: 'border-[#ff3355]/25' },
  high:     { label: 'HIGH',     bg: 'bg-[#ffaa00]/10', text: 'text-[#ffaa00]', border: 'border-[#ffaa00]/25' },
  medium:   { label: 'MEDIUM',   bg: 'bg-[#00d4ff]/10', text: 'text-[#00d4ff]', border: 'border-[#00d4ff]/25' },
};

export default function AttackPanel() {
  const { triggerAttack, activeAttacks } = useSimulation();

  return (
    <div className="shrink-0 border-b border-[#1e2d3d] bg-[#070b11]/80">
      {/* Panel Header */}
      <div className="px-5 py-3 flex items-center justify-between border-b border-[#1e2d3d]">
        <div className="flex items-center gap-3">
          <div className="relative">
            <ShieldAlert className="text-[#ff3355]" size={18} />
            {activeAttacks.length > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-[#ff3355]" />
            )}
          </div>
          <div>
            <h2 className="text-[11px] font-mono font-bold text-[#e8eaed] tracking-[0.15em] uppercase">
              Attack Simulation Control
            </h2>
            <p className="text-[9px] font-mono text-[#4d5562] tracking-wider">
              Select a scenario to initiate — real logs forwarded to SIEM
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {activeAttacks.length > 0 ? (
            <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#ff3355]/10 border border-[#ff3355]/30">
              <span className="w-1.5 h-1.5 rounded-full bg-[#ff3355] animate-ping" />
              <span className="text-[9px] font-mono text-[#ff3355] tracking-widest">
                {activeAttacks.length} ACTIVE SIMULATION{activeAttacks.length > 1 ? 'S' : ''}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#1a1f2e] border border-[#30363d]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#4d5562]" />
              <span className="text-[9px] font-mono text-[#4d5562] tracking-widest">STANDBY</span>
            </div>
          )}
        </div>
      </div>

      {/* Scenario Grid */}
      <div className="p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
        {SCENARIOS.map((s) => {
          const isActive = activeAttacks.includes(s.type);
          const sevCfg = SEV_CONFIG[s.severity];

          return (
            <button
              key={s.type}
              onClick={() => !isActive && triggerAttack(s.type)}
              disabled={isActive}
              className={`group relative flex flex-col items-start p-3 rounded-lg border text-left transition-all duration-200 overflow-hidden ${
                isActive
                  ? 'bg-[#ff3355]/8 border-[#ff3355]/50 cursor-not-allowed'
                  : 'bg-[#0d1117]/80 border-[#1e2d3d] hover:border-[#ff3355]/50 hover:bg-[#160c10] cursor-pointer'
              }`}
            >
              {/* Active shimmer overlay */}
              {isActive && (
                <div className="absolute inset-0 pointer-events-none">
                  <div className="absolute inset-0 bg-gradient-to-br from-[#ff3355]/5 to-transparent" />
                  <div className="absolute bottom-0 left-0 right-0 h-0.5 progress-bar" style={{ animation: 'none', background: 'linear-gradient(90deg, #ff3355, #ff6680, #ff3355)', backgroundSize: '200% 100%' }} />
                </div>
              )}

              {/* Top row: icon + severity */}
              <div className="flex items-center justify-between w-full mb-2">
                <div className={`p-1.5 rounded transition-colors ${isActive ? 'bg-[#ff3355]/20 text-[#ff3355]' : 'bg-[#1a1f2e] text-[#8b949e] group-hover:text-[#ff3355] group-hover:bg-[#ff3355]/10'}`}>
                  {s.icon}
                </div>
                <span className={`text-[8px] font-mono font-bold tracking-widest px-1.5 py-0.5 rounded border ${isActive ? 'bg-[#ff3355]/20 border-[#ff3355]/30 text-[#ff3355]' : `${sevCfg.bg} ${sevCfg.border} ${sevCfg.text}`}`}>
                  {isActive ? 'LIVE' : sevCfg.label}
                </span>
              </div>

              {/* Name */}
              <div className={`text-[11px] font-bold leading-tight font-mono mb-0.5 ${isActive ? 'text-[#ff6680]' : 'text-[#c9d1d9] group-hover:text-white'}`}>
                {s.name}
              </div>

              {/* Description */}
              <div className="text-[9px] text-[#4d5562] leading-tight truncate w-full group-hover:text-[#8b949e]">
                {s.desc}
              </div>

              {/* MITRE tag */}
              <div className={`mt-1.5 text-[8px] font-mono px-1.5 py-0.5 rounded ${isActive ? 'bg-[#ff3355]/15 text-[#ff8899]' : 'bg-[#161b22] text-[#4d5562] group-hover:text-[#a855f7] group-hover:bg-[#a855f7]/10'}`}>
                {s.mitre}
              </div>

              {/* Active progress bar */}
              {isActive && (
                <div className="w-full mt-2 h-0.5 bg-[#1a1f2e] rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-[#ff3355] via-[#ff6680] to-[#ff3355] animate-pulse w-full" />
                </div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
