import React from 'react';
import { useSimulation } from '../context/SimulationContext';
import { Activity, Zap } from 'lucide-react';

export default function RulesPanel() {
  useSimulation();

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg flex flex-col h-full overflow-hidden">
      <div className="p-3 border-b border-[#30363d] bg-[#0d1117] flex justify-between items-center">
        <h3 className="font-mono text-[#e8eaed] font-bold flex items-center gap-2">
          <Activity className="text-[#00d4ff]" size={18} />
          CORRELATION_RULES
        </h3>
      </div>
      
      <div className="flex-1 overflow-y-auto p-2 space-y-2 bg-[#0d1117]">
        <div className="h-full flex flex-col items-center justify-center text-[#8b949e] gap-3 text-center px-4">
          <Zap size={48} className="text-[#00d4ff]/30" />
          <div>
            <p className="font-bold text-[#e8eaed]">Rules Engine Active Externally</p>
            <p className="text-xs mt-1">Check your SecureWatch dashboard for correlation rule hits and attack patterns.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
