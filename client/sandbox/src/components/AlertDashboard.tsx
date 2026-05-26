import React from 'react';
import { useSimulation } from '../context/SimulationContext';
import { AlertTriangle, ShieldAlert } from 'lucide-react';

export default function AlertDashboard() {
  const { alerts } = useSimulation();

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg flex flex-col h-full overflow-hidden">
      <div className="p-3 border-b border-[#30363d] bg-[#0d1117] flex justify-between items-center">
        <h3 className="font-mono text-[#e8eaed] font-bold flex items-center gap-2">
          <AlertTriangle className="text-[#ffaa00]" size={18} />
          ACTIVE_ALERTS
        </h3>
        <span className="bg-[#ff3355]/20 text-[#ff3355] px-2 py-0.5 rounded text-xs font-bold">
          {alerts.length} Total
        </span>
      </div>
      
      <div className="flex-1 overflow-y-auto p-2 space-y-2 bg-[#0d1117]">
        <div className="h-full flex flex-col items-center justify-center text-[#8b949e] gap-3 text-center px-4">
          <ShieldAlert size={48} className="text-[#00d4ff]/30" />
          <div>
            <p className="font-bold text-[#e8eaed]">Monitored by SecureWatch SIEM</p>
            <p className="text-xs mt-1">Alert generation and active response blocking are handled by your external SIEM tool.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
