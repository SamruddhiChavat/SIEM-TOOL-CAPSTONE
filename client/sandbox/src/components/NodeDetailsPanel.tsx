import React from 'react';
import { DeviceNode } from '../types';
import { X, Server, Shield, Monitor, MonitorCheck } from 'lucide-react';
import { useSimulation } from '../context/SimulationContext';

interface NodeDetailsPanelProps {
  node: DeviceNode;
  onClose: () => void;
}

export default function NodeDetailsPanel({ node, onClose }: NodeDetailsPanelProps) {
  const { logs, alerts } = useSimulation();

  // Get recent logs for this node
  const nodeLogs = logs
    .filter(l => l.srcIp === node.ip || l.dstIp === node.ip)
    .slice(0, 15);

  const nodeAlerts = alerts
    .filter(a => a.srcDevice === node.hostname || a.dstDevice === node.hostname)
    .slice(0, 5);

  const Icon = node.os === 'Appliance' ? Shield :
               node.os === 'Ubuntu' || node.os.includes('Server') ? Server :
               node.os === 'macOS' ? Monitor : MonitorCheck;

  let statusColor = 'text-[#00ff88]';
  let bgColor = 'bg-[#00ff88]/10 border-[#00ff88]/30';
  
  if (node.status === 'RED') {
    statusColor = 'text-[#ff3355]';
    bgColor = 'bg-[#ff3355]/20 border-[#ff3355]/50';
  } else if (node.status === 'YELLOW') {
    statusColor = 'text-[#ffaa00]';
    bgColor = 'bg-[#ffaa00]/10 border-[#ffaa00]/30';
  } else if (node.status === 'GREY') {
    statusColor = 'text-[#8b949e]';
    bgColor = 'bg-[#161b22] border-[#30363d]';
  }

  return (
    <div className="absolute top-0 right-0 w-80 h-full bg-[#0d1117] border-l border-[#30363d] shadow-2xl flex flex-col z-10 animate-slide-in">
      <div className="p-4 border-b border-[#30363d] flex justify-between items-start bg-[#161b22]">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg border ${bgColor} ${statusColor}`}>
            <Icon size={24} />
          </div>
          <div>
            <h3 className="font-bold text-[#e8eaed]">{node.hostname}</h3>
            <p className="text-xs text-[#8b949e] font-mono">{node.ip}</p>
          </div>
        </div>
        <button onClick={onClose} className="text-[#8b949e] hover:text-[#c9d1d9]">
          <X size={20} />
        </button>
      </div>

      <div className="p-4 border-b border-[#30363d] space-y-3">
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <span className="text-[#8b949e] text-xs block">OS</span>
            <span className="text-[#c9d1d9]">{node.os}</span>
          </div>
          <div>
            <span className="text-[#8b949e] text-xs block">Role</span>
            <span className="text-[#c9d1d9]">{node.role}</span>
          </div>
          <div>
            <span className="text-[#8b949e] text-xs block">Status</span>
            <span className={`font-bold ${statusColor}`}>{node.status}</span>
          </div>
          <div>
            <span className="text-[#8b949e] text-xs block">Group</span>
            <span className="text-[#c9d1d9] capitalize">{node.group}</span>
          </div>
        </div>
      </div>

      {nodeAlerts.length > 0 && (
        <div className="p-4 border-b border-[#30363d]">
          <h4 className="text-xs font-bold text-[#8b949e] mb-2 uppercase tracking-wider">Related Alerts</h4>
          <div className="space-y-2">
            {nodeAlerts.map(alert => (
              <div key={alert.id} className="text-xs p-2 rounded bg-[#161b22] border border-[#ff3355]/20 text-[#c9d1d9]">
                <span className="text-[#ff3355] font-bold block mb-1">{alert.ruleName}</span>
                <span className="text-[#8b949e]">{new Date(alert.timestamp).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto p-4">
        <h4 className="text-xs font-bold text-[#8b949e] mb-2 uppercase tracking-wider">Recent Activity</h4>
        <div className="space-y-2">
          {nodeLogs.length === 0 ? (
            <p className="text-xs text-[#8b949e]">No recent logs.</p>
          ) : (
            nodeLogs.map(log => (
              <div key={log.id} className="text-xs p-2 rounded bg-[#161b22] font-mono text-[#8b949e]">
                <span className={log.severity === 'CRITICAL' ? 'text-[#ff3355]' : 'text-[#8b949e]'}>
                  [{new Date(log.timestamp).toLocaleTimeString()}]
                </span>{' '}
                <span className="text-[#c9d1d9]">{log.eventType}</span>
                {log.severity === 'CRITICAL' && (
                  <p className="text-[#ff3355] mt-1">{log.message}</p>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
