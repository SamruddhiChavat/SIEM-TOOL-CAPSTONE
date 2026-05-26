import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { DeviceNode, NetworkEdge, LogEntry, Alert, CorrelationRule, AttackType } from '../types';
import { initialNodes, initialEdges } from '../data/initialData';
import { generateBackgroundLog, handleAttackLogic } from './simulationEngine';

interface SimulationContextType {
  nodes: DeviceNode[];
  edges: NetworkEdge[];
  logs: LogEntry[];
  alerts: Alert[];
  rules: CorrelationRule[];
  activeAttacks: AttackType[];
  triggerAttack: (type: AttackType) => void;
  resetSimulation: () => void;
  clearAlerts: () => void;
  updateNodeStatus: (id: string, status: DeviceNode['status']) => void;
  addLog: (log: Omit<LogEntry, 'id'>) => void;
  addAlert: (alert: Omit<Alert, 'id' | 'status'>) => void;
  addRule: (rule: Omit<CorrelationRule, 'id' | 'timestamp'>) => void;
}

const SimulationContext = createContext<SimulationContextType | undefined>(undefined);

export function SimulationProvider({ children }: { children: ReactNode }) {
  const [nodes, setNodes] = useState<DeviceNode[]>(initialNodes);
  const [edges, setEdges] = useState<NetworkEdge[]>(initialEdges);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [activeAttacks, setActiveAttacks] = useState<AttackType[]>([]);

  const addLog = useCallback((log: Omit<LogEntry, 'id'>) => {
    setLogs(prev => {
      const newLogs = [{ ...log, id: Math.random().toString(36).substring(7) }, ...prev];
      return newLogs.slice(0, 1000); // Keep last 1000 logs
    });

    // Forward to Relay Backend
    fetch('http://localhost:4000/api/logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(log)
    }).catch(err => console.error("Failed to forward log to relay server:", err));
  }, []);

  const addAlert = useCallback((alert: Omit<Alert, 'id' | 'status'>) => {
    setAlerts(prev => [{ ...alert, id: Math.random().toString(36).substring(7), status: 'Open' }, ...prev]);
  }, []);

  const addRule = useCallback((rule: Omit<CorrelationRule, 'id' | 'timestamp'>) => {
    setRules(prev => [{ ...rule, id: Math.random().toString(36).substring(7), timestamp: Date.now() }, ...prev]);
  }, []);

  const updateNodeStatus = useCallback((id: string, status: DeviceNode['status']) => {
    setNodes(prev => prev.map(node => node.id === id ? { ...node, status } : node));
  }, []);

  const triggerAttack = useCallback((type: AttackType) => {
    if (activeAttacks.includes(type)) return; // Prevent triggering same attack twice
    setActiveAttacks(prev => [...prev, type]);
    
    // Call the simulation engine handler to start the sequence
    handleAttackLogic(type, { nodes, updateNodeStatus, addLog, addAlert, addRule, setActiveAttacks });
  }, [activeAttacks, nodes, updateNodeStatus, addLog, addAlert, addRule]);

  const resetSimulation = useCallback(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    setLogs([]);
    setAlerts([]);
    setRules([]);
    setActiveAttacks([]);
  }, []);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
  }, []);

  // Background noise generator
  useEffect(() => {
    const interval = setInterval(() => {
      const log = generateBackgroundLog(nodes);
      addLog(log);
    }, 2000); // Every 2 seconds

    return () => clearInterval(interval);
  }, [nodes, addLog]);

  // Sync SIEM responses back to Sandbox in real-time via SSE
  useEffect(() => {
    const es = new EventSource('/api/logs/stream');
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.eventType === 'RESPONSE_ISOLATE') {
          const target = data.dstIp || data.destIp;
          setNodes(prev => {
            const node = prev.find(n => n.ip === target || n.hostname === target);
            return node ? prev.map(n => n.id === node.id ? { ...n, status: 'YELLOW' } : n) : prev;
          });
        } else if (data.eventType === 'RESPONSE_REMEDIATE') {
          const target = data.dstIp || data.destIp;
          setNodes(prev => {
            const node = prev.find(n => n.ip === target || n.hostname === target);
            return node ? prev.map(n => n.id === node.id ? { ...n, status: 'GREEN' } : n) : prev;
          });
        }
      } catch { /* ignore parse errors */ }
    };
    return () => es.close();
  }, []);

  return (
    <SimulationContext.Provider
      value={{
        nodes,
        edges,
        logs,
        alerts,
        rules,
        activeAttacks,
        triggerAttack,
        resetSimulation,
        clearAlerts,
        updateNodeStatus,
        addLog,
        addAlert,
        addRule
      }}
    >
      {children}
    </SimulationContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useSimulation() {
  const context = useContext(SimulationContext);
  if (context === undefined) {
    throw new Error('useSimulation must be used within a SimulationProvider');
  }
  return context;
}
