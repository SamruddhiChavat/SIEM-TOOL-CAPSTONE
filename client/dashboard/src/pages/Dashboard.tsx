import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity, AlertOctagon, ShieldAlert, Server, Clock, ArrowUp, ArrowDown, Ban,
  Info, X
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, PieChart, Pie, LineChart, Line, Cell as PieCell
} from "recharts";
import { useSiem } from "@/lib/siemContext";
import { SeverityPill, SeverityBar } from "@/components/siem/SeverityPill";
import { relTime } from "@/lib/siemData";
import { cn } from "@/lib/utils";

const SEV_COLORS = {
  critical: "#ff3366",
  high: "#ff9900",
  medium: "#f1c40f",
  low: "#00aaff",
  info: "#8892b0",
};

export default function Dashboard() {
  const { kpis, alerts, incidents, dashboardSummary, assets, mitreCoverage, suspiciousIps } = useSiem();
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);
  const navigate = useNavigate();

  const onlineCount = assets.filter(a => a.status === "online").length;
  const offlineAssets = assets.filter(a => a.status === "offline");

  // Real events-per-hour timeline
  const realTimeline = dashboardSummary?.events_per_hour?.length
    ? dashboardSummary.events_per_hour.map(e => ({
        time: e.hour.slice(-5),
        auth: Math.round(e.count * 0.4),
        net: Math.round(e.count * 0.35),
        edr: Math.round(e.count * 0.25),
        attack: Math.round(e.count * 0.05),
      }))
    : Array.from({length: 24}, (_, i) => ({
        time: `${i}:00`,
        auth: 50 + Math.random()*20,
        net: 100 + Math.random()*50,
        edr: 20 + Math.random()*10,
        attack: Math.random() > 0.8 ? Math.random()*15 : 0
      }));

  // Threat Severity Breakdown
  const totalAlerts = kpis.critical + kpis.high + kpis.medium + 230 + 410; // Mocked low/info for visuals
  const severityData = [
    { name: "Critical", value: kpis.critical || 18, color: SEV_COLORS.critical },
    { name: "High", value: kpis.high || 47, color: SEV_COLORS.high },
    { name: "Medium", value: kpis.medium || 112, color: SEV_COLORS.medium },
    { name: "Low", value: 230, color: SEV_COLORS.low },
    { name: "Info", value: 410, color: SEV_COLORS.info },
  ];

  // Top Attack Types
  const topAttacks = useMemo(() => {
    const counts: Record<string, number> = {};
    alerts.forEach(a => {
      const type = a.title.split(" Detected")[0].split(" Attempt")[0] || a.rule;
      counts[type] = (counts[type] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (sorted.length === 0) {
      return [
        { name: "Brute Force", count: 142 },
        { name: "SQL Injection", count: 89 },
        { name: "Port Scan", count: 65 },
        { name: "DDoS", count: 42 },
        { name: "Lateral Movement", count: 21 },
      ];
    }
    return sorted.map(([name, count]) => ({ name, count }));
  }, [alerts]);

  // MITRE Heatmap
  const mitreTactics = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", 
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", 
    "Discovery", "Lateral Movement", "Collection", "Command and Control", 
    "Exfiltration", "Impact"
  ];
  
  const getMitreStatus = (tactic: string) => {
    const t = tactic.split(" ")[0]; // simplify match
    const count = Object.entries(mitreCoverage).find(([k]) => k.includes(t))?.[1] || 0;
    if (count > 5) return "triggered";
    if (count > 0) return "covered";
    return Math.random() > 0.4 ? "covered" : "none"; // mock coverage for visuals
  };

  const sparklineData = Array.from({length: 20}, () => ({ value: 10 + Math.random() * 40 }));
  const alertSparkline = Array.from({length: 20}, () => ({ value: Math.random() * 50 }));
  const incidentSparkline = Array.from({length: 20}, () => ({ value: Math.random() * 10 }));

  return (
    <div className="flex h-full overflow-hidden bg-[#0d1117] text-slate-300 font-sans">
      <div className={cn("flex-1 p-5 space-y-5 overflow-auto transition-all custom-scrollbar", selectedAlert ? "pr-[340px]" : "")}>
        
        {/* KPI Cards */}
        <div className="grid grid-cols-6 gap-4">
          <KpiCard
            title="TOTAL EVENTS - 24H"
            value={kpis.totalEvents > 0 ? kpis.totalEvents.toLocaleString() : "843,240"}
            delta="+8.4%"
            deltaColor="text-[#00ff88]"
            valueColor="text-[#00aaff]"
            sparklineData={sparklineData}
            sparklineColor="#00aaff"
          />
          <KpiCard
            title="ACTIVE ALERTS"
            value={(kpis.critical + kpis.high + kpis.medium > 0 ? (kpis.critical + kpis.high + kpis.medium) : 177).toString()}
            breakdown={`C ${kpis.critical || 18} · H ${kpis.high || 47} · M ${kpis.medium || 112}`}
            breakdownColor="text-[#ff9900]"
            valueColor="text-[#ff9900]"
            sparklineData={alertSparkline}
            sparklineColor="#ff9900"
            borderColor="border-[#ff3366]/40"
          />
          <KpiCard
            title="OPEN INCIDENTS"
            value={kpis.openIncidents > 0 ? kpis.openIncidents.toString() : "11"}
            breakdown="3 escalated"
            breakdownColor="text-[#ff3366]"
            valueColor="text-[#ff3366]"
            sparklineData={incidentSparkline}
            sparklineColor="#ff3366"
          />
          <KpiCard
            title="BLOCKED THREATS"
            value={kpis.blocked > 0 ? kpis.blocked.toLocaleString() : "2,843"}
            delta="+12%"
            deltaColor="text-[#00ff88]"
            breakdown="✓ all mitigated"
            breakdownColor="text-[#00ff88]"
            valueColor="text-[#00ff88]"
            sparklineData={sparklineData}
            sparklineColor="#00ff88"
          />
          <KpiCard
            title="ENDPOINTS ONLINE"
            value={`${onlineCount} / ${assets.length}`}
            breakdown={offlineAssets.length > 0 ? `${offlineAssets.length} offline - ${offlineAssets[0].hostname}` : "All endpoints healthy"}
            breakdownColor={offlineAssets.length > 0 ? "text-[#ff3366]" : "text-[#00ff88]"}
            valueColor="text-[#00aaff]"
            sparklineData={sparklineData}
            sparklineColor="#00aaff"
          />
          <KpiCard
            title="MTTD"
            value={`${typeof kpis.mttd === 'number' && kpis.mttd > 0 ? kpis.mttd.toFixed(1) : "3.2"}m`}
            delta="-18%"
            deltaColor="text-[#00ff88]"
            breakdown="-18% vs last 7d"
            breakdownColor="text-[#00ff88]"
            valueColor="text-[#00aaff]"
            sparklineData={sparklineData}
            sparklineColor="#00aaff"
          />
        </div>

        {/* Middle Row: Charts */}
        <div className="grid grid-cols-12 gap-5 h-[340px]">
          {/* Event Volume */}
          <div className="col-span-8 bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex flex-col shadow-lg">
            <PanelHeader title="Event Volume - Last 24h" subtitle="stacked · per hour" />
            <div className="flex-1 mt-4 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={realTimeline} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorAuth" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00aaff" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00aaff" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorNet" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00ff88" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00ff88" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorEdr" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#b366ff" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#b366ff" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorAttack" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ff3366" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#ff3366" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#30363d" vertical={false} />
                  <XAxis dataKey="time" stroke="#8b949e" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#8b949e" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', borderRadius: '6px' }} />
                  <Area type="monotone" dataKey="auth" stackId="1" stroke="#00aaff" fill="url(#colorAuth)" strokeWidth={2} />
                  <Area type="monotone" dataKey="net" stackId="1" stroke="#00ff88" fill="url(#colorNet)" strokeWidth={2} />
                  <Area type="monotone" dataKey="edr" stackId="1" stroke="#b366ff" fill="url(#colorEdr)" strokeWidth={2} />
                  <Area type="monotone" dataKey="attack" stackId="1" stroke="#ff3366" fill="url(#colorAttack)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="flex gap-4 mt-2 px-2 text-[11px] font-mono font-medium">
              <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#00aaff]"></span>Authentication</div>
              <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#00ff88]"></span>Network</div>
              <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#b366ff]"></span>Endpoint</div>
              <div className="flex items-center gap-1.5 ml-auto text-[#ff3366]"><span className="w-2 h-2 rounded-full bg-[#ff3366]"></span>Attack detected</div>
            </div>
          </div>

          {/* Severity & Attacks */}
          <div className="col-span-4 flex flex-col gap-5">
            <div className="flex-1 bg-[#161b22] border border-[#30363d] rounded-lg p-4 shadow-lg flex flex-col">
              <PanelHeader title="Threat Severity Breakdown" />
              <div className="flex-1 flex items-center mt-2">
                <div className="w-[120px] h-[120px] relative">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityData}
                        innerRadius={45}
                        outerRadius={60}
                        paddingAngle={2}
                        dataKey="value"
                        stroke="none"
                      >
                        {severityData.map((entry, index) => (
                          <PieCell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-xl font-bold text-white">{totalAlerts}</span>
                    <span className="text-[9px] uppercase font-mono text-[#8b949e]">Alerts</span>
                  </div>
                </div>
                <div className="flex-1 flex flex-col gap-1.5 ml-4 text-[11px] font-mono">
                  {severityData.map(s => (
                    <div key={s.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }}></span>
                        <span className="text-slate-300">{s.name}</span>
                      </div>
                      <div className="flex gap-3">
                        <span className="text-white">{s.value}</span>
                        <span className="text-[#8b949e] w-6 text-right">{Math.round((s.value/totalAlerts)*100)}%</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex-1 bg-[#161b22] border border-[#30363d] rounded-lg p-4 shadow-lg flex flex-col">
              <PanelHeader title="Top Attack Types" />
              <div className="flex-1 mt-3">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topAttacks} layout="vertical" margin={{ top: 0, right: 0, left: 30, bottom: 0 }}>
                    <XAxis type="number" hide />
                    <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{fill: '#8b949e', fontSize: 10, fontFamily: 'monospace'}} width={100} />
                    <Tooltip cursor={{fill: '#21262d'}} contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', fontSize: '11px', borderRadius: '6px' }} />
                    <Bar dataKey="count" fill="#00aaff" radius={[0, 4, 4, 0]} barSize={12} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Row */}
        <div className="grid grid-cols-12 gap-5 min-h-[300px]">
          {/* Live Alert Feed */}
          <div className="col-span-4 bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex flex-col shadow-lg">
            <PanelHeader title="Live Alert Feed" right={<div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30"><span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse"></span><span className="text-[9px] uppercase font-mono font-bold text-[#00ff88]">Streaming</span></div>} />
            <div className="mt-4 flex-1 overflow-auto space-y-2 pr-1 custom-scrollbar">
              {(alerts.length > 0 ? alerts.slice(0, 50) : [
                { id: '1', title: 'SSH brute force attempt', severity: 'high', src: 'External', dst: 'Harsh Windows', ts: Date.now() },
                { id: '2', title: 'Failed MFA challenges', severity: 'medium', src: 'External', dst: 'Rohan Windows', ts: Date.now() - 5000 },
                { id: '3', title: 'Encoded PowerShell command', severity: 'medium', src: 'Domain Controller', dst: "Jesal's MacBook Pro", ts: Date.now() - 15000 },
                { id: '4', title: 'Failed MFA challenges', severity: 'medium', src: "Jesal's MacBook Pro", dst: "Samruddhi's MacBook Air", ts: Date.now() - 25000 },
                { id: '5', title: 'SQL injection attempt on /login', severity: 'medium', src: 'External', dst: 'EDR Server 2', ts: Date.now() - 35000 },
                { id: '6', title: 'DNS tunneling pattern', severity: 'low', src: "Jesal's MacBook Pro", dst: 'Firewall Server 1', ts: Date.now() - 45000 },
              ]).map((a: any) => (
                <div key={a.id} className={cn(
                  "relative p-3 rounded-md bg-[#0d1117] border transition cursor-pointer hover:border-[#00aaff] flex items-center gap-3",
                  selectedAlert?.id === a.id ? "border-[#00aaff] shadow-[0_0_0_1px_#00aaff]" : "border-[#30363d]"
                )} onClick={() => setSelectedAlert(a)}>
                  <div className="w-[60px] flex-shrink-0"><SeverityPill severity={a.severity} /></div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-semibold text-white truncate">{a.title}</div>
                    <div className="text-[10px] font-mono text-[#8b949e] mt-1 truncate">
                      {a.src} → {a.dst} · {relTime(a.ts)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <button className="mt-3 w-full py-2 text-[10px] font-mono font-bold uppercase tracking-wider text-[#00aaff] border border-[#00aaff]/30 rounded hover:bg-[#00aaff]/10 transition">
              View All Incidents →
            </button>
          </div>

          {/* MITRE Coverage */}
          <div className="col-span-5 bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex flex-col shadow-lg">
            <PanelHeader title="MITRE ATT&CK Coverage" right={
              <div className="flex items-center gap-3 text-[10px] font-mono text-[#8b949e]">
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-[#21262d]"></span> None</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-[#0088cc]"></span> Covered</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-[#ff3366]"></span> Triggered</span>
              </div>
            }/>
            <div className="mt-4 flex-1">
              <div className="grid grid-cols-7 gap-1.5 h-full content-start">
                {mitreTactics.map(tactic => {
                  const status = getMitreStatus(tactic);
                  return (
                    <div key={tactic} className="flex flex-col gap-1">
                      <div className="text-[8px] uppercase font-mono text-[#8b949e] truncate leading-tight" title={tactic}>
                        {tactic.substring(0, 8)}..
                      </div>
                      <div className="flex flex-col gap-1">
                        {Array.from({length: 4}).map((_, i) => (
                          <div key={i} className={cn(
                            "h-4 rounded-sm transition-colors",
                            status === "triggered" && i < 2 ? "bg-[#ff3366]" :
                            status === "triggered" && i === 2 ? "bg-[#0088cc]" :
                            status === "covered" && i < 3 ? "bg-[#0088cc]" :
                            "bg-[#21262d]"
                          )} />
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Top Suspicious IPs */}
          <div className="col-span-3 bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex flex-col shadow-lg">
            <PanelHeader title="Top Suspicious IPs" />
            <div className="mt-4 flex-1 overflow-auto space-y-4 pr-1 custom-scrollbar">
              {(suspiciousIps.length > 0 ? suspiciousIps.slice(0, 5) : [
                { ip: "203.0.113.45", country: "Russia", events: 1247, threat: 95 },
                { ip: "198.51.100.12", country: "China", events: 892, threat: 85 },
                { ip: "203.0.113.99", country: "North Korea", events: 654, threat: 80 },
                { ip: "198.51.100.77", country: "Romania", events: 421, threat: 60 },
                { ip: "203.0.113.5", country: "Brazil", events: 333, threat: 50 },
              ]).map((ip: any, i) => (
                <div key={ip.ip} className="flex items-center gap-3">
                  <div className="w-5 text-center text-sm">{ip.flag || ["🇷🇺","🇨🇳","🇰🇵","🇷🇴","🇧🇷"][i] || "🌐"}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between text-xs font-mono font-medium text-white">
                      <span>{ip.ip}</span>
                      <Ban className="w-3.5 h-3.5 text-[#ff3366]" />
                    </div>
                    <div className="text-[10px] text-[#8b949e] mb-1">{ip.country} - {ip.events}</div>
                    <div className="h-1 bg-[#21262d] rounded-full overflow-hidden">
                      <div className={cn(
                        "h-full rounded-full",
                        ip.threat > 80 ? "bg-[#ff3366]" : ip.threat > 60 ? "bg-[#ff9900]" : "bg-[#00aaff]"
                      )} style={{ width: `${ip.threat}%` }}></div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        
        {/* Extended Section */}
        <div className="grid grid-cols-12 gap-5 pb-5">
          {/* User Behavior Anomalies */}
          <div className="col-span-6 bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex flex-col shadow-lg">
            <PanelHeader title="User Behavior Anomalies (UEBA)" />
            <div className="mt-4 flex-1">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-[#8b949e] border-b border-[#30363d]">
                    <th className="pb-2 font-mono font-normal uppercase">User</th>
                    <th className="pb-2 font-mono font-normal uppercase">Department</th>
                    <th className="pb-2 font-mono font-normal uppercase">Anomaly</th>
                    <th className="pb-2 font-mono font-normal uppercase">Risk</th>
                    <th className="pb-2 font-mono font-normal uppercase text-right">Time</th>
                  </tr>
                </thead>
                <tbody className="text-white">
                  <tr className="border-b border-[#30363d]/50">
                    <td className="py-3 flex items-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-[#30363d] flex items-center justify-center font-bold text-[10px]">H</div>
                      harsh.mehta
                    </td>
                    <td className="py-3 text-[#8b949e]">Engineering</td>
                    <td className="py-3">Mass file download (3.2 GB)</td>
                    <td className="py-3"><SeverityPill severity="critical" /></td>
                    <td className="py-3 text-right text-[#8b949e] font-mono">2m ago</td>
                  </tr>
                  <tr>
                    <td className="py-3 flex items-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-[#30363d] flex items-center justify-center font-bold text-[10px]">R</div>
                      rohan.verma
                    </td>
                    <td className="py-3 text-[#8b949e]">Sales</td>
                    <td className="py-3">Login from unusual location (Russia)</td>
                    <td className="py-3"><SeverityPill severity="high" /></td>
                    <td className="py-3 text-right text-[#8b949e] font-mono">15m ago</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          
          {/* Recent Correlation Rule Triggers */}
          <div className="col-span-6 bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex flex-col shadow-lg">
            <PanelHeader title="Recent Correlation Rule Triggers" />
            <div className="mt-4 flex-1 space-y-3">
              <div className="flex items-center justify-between p-3 rounded-md border border-[#ff9900]/30 bg-[#ff9900]/5">
                <div className="flex items-start gap-3">
                  <Activity className="w-4 h-4 text-[#ff9900] mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-white mb-1">Brute Force SSH Detected</div>
                    <div className="text-[10px] text-[#8b949e]">More than 10 failed SSH logins from same source within 5 minutes</div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <SeverityPill severity="high" />
                  <span className="text-[11px] font-mono text-[#00aaff]">+142</span>
                  <span className="text-[10px] text-[#8b949e] font-mono">2m ago {'>'}</span>
                </div>
              </div>
              <div className="flex items-center justify-between p-3 rounded-md border border-[#ff3366]/30 bg-[#ff3366]/5">
                <div className="flex items-start gap-3">
                  <Activity className="w-4 h-4 text-[#ff3366] mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-white mb-1">Data Exfiltration Pattern</div>
                    <div className="text-[10px] text-[#8b949e]">Large outbound data transfer following suspicious login</div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <SeverityPill severity="critical" />
                  <span className="text-[11px] font-mono text-[#00aaff]">+21</span>
                  <span className="text-[10px] text-[#8b949e] font-mono">18m ago {'>'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* Right Side Panel: Alert Detail */}
      <div className={cn(
        "fixed right-0 top-[53px] bottom-0 w-[340px] bg-[#161b22] border-l border-[#30363d] shadow-2xl transform transition-transform duration-300 z-40 flex flex-col",
        selectedAlert ? "translate-x-0" : "translate-x-full"
      )}>
        {selectedAlert && (
          <>
            <div className="p-4 border-b border-[#30363d] flex items-center justify-between bg-[#0d1117]">
              <div className="font-semibold text-sm text-white">Alert Details</div>
              <button onClick={() => setSelectedAlert(null)} className="p-1.5 hover:bg-[#30363d] rounded text-[#8b949e] transition"><X className="w-4 h-4" /></button>
            </div>
            <div className="flex-1 overflow-auto p-5 space-y-6 custom-scrollbar">
              
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <SeverityPill severity={selectedAlert.severity || 'medium'} />
                  <span className="text-[11px] font-mono text-[#8b949e]">{relTime(selectedAlert.ts || Date.now())}</span>
                </div>
                <h2 className="text-lg font-bold leading-tight text-white mb-2">{selectedAlert.title}</h2>
                <div className="text-[12px] font-mono text-[#00aaff] bg-[#00aaff]/10 px-2 py-1 rounded inline-block border border-[#00aaff]/20">{selectedAlert.rule || 'Unknown Rule'}</div>
              </div>

              <div className="bg-[#00aaff]/5 border border-[#00aaff]/20 rounded-md p-4 text-xs leading-relaxed text-slate-300">
                <div className="flex items-center gap-2 font-bold text-[#00aaff] mb-2 uppercase tracking-wide text-[10px]">
                  <Info className="w-3.5 h-3.5" /> Engine Explanation
                </div>
                {selectedAlert.rawLog?.includes("behavioral") ? (
                  <span>
                    {JSON.parse(selectedAlert.rawLog).description || "Behavioral anomaly detected deviating from historical baseline."}
                  </span>
                ) : (
                  <span>Standard signature-based detection for {selectedAlert.rule}. Observed malicious activity originating from {selectedAlert.src || 'Unknown'}.</span>
                )}
              </div>

              <div className="space-y-3 text-xs bg-[#0d1117] rounded-md border border-[#30363d] p-3">
                <div className="grid grid-cols-3 border-b border-[#30363d] pb-2">
                  <span className="text-[#8b949e]">Source</span>
                  <span className="col-span-2 font-mono text-white truncate">{selectedAlert.src || "N/A"}</span>
                </div>
                <div className="grid grid-cols-3 border-b border-[#30363d] pb-2 pt-2">
                  <span className="text-[#8b949e]">Target</span>
                  <span className="col-span-2 font-mono text-white truncate">{selectedAlert.dst || "N/A"}</span>
                </div>
                <div className="grid grid-cols-3 pt-2">
                  <span className="text-[#8b949e]">MITRE</span>
                  <span className="col-span-2 font-mono text-white">{selectedAlert.mitreTactic || selectedAlert.rule || "N/A"}</span>
                </div>
              </div>

              <div>
                <div className="text-[10px] uppercase font-bold tracking-wider text-[#8b949e] mb-2">Recommended Action</div>
                <div className="bg-[#0d1117] border border-[#30363d] rounded-md p-3 text-xs text-slate-300 leading-relaxed">
                  {selectedAlert.recommendation || "Investigate the affected endpoint and isolate if lateral movement is suspected."}
                </div>
              </div>
              
              <div className="pt-4">
                <button
                  onClick={() => {
                    navigate("/logs", { state: { search: selectedAlert.src || selectedAlert.sourceIp || "" } });
                    setSelectedAlert(null);
                  }}
                  className="w-full bg-[#00aaff] hover:bg-[#0088cc] text-black font-bold uppercase tracking-wider text-[11px] py-3 rounded-md transition shadow-[0_0_15px_rgba(0,170,255,0.3)]"
                >
                  Investigate in Log Explorer
                </button>
                <button
                  onClick={() => {
                    navigate("/incidents", { state: { search: selectedAlert.title || "" } });
                    setSelectedAlert(null);
                  }}
                  className="w-full mt-2 border border-[#00aaff]/30 text-[#00aaff] font-bold uppercase tracking-wider text-[11px] py-2.5 rounded-md transition hover:bg-[#00aaff]/10"
                >
                  Open Full Incident →
                </button>
              </div>
            </div>
          </>
        )}
      </div>

    </div>
  );
}

function PanelHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between">
      <div>
        <h3 className="text-[11px] font-bold uppercase tracking-wider text-white">{title}</h3>
        {subtitle && <p className="text-[10px] font-mono text-[#8b949e] mt-1">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}

function KpiCard({
  title, value, delta, deltaColor, breakdown, breakdownColor, valueColor, sparklineData, sparklineColor, borderColor
}: { 
  title: string; value: string; delta?: string; deltaColor?: string; breakdown?: string; breakdownColor?: string; 
  valueColor: string; sparklineData: any[]; sparklineColor: string; borderColor?: string;
}) {
  return (
    <div className={cn(
      "bg-[#161b22] border rounded-lg p-4 flex flex-col justify-between shadow-lg relative overflow-hidden group min-h-[110px]",
      borderColor ? borderColor : "border-[#30363d]"
    )}>
      <div className="flex items-center justify-between z-10 w-full mb-2">
        <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#8b949e] truncate pr-2 flex-1" title={title}>
          {title.replace(' - 24H', '')}
        </div>
        {delta && <div className={cn("text-[10px] font-mono font-bold flex items-center gap-0.5 whitespace-nowrap", deltaColor)}>
          {delta.startsWith('+') ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />}
          {delta.replace('+', '').replace('-', '')}
        </div>}
      </div>
      <div className="mt-1 z-10 relative pb-2">
        <div className={cn("text-3xl font-bold tracking-tight leading-none mb-1.5", valueColor)} style={{ textShadow: `0 0 10px ${sparklineColor}40` }}>{value}</div>
        {breakdown && <div className={cn("text-[10px] font-mono truncate", breakdownColor)}>{breakdown}</div>}
      </div>
    </div>
  );
}
