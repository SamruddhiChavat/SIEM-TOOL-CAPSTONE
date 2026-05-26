import { useEffect, useState, useMemo } from "react";
import { COUNTRIES, TARGET, randomIp, pickAttackType, relTime } from "@/lib/siemData";
import { useSiem } from "@/lib/siemContext";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { ComposableMap, Geographies, Geography, Marker, Line } from "react-simple-maps";

const geoUrl = "/world-110m.json";

interface ConnRow { id: number; src: string; dst: string; port: number; proto: string; action: "Allow" | "Block"; ts: number; }

export default function ThreatMap() {
  const { threatMapData, suspiciousIps } = useSiem();
  const [filter, setFilter] = useState<"all" | "blocked" | "allowed" | "critical">("all");
  const [selectedConn, setSelectedConn] = useState<ConnRow | null>(null);

  // Build connection rows from real events from backend
  const [conns, setConns] = useState<ConnRow[]>([]);

  // When real threat map data arrives, seed connections from it
  useEffect(() => {
    if (!threatMapData?.events?.length) return;
    const realConns: ConnRow[] = threatMapData.events.slice(0, 24).map((ev, i) => ({
      id: i,
      src: ev.source_ip || randomIp(true),
      dst: ev.destination_ip || `192.168.1.${10 + i}`,
      port: [22, 80, 443, 3389, 445, 53][i % 6],
      proto: "TCP",
      action: ev.severity === "critical" || ev.severity === "high" ? "Block" : "Allow",
      ts: ev.timestamp ? new Date(ev.timestamp).getTime() : Date.now() - i * 9000,
    }));
    setConns(realConns);
  }, [threatMapData]);

  // Build country attack sources — prefer real country_risk data
  const countrySources = useMemo(() => {
    // If we have live suspicious IPs, group them by country
    if (suspiciousIps && suspiciousIps.length > 0) {
      const grouped = suspiciousIps.reduce((acc, curr) => {
        const cname = curr.country;
        acc[cname] = (acc[cname] || 0) + curr.events;
        return acc;
      }, {} as Record<string, number>);
      
      const res = COUNTRIES.map(c => ({
        ...c,
        events: grouped[c.name] || (threatMapData?.country_risk ? threatMapData.country_risk[c.name] : 0) || 0,
        attackTypes: [pickAttackType()],
      })).filter(c => c.events > 0).sort((a, b) => b.events - a.events);
      
      if (res.length > 0) return res;
    }
    
    if (threatMapData?.country_risk && Object.keys(threatMapData.country_risk).length > 0) {
      return COUNTRIES.map(c => ({
        ...c,
        events: threatMapData.country_risk[c.name] || 0,
        attackTypes: [pickAttackType()],
      })).filter(c => c.events > 0).sort((a, b) => b.events - a.events);
    }
    return [];
  }, [threatMapData, suspiciousIps]);

  // Stats from real data
  const stats = useMemo(() => {
    const totalBlocked = conns.filter(c => c.action === "Block").length;
    const uniqueSrcIPs = new Set(conns.map(c => c.src)).size;
    const portCounts: Record<number, number> = {};
    conns.forEach(c => { portCounts[c.port] = (portCounts[c.port] || 0) + 1; });
    const topPortEntry = Object.entries(portCounts).sort((a, b) => b[1] - a[1])[0];
    const topPort = topPortEntry ? topPortEntry[0] : "22";
    return {
      blocked: threatMapData?.events ? threatMapData.events.filter(e => e.severity === "critical" || e.severity === "high").length.toLocaleString() : totalBlocked.toLocaleString(),
      uniqueIPs: threatMapData?.events ? new Set(threatMapData.events.map(e => e.source_ip)).size.toString() : uniqueSrcIPs.toString(),
      topPort: `${topPort} ${topPort === "22" ? "SSH" : topPort === "443" ? "HTTPS" : topPort === "3389" ? "RDP" : "TCP"}`,
    };
  }, [conns, threatMapData]);

  return (
    <div className="p-4 h-[calc(100vh-60px)] flex flex-col gap-4 overflow-hidden">
      {/* Top Filter Bar */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="flex items-center gap-2 px-3 py-1.5 bg-surface-2 border border-border rounded-md">
          <span className="text-[11px] font-mono uppercase text-muted-foreground">Time:</span>
          <select className="bg-transparent text-sm outline-none text-foreground">
            <option>Last 24h</option>
            <option>Last 7d</option>
            <option>Last 30d</option>
          </select>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-surface-2 border border-border rounded-md">
          <span className="text-[11px] font-mono uppercase text-muted-foreground">Country:</span>
          <select className="bg-transparent text-sm outline-none text-foreground">
            <option>All</option>
            {countrySources.map(c => <option key={c.code}>{c.name}</option>)}
          </select>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-surface-2 border border-border rounded-md">
          <span className="text-[11px] font-mono uppercase text-muted-foreground">MITRE:</span>
          <select className="bg-transparent text-sm outline-none text-foreground max-w-[200px] truncate">
            <option>All</option>
            <option>TA0001: Initial Access</option>
            <option>TA0011: Command and Control</option>
          </select>
        </div>

        <div className="ml-auto flex items-center gap-1 bg-surface-2 border border-border p-1 rounded-md">
          {(["all", "blocked", "allowed", "critical"] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)} className={cn("px-4 py-1 text-[10px] font-mono uppercase tracking-wider rounded transition", filter === f ? "bg-primary/20 text-primary border border-primary/30" : "text-muted-foreground hover:text-foreground border border-transparent")}>
              {f === "critical" ? "Critical Only" : f}
            </button>
          ))}
        </div>
      </div>

      <div className="flex flex-1 gap-4 min-h-0">
        {/* Left Panel: Threats */}
        <div className="w-[300px] flex flex-col gap-4 shrink-0 overflow-y-auto pr-1">
          <div className="siem-card flex-1 flex flex-col p-4 relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-4 bg-danger rounded-full" />
                <h3 className="text-sm font-semibold">Incoming Threats</h3>
              </div>
              <span className="w-2 h-2 rounded-full bg-danger animate-pulse shadow-[0_0_8px_hsl(var(--danger))]" />
            </div>
            
            <div className="space-y-3 overflow-y-auto flex-1 pr-1 custom-scrollbar">
              {countrySources.map(c => (
                <div key={c.code} className="flex items-center justify-between group cursor-pointer">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">{c.flag}</span>
                    <div className="flex flex-col">
                      <span className="text-xs text-foreground group-hover:text-primary transition">{c.name}</span>
                      <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[120px]">{c.attackTypes[0]}</span>
                    </div>
                  </div>
                  <span className="text-xs font-mono text-danger font-semibold">{c.events}</span>
                </div>
              ))}
              
              {countrySources.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-center p-4">
                  <div className="w-8 h-8 rounded-full bg-surface-2 flex items-center justify-center mb-3">🛡️</div>
                  <p className="text-xs text-muted-foreground font-mono">No incoming threats detected.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Center: Map */}
        <div className="flex-1 siem-card relative overflow-hidden flex flex-col">
          <div className="absolute top-4 left-4 z-10 flex items-center gap-4">
            {countrySources.length === 0 && conns.length === 0 && (
              <div className="bg-background/80 backdrop-blur px-4 py-2 rounded border border-border flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <span className="text-xs font-mono text-primary">Awaiting Simulation...</span>
              </div>
            )}
          </div>
          
          <div className="flex-1 w-full relative">
            <ComposableMap 
              projection="geoMercator" 
              projectionConfig={{ scale: 130, center: [0, 30] }}
              style={{ width: "100%", height: "100%" }}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="hsl(var(--surface-2))"
                      stroke="hsl(var(--border))"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "hsl(var(--surface-3))", outline: "none" },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>

              {/* Draw arcs from sources to target */}
              {countrySources.map((c, i) => (
                <Line
                  key={`line-${c.code}`}
                  from={[c.lng, c.lat]}
                  to={[TARGET.lng, TARGET.lat]}
                  stroke="hsl(var(--danger))"
                  strokeWidth={1.5}
                  strokeLinecap="round"
                  style={{
                    strokeDasharray: "4 4",
                    animation: "dash-move 2s linear infinite"
                  }}
                />
              ))}

              {/* Source Markers */}
              {countrySources.map((c) => (
                <Marker key={`marker-${c.code}`} coordinates={[c.lng, c.lat]}>
                  <circle r={3} fill="hsl(var(--danger))" />
                  <circle r={8} fill="hsl(var(--danger))" opacity={0.3}>
                    <animate attributeName="r" from="3" to="12" dur="1.5s" repeatCount="indefinite" />
                    <animate attributeName="opacity" from="0.6" to="0" dur="1.5s" repeatCount="indefinite" />
                  </circle>
                </Marker>
              ))}

              {/* Target Marker */}
              <Marker coordinates={[TARGET.lng, TARGET.lat]}>
                <circle r={4} fill="hsl(var(--primary))" />
                <circle r={12} fill="hsl(var(--primary))" opacity={0.4}>
                  <animate attributeName="r" from="4" to="20" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite" />
                </circle>
              </Marker>
            </ComposableMap>
          </div>

          {/* Bottom Stats Overlay */}
          <div className="absolute bottom-6 left-1/2 -translate-x-1/2 flex items-center gap-12 bg-background/90 backdrop-blur border border-border px-8 py-3 rounded-full shadow-lg">
            <div className="flex flex-col items-center">
              <span className="text-[9px] font-mono uppercase text-muted-foreground mb-0.5">Blocked Today</span>
              <span className="text-lg font-mono font-bold text-success glow-text-success">{stats.blocked}</span>
            </div>
            <div className="w-px h-8 bg-border" />
            <div className="flex flex-col items-center">
              <span className="text-[9px] font-mono uppercase text-muted-foreground mb-0.5">Unique Source IPs</span>
              <span className="text-lg font-mono font-bold text-primary glow-text-primary">{stats.uniqueIPs}</span>
            </div>
            <div className="w-px h-8 bg-border" />
            <div className="flex flex-col items-center">
              <span className="text-[9px] font-mono uppercase text-muted-foreground mb-0.5">Top Targeted Port</span>
              <span className="text-lg font-mono font-bold text-warning glow-text-warning">{stats.topPort}</span>
            </div>
          </div>
        </div>

        {/* Right Panel: Active Connections */}
        <div className="w-[320px] flex flex-col shrink-0">
          <div className="siem-card flex-1 p-4 flex flex-col relative">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-primary" />
                <h3 className="text-sm font-semibold">Active Connections</h3>
              </div>
              <span className="text-[10px] font-mono text-muted-foreground">{conns.length}</span>
            </div>
            
            <div className="flex-1 overflow-y-auto pr-1 space-y-1.5 custom-scrollbar">
              {conns.filter(c => filter === "all" || (filter === "blocked" && c.action === "Block") || (filter === "allowed" && c.action === "Allow") || filter === "critical").map(c => (
                <div key={c.id} className="flex flex-col p-2 bg-surface-2 border border-border rounded hover:border-primary/40 transition text-xs font-mono">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-muted-foreground">{c.src}</span>
                    <span className="text-muted-foreground">›</span>
                    <span className="text-foreground">{c.dst}</span>
                  </div>
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-muted-foreground">:{c.port}</span>
                    <span className={cn("px-1.5 py-0.5 rounded", c.action === "Block" ? "bg-danger/15 text-danger border border-danger/20" : "bg-success/15 text-success border border-success/20")}>{c.action.toUpperCase()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
