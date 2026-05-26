import { useMemo, useState, useEffect } from "react";
import { useSiem, LiveAsset } from "@/lib/siemContext";

export type EnrichedAsset = LiveAsset & {
  riskScore: number;
  owner: string;
  businessUnit: string;
  lastScan: number;
  cveCount: number;
};
import { Laptop, Monitor, Server, Flame, Search, Grid3x3, List, X, ShieldAlert, Camera, WifiOff, UserX, Trophy } from "lucide-react";
import { cn } from "@/lib/utils";
import { relTime } from "@/lib/siemData";
import { toast } from "sonner";
import { BarChart, Bar, XAxis, ResponsiveContainer, Tooltip } from "recharts";

const STATUS_CFG: Record<string, { dot: string; label: string; cls: string }> = {
  online:       { dot: "bg-success",              label: "Online",       cls: "text-success border-success/40" },
  offline:      { dot: "bg-muted-foreground",      label: "Offline",      cls: "text-muted-foreground border-border" },
  compromised:  { dot: "bg-danger animate-pulse",  label: "Compromised",  cls: "text-danger border-danger/40 animate-glow-danger" },
  quarantined:  { dot: "bg-warning",               label: "Quarantined",  cls: "text-warning border-warning/40" },
};

const MOCK_CVES = [
  { id: "CVE-2024-21413", severity: "critical", score: 9.8, desc: "Microsoft Outlook RCE via malformed email hyperlink" },
  { id: "CVE-2024-1709",  severity: "critical", score: 10.0,desc: "ConnectWise ScreenConnect auth bypass" },
  { id: "CVE-2023-44487", severity: "high",     score: 7.5, desc: "HTTP/2 Rapid Reset DoS (Nginx)" },
  { id: "CVE-2021-44228", severity: "critical", score: 10.0,desc: "Log4Shell: Remote code execution" },
];

const MOCK_PORTS = ["22 (SSH)", "80 (HTTP)", "443 (HTTPS)", "3389 (RDP)", "5985 (WinRM)"];

const RISK_HISTORY = Array.from({ length: 14 }, (_, i) => ({
  d: `Day ${i + 1}`,
  score: Math.round(40 + Math.random() * 50),
}));

function iconFor(type: string) {
  if (type === "laptop")  return Laptop;
  if (type === "desktop") return Monitor;
  if (type === "firewall") return Flame;
  return Server;
}

function RiskScore({ score }: { score: number }) {
  const color = score >= 80 ? "text-danger" : score >= 50 ? "text-warning" : "text-success";
  const ring  = score >= 80 ? "stroke-danger" : score >= 50 ? "stroke-warning" : "stroke-success";
  const r = 20, circ = 2 * Math.PI * r, offset = circ - (score / 100) * circ;
  return (
    <div className="relative w-14 h-14 flex items-center justify-center">
      <svg className="absolute inset-0 -rotate-90" viewBox="0 0 48 48">
        <circle cx="24" cy="24" r={r} fill="none" stroke="hsl(var(--border))" strokeWidth="4" />
        <circle cx="24" cy="24" r={r} fill="none" className={ring} strokeWidth="4"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" />
      </svg>
      <span className={cn("text-sm font-mono font-bold relative z-10", color)}>{score}</span>
    </div>
  );
}

export default function Assets() {
  const { assets: liveAssets, isolateAsset, blockIp, captureSnapshot, disableAccount, remediateAsset } = useSiem();
  const [view, setView]     = useState<"grid" | "table" | "leaderboard">("grid");
  const [filter, setFilter] = useState("All");
  const [q, setQ]           = useState("");
  const [sel, setSel]       = useState<EnrichedAsset | null>(null);
  const [assetTab, setAssetTab] = useState<"Overview" | "Timeline" | "Vulnerabilities" | "Ports" | "Response">("Overview");
  const [sortKey, setSortKey] = useState<"risk" | "alerts">("risk");

  const [scanState, setScanState] = useState<{ status: "idle" | "scanning" | "complete"; threatsFound?: boolean; results?: string[] }>({ status: "idle" });
  const [scanProgress, setScanProgress] = useState(0);

  // Reset scan state when asset changes
  useEffect(() => {
    setScanState({ status: "idle" });
    setScanProgress(0);
  }, [sel?.id]);

  const runScan = () => {
    setScanState({ status: "scanning" });
    setScanProgress(0);
    toast("Full endpoint scan initiated", { description: "Scanning memory, registry, and filesystem..." });
    
    let p = 0;
    const interval = setInterval(() => {
      p += 20 + Math.random() * 15;
      if (p >= 100) {
        clearInterval(interval);
        setScanProgress(100);
        
        // Compute simulated results
        const isCompromised = sel?.status === "compromised" || sel?.status === "quarantined";
        const results = isCompromised 
          ? [
              "C:\\Windows\\Temp\\payload.exe (Trojan.Win32)", 
              "Memory: Suspicious injected thread in svchost.exe", 
              "Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"
            ]
          : [
              "No threats detected.", 
              "System memory clean.", 
              "Boot sectors clean."
            ];
            
        setTimeout(() => {
          setScanState({ status: "complete", threatsFound: isCompromised, results });
          toast[isCompromised ? "error" : "success"]("Endpoint scan complete", { description: isCompromised ? "Malware artifacts detected!" : "System is clean." });
        }, 500);
      } else {
        setScanProgress(Math.floor(p));
      }
    }, 400);
  };

  const counts = useMemo(() => ({
    total:       liveAssets.length,
    online:      liveAssets.filter(a => a.status === "online").length,
    offline:     liveAssets.filter(a => a.status === "offline").length,
    compromised: liveAssets.filter(a => a.status === "compromised").length,
    quarantined: liveAssets.filter(a => a.status === "quarantined").length,
  }), [liveAssets]);

  const filtered = liveAssets.filter(a => {
    if (q && !a.hostname.toLowerCase().includes(q.toLowerCase()) && !a.ip.includes(q)) return false;
    if (filter === "All") return true;
    if (filter === "Servers")   return a.type === "server";
    if (filter === "Firewalls") return a.type === "firewall";
    return a.os.toLowerCase().includes(filter.toLowerCase());
  });

  // Enrich assets with computed risk score based on real alerts and status
  const enriched: EnrichedAsset[] = useMemo(() => filtered.map((a, i) => ({
    ...a,
    riskScore: a.status === "compromised" ? Math.min(100, 85 + a.alerts * 2) :
               a.status === "quarantined" ? Math.min(100, 60 + a.alerts) :
               a.status === "offline" ? 30 : Math.min(50, 10 + a.alerts * 5),
    owner: ["Jesal Shah", "Samruddhi Chavat", "Harsh Zavare", "Nikhita Ghule"][i % 4],
    businessUnit: ["SOC", "Engineering", "Finance", "HR"][i % 4],
    lastScan: Date.now() - (i * 3600000 + 86400000),
    cveCount: a.status === "compromised" ? 4 : a.status === "quarantined" ? 2 : 0,
  })), [filtered]);

  const leaderboard = [...enriched].sort((a, b) =>
    sortKey === "risk" ? b.riskScore - a.riskScore : b.alerts - a.alerts
  ).slice(0, 10);

  return (
    <div className="p-5 space-y-4">
      {/* KPI ribbon */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: "Total",       value: counts.total,       color: "text-foreground" },
          { label: "Online",      value: counts.online,      color: "text-success" },
          { label: "Offline",     value: counts.offline,     color: "text-muted-foreground" },
          { label: "Compromised", value: counts.compromised, color: "text-danger" },
          { label: "Quarantined", value: counts.quarantined, color: "text-warning" },
        ].map(s => (
          <div key={s.label} className="siem-card p-3">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{s.label}</div>
            <div className={cn("text-2xl font-mono font-semibold mt-1", s.color)}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="flex items-center gap-2 flex-wrap">
        {["All","Windows","macOS","Linux","Servers","Firewalls"].map(f => (
          <button key={f} onClick={() => setFilter(f)} className={cn("px-3 h-8 rounded text-[11px] font-mono uppercase tracking-wider border transition", filter === f ? "bg-primary/15 text-primary border-primary/50" : "border-border text-muted-foreground hover:text-foreground")}>{f}</button>
        ))}
        <div className="relative ml-auto w-64">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search hostname or IP…" className="w-full h-8 pl-8 pr-2 bg-surface-2 border border-border rounded text-xs font-mono outline-none focus:border-primary/40" />
        </div>
        <div className="flex border border-border rounded overflow-hidden">
          {([["grid", Grid3x3], ["table", List], ["leaderboard", Trophy]] as const).map(([v, Icon]) => (
            <button key={v} onClick={() => setView(v as "grid" | "table" | "leaderboard")} className={cn("w-8 h-8 flex items-center justify-center", view === v ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground")}>
              <Icon className="w-3.5 h-3.5" />
            </button>
          ))}
        </div>
      </div>

      {/* Grid view */}
      {view === "grid" && (
        <div className="grid grid-cols-4 gap-3">
          {enriched.map(a => {
            const Icon = iconFor(a.type);
            const cfg  = STATUS_CFG[a.status];
            return (
              <button key={a.id} onClick={() => { setSel(a); setAssetTab("Overview"); }} className={cn("siem-card p-4 text-left hover:border-primary/40 transition", a.status === "compromised" && "siem-card-danger")}>
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded bg-primary/10 border border-primary/20 flex items-center justify-center"><Icon className="w-5 h-5 text-primary" /></div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate">{a.hostname}</div>
                    <div className="text-[10px] font-mono text-muted-foreground">{a.ip}</div>
                  </div>
                  <RiskScore score={a.riskScore} />
                </div>
                <div className="mt-3 flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded border border-border bg-surface-2 text-[10px] font-mono">{a.os}</span>
                  <span className={cn("flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] font-mono uppercase", cfg.cls)}>
                    <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} /> {cfg.label}
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-muted-foreground">
                  <span>Owner: {a.owner}</span>
                  {a.cveCount > 0 && <span className="text-danger font-semibold">{a.cveCount} CVEs</span>}
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* Table view */}
      {view === "table" && (
        <div className="siem-card overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-surface-2">
              <tr className="text-[10px] font-mono uppercase text-muted-foreground">
                {["Hostname","IP","OS","Owner","BU","Status","Risk","CVEs","Alerts"].map(h => <th key={h} className="text-left px-3 py-2">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {enriched.map(a => (
                <tr key={a.id} onClick={() => { setSel(a); setAssetTab("Overview"); }} className="border-t border-border hover:bg-surface-2 cursor-pointer">
                  <td className="px-3 py-2 font-medium">{a.hostname}</td>
                  <td className="px-3 font-mono">{a.ip}</td>
                  <td className="px-3 text-muted-foreground">{a.os}</td>
                  <td className="px-3 text-muted-foreground">{a.owner}</td>
                  <td className="px-3 text-muted-foreground">{a.businessUnit}</td>
                  <td className="px-3"><span className={cn("px-2 py-0.5 rounded border text-[10px] font-mono uppercase", STATUS_CFG[a.status].cls)}>{STATUS_CFG[a.status].label}</span></td>
                  <td className="px-3"><span className={cn("font-mono font-semibold", a.riskScore >= 80 ? "text-danger" : a.riskScore >= 50 ? "text-warning" : "text-success")}>{a.riskScore}</span></td>
                  <td className="px-3 font-mono text-danger">{a.cveCount}</td>
                  <td className="px-3 font-mono text-danger">{a.alerts}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Risk Leaderboard */}
      {view === "leaderboard" && (
        <div className="siem-card overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-3">
            <Trophy className="w-5 h-5 text-warning" />
            <div className="font-semibold">Asset Risk Leaderboard</div>
            <div className="ml-auto flex gap-1">
              {(["risk", "alerts"] as const).map(k => (
                <button key={k} onClick={() => setSortKey(k)} className={cn("px-3 h-7 rounded border text-[10px] font-mono uppercase transition", sortKey === k ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground")}>
                  Sort by {k}
                </button>
              ))}
            </div>
          </div>
          <table className="w-full text-xs">
            <thead className="bg-surface-2">
              <tr className="text-[10px] font-mono uppercase text-muted-foreground">
                {["#","Hostname","IP","Status","Risk Score","CVEs","Alerts","Last Scan"].map(h => <th key={h} className="text-left px-3 py-2">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {leaderboard.map((a, i) => (
                <tr key={a.id} onClick={() => { setSel(a); setAssetTab("Overview"); }} className="border-t border-border hover:bg-surface-2 cursor-pointer">
                  <td className="px-3 py-2 font-mono font-bold text-muted-foreground">#{i + 1}</td>
                  <td className="px-3 font-medium">{a.hostname}</td>
                  <td className="px-3 font-mono">{a.ip}</td>
                  <td className="px-3"><span className={cn("px-2 py-0.5 rounded border text-[10px] font-mono uppercase", STATUS_CFG[a.status].cls)}>{STATUS_CFG[a.status].label}</span></td>
                  <td className="px-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 rounded bg-surface-2 border border-border overflow-hidden">
                        <div className="h-full transition-all" style={{ width: `${a.riskScore}%`, background: a.riskScore >= 80 ? "hsl(var(--danger))" : a.riskScore >= 50 ? "hsl(var(--warning))" : "hsl(var(--success))" }} />
                      </div>
                      <span className={cn("font-mono font-bold w-7", a.riskScore >= 80 ? "text-danger" : a.riskScore >= 50 ? "text-warning" : "text-success")}>{a.riskScore}</span>
                    </div>
                  </td>
                  <td className="px-3 font-mono text-danger">{a.cveCount}</td>
                  <td className="px-3 font-mono text-danger">{a.alerts}</td>
                  <td className="px-3 text-[10px] font-mono text-muted-foreground">{relTime(a.lastScan)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Asset Detail Drawer */}
      {sel && (
        <>
          <div className="fixed inset-0 z-40 bg-background/50 backdrop-blur-sm" onClick={() => setSel(null)} />
          <aside className="fixed right-0 top-0 bottom-0 z-50 w-[580px] bg-card border-l border-border animate-slide-in-right flex flex-col">
            <div className="p-4 border-b border-border flex items-start justify-between">
              <div>
                <div className="text-[10px] font-mono text-primary">{sel.businessUnit} • {sel.os}</div>
                <h2 className="text-base font-semibold">{sel.hostname}</h2>
                <div className="text-[10px] font-mono text-muted-foreground">{sel.ip} • Owner: {sel.owner}</div>
              </div>
              <div className="flex items-center gap-3">
                <RiskScore score={sel.riskScore} />
                <button onClick={() => setSel(null)} className="w-8 h-8 rounded hover:bg-surface-2 flex items-center justify-center"><X className="w-4 h-4" /></button>
              </div>
            </div>

            <div className="flex border-b border-border overflow-x-auto">
              {(["Overview","Timeline","Vulnerabilities","Ports","Response"] as const).map(t => (
                <button key={t} onClick={() => setAssetTab(t)} className={cn("px-4 h-10 text-xs font-medium border-b-2 transition whitespace-nowrap", assetTab === t ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}>{t}</button>
              ))}
            </div>

            <div className="flex-1 overflow-auto p-4 text-xs space-y-4">
              {assetTab === "Overview" && (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      ["Status",    STATUS_CFG[sel.status].label],
                      ["Open Alerts", sel.alerts.toString()],
                      ["EDR Agent", "v3.4.1 (active)"],
                      ["Log Agent", "v2.8.0 (active)"],
                      ["Last Scan", relTime(sel.lastScan)],
                      ["CVEs",      `${sel.cveCount} found`],
                    ].map(([l, v]) => (
                      <div key={l} className="p-2 rounded bg-surface-2 border border-border">
                        <div className="text-[10px] text-muted-foreground">{l}</div>
                        <div className="font-mono mt-0.5">{v}</div>
                      </div>
                    ))}
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">14-Day Risk Score Trend</div>
                    <div className="h-28">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={RISK_HISTORY}>
                          <XAxis dataKey="d" stroke="hsl(var(--muted-foreground))" fontSize={8} tickLine={false} />
                          <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", fontSize: 10 }} />
                          <Bar dataKey="score" fill="hsl(var(--primary))" radius={[2, 2, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Auto-Tags</div>
                    <div className="flex flex-wrap gap-1.5">
                      {[sel.businessUnit, sel.os, sel.type, "GDPR Scope", "PCI-DSS"].map(tag => (
                        <span key={tag} className="px-2 py-0.5 rounded-full border border-border bg-surface-2 text-[10px] font-mono">{tag}</span>
                      ))}
                    </div>
                  </div>
                </>
              )}

              {assetTab === "Timeline" && (
                <div className="space-y-2 relative pl-3 border-l-2 border-border">
                  {Array.from({ length: 8 }).map((_, i) => (
                    <div key={i} className="relative">
                      <div className="absolute -left-[17px] top-2 w-2 h-2 rounded-full bg-border" />
                      <div className="p-2 rounded bg-surface-2 border border-border font-mono text-[10px]">
                        <div className="text-muted-foreground mb-0.5">{new Date(Date.now() - i * 60000 * 15).toLocaleTimeString("en-IN", { hour12: false })}</div>
                        <span className="text-primary">EVT-{4500 + i * 3}</span>{" "}
                        <span>{["process_exec", "net_conn", "file_write", "logon_fail"][i % 4]}</span>{" "}
                        <span className="text-success">"{["powershell", "sshd", "python3", "explorer.exe"][i % 4]}"</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {assetTab === "Vulnerabilities" && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Known CVEs</div>
                    <button onClick={() => toast("Vulnerability scan initiated")} className="text-[10px] font-mono text-primary hover:underline">Run Scan Now</button>
                  </div>
                  {MOCK_CVES.slice(0, sel.cveCount + 1).map(cve => (
                    <div key={cve.id} className="p-3 rounded border border-border bg-surface-2">
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-mono text-danger font-semibold">{cve.id}</div>
                        <div className={cn("px-2 py-0.5 rounded border text-[9px] font-mono uppercase", cve.severity === "critical" ? "border-danger/40 text-danger bg-danger/10" : "border-warning/40 text-warning bg-warning/10")}>
                          CVSS {cve.score}
                        </div>
                      </div>
                      <div className="text-muted-foreground mt-1">{cve.desc}</div>
                    </div>
                  ))}
                  {sel.cveCount === 0 && <div className="text-center text-muted-foreground py-4 text-xs">No CVEs detected in last scan</div>}
                </div>
              )}

              {assetTab === "Ports" && (
                <div className="space-y-2">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Open Ports</div>
                  {MOCK_PORTS.map(p => (
                    <div key={p} className="flex items-center gap-3 p-2 rounded border border-border bg-surface-2 font-mono text-xs">
                      <div className="w-2 h-2 rounded-full bg-success" />
                      <span className="text-primary">{p}</span>
                      <span className="ml-auto text-muted-foreground">OPEN</span>
                    </div>
                  ))}
                </div>
              )}

              {assetTab === "Response" && (
                <div className="space-y-3">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Active Response Actions</div>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { label: "Isolate Host", desc: "Cut all network connectivity via EDR", Icon: WifiOff, cls: "border-danger/40 bg-danger/5 text-danger hover:bg-danger/10",
                        action: () => isolateAsset(sel!.hostname, "") },
                      { label: "Capture Snapshot", desc: "Pull memory & disk forensic image", Icon: Camera, cls: "border-primary/40 bg-primary/5 text-primary hover:bg-primary/10",
                        action: () => captureSnapshot("") },
                      { label: "Block Source IPs", desc: `Block active attack IPs`, Icon: X, cls: "border-warning/40 bg-warning/5 text-warning hover:bg-warning/10",
                        action: () => { if (sel?.lastAttack) { blockIp(sel.lastAttackIp || "", ""); } else { toast("No active attack IP found"); } } },
                      { label: "Disable Account", desc: "Lock AD account tied to this host", Icon: UserX, cls: "border-border bg-surface-2 text-foreground hover:border-primary/40",
                        action: () => disableAccount("") },
                    ].map(a => (
                      <button key={a.label} onClick={a.action} className={cn("flex flex-col items-start p-3 rounded border text-left transition", a.cls)}>
                        <div className="flex items-center gap-2 mb-1 font-semibold text-xs"><a.Icon className="w-4 h-4" />{a.label}</div>
                        <div className="text-[10px] text-muted-foreground">{a.desc}</div>
                      </button>
                    ))}
                  </div>
                  {/* Show real response state */}
                  <div className="p-3 rounded border border-border bg-surface-2 text-[11px] space-y-1">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Current Status</div>
                    <div className={cn("font-semibold", sel!.status === "compromised" ? "text-danger" : sel!.status === "quarantined" ? "text-warning" : "text-success")}>
                      {sel!.status.toUpperCase()}
                    </div>
                    {sel!.alerts > 0 && <div className="text-danger">{sel!.alerts} live alerts detected on this host</div>}
                    {sel.lastAttack && <div className="text-warning">Last attack: {sel.lastAttack}</div>}
                    {sel.blockedIps && sel.blockedIps.length > 0 && <div className="text-success">Blocked IPs: {sel.blockedIps.join(", ")}</div>}
                  </div>
                  <div className="space-y-3 mt-4 pt-4 border-t border-border">
                    {scanState.status === "idle" && (
                      <button onClick={runScan} className="w-full h-9 rounded border border-border bg-surface-2 text-xs flex items-center justify-center gap-2 hover:border-primary/40 transition group">
                        <ShieldAlert className="w-3.5 h-3.5 text-primary group-hover:scale-110 transition-transform" /> Run Full Endpoint Scan
                      </button>
                    )}
                    {scanState.status === "scanning" && (
                      <div className="p-3 rounded border border-border bg-surface-2 space-y-2">
                        <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider">
                          <span className="text-primary animate-pulse">Scanning memory & disk...</span>
                          <span className="text-muted-foreground">{scanProgress}%</span>
                        </div>
                        <div className="w-full bg-background h-1.5 rounded-full overflow-hidden">
                          <div className="bg-primary h-full transition-all duration-300" style={{ width: `${scanProgress}%` }} />
                        </div>
                      </div>
                    )}
                    {scanState.status === "complete" && (
                      <div className="p-3 rounded border border-border bg-surface-2 space-y-2">
                        <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                          <ShieldAlert className={cn("w-3.5 h-3.5", scanState.threatsFound ? "text-danger" : "text-success")} />
                          Scan Complete
                        </div>
                        <ul className="space-y-1">
                          {scanState.results?.map((res, idx) => (
                            <li key={idx} className={cn("text-[10px] font-mono", scanState.threatsFound && idx === 0 ? "text-danger font-semibold" : "text-muted-foreground")}>
                              • {res}
                            </li>
                          ))}
                        </ul>
                        <button onClick={() => setScanState({ status: "idle", progress: 0 })} className="text-[10px] text-primary hover:underline mt-1">Run again</button>
                      </div>
                    )}
                    {(sel!.status === "compromised" || sel!.status === "quarantined") && (
                      <div className="p-3 rounded border border-success/40 bg-success/5 space-y-2">
                        <div className="text-[11px] text-success leading-relaxed">
                          <strong>Automated Remediation:</strong> This action will automatically clear all active threat alerts, lift any network quarantine restrictions (EDR), and restore the endpoint's overall health status back to Online.
                        </div>
                        <button onClick={() => { remediateAsset(sel!.hostname); setSel(null); }} className="w-full h-8 rounded bg-success text-success-foreground font-semibold text-xs flex items-center justify-center transition hover:bg-success/90 shadow-sm shadow-success/20">
                          Approve Remediate & Restore
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </aside>
        </>
      )}
    </div>
  );
}
