import React, { useMemo, useState, useCallback, useRef, useEffect } from "react";
import { useSiem } from "@/lib/siemContext";
import { Play, Save, Download, ChevronRight, Loader2, History, Star, BarChart2, Table, PieChart, X, ExternalLink, Plus, Search } from "lucide-react";
import { BarChart, Bar, XAxis, ResponsiveContainer, Tooltip, PieChart as RechartsPie, Pie, Cell } from "recharts";
import { fmtTime } from "@/lib/siemData";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const SEV_DOT: Record<string, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low", info: "bg-sev-info",
};

const SUGGESTIONS = [
  'source="firewall"', 'source="edr"', 'source="auth"',
  'severity="critical"', 'severity="high"', 'severity="medium"',
  'source_ip="', 'host="', 'event_id="', '| last 1h', '| last 24h', '| last 7d',
  'AND', 'OR', 'NOT', 'protocol="TCP"', 'protocol="UDP"',
];

const SAVED_SEARCHES = [
  { name: "Critical Failed Logins", query: 'source="auth" severity="critical" event_id="4625" | last 24h' },
  { name: "Firewall Blocks Today", query: 'source="firewall" action="block" | last 24h' },
  { name: "EDR Alerts - All", query: 'source="edr" | last 7d' },
  { name: "Suspicious PowerShell", query: 'source="edr" process="powershell" | last 24h' },
];

const SEV_COLORS: Record<string, string> = {
  critical: "hsl(var(--sev-critical))", high: "hsl(var(--sev-high))",
  medium: "hsl(var(--sev-medium))", low: "hsl(var(--sev-low))", info: "hsl(var(--sev-info))",
};

export default function LogExplorer() {
  const { logs } = useSiem();
  const [query, setQuery] = useState(`source="*" | last 24h`);
  const [running, setRunning] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [vizMode, setVizMode] = useState<"table" | "histogram" | "pie">("table");
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [searchHistory, setSearchHistory] = useState<string[]>([
    'source="auth" severity="critical" | last 1h',
    'source="firewall" action="block" | last 24h',
  ]);
  const [showHistory, setShowHistory] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; value: string; field: string } | null>(null);
  const [savedSearches, setSavedSearches] = useState(SAVED_SEARCHES);
  const inputRef = useRef<HTMLInputElement>(null);

  // Advanced query parser
  const displayLogs = useMemo(() => {
    let filtered = [...logs];
    const q = query.toLowerCase();

    // Severity filter
    const sevMatch = q.match(/severity="([^"]+)"/);
    if (sevMatch) filtered = filtered.filter(l => l.severity === sevMatch[1]);

    // Source filter
    const srcMatch = q.match(/source="([^"]+)"/);
    if (srcMatch && srcMatch[1] !== "*") filtered = filtered.filter(l => l.format?.toLowerCase().includes(srcMatch[1]));

    // Source IP filter
    const ipMatch = q.match(/source_ip="([^"]+)"/);
    if (ipMatch) filtered = filtered.filter(l => l.srcIp === ipMatch[1]);

    // Host filter
    const hostMatch = q.match(/host="([^"]+)"/);
    if (hostMatch) filtered = filtered.filter(l => l.host?.toLowerCase().includes(hostMatch[1]));

    // Event ID filter
    const evtMatch = q.match(/event_id="([^"]+)"/);
    if (evtMatch) filtered = filtered.filter(l => l.eventId === evtMatch[1]);

    // NOT operator
    if (q.includes(" not ")) {
      const notParts = q.split(" not ");
      if (notParts[1]) {
        const notTerm = notParts[1].replace(/"/g, "").split(" ")[0];
        filtered = filtered.filter(l => !l.message?.toLowerCase().includes(notTerm));
      }
    }

    // Time range
    const now = Date.now();
    if (q.includes("last 1h")) filtered = filtered.filter(l => l.ts > now - 3600000);
    else if (q.includes("last 7d")) filtered = filtered.filter(l => l.ts > now - 604800000);
    // default last 24h

    return filtered.slice(0, 200);
  }, [logs, query]);

  // Autocomplete suggestions
  const activeSuggestions = useMemo(() => {
    const last = query.split(" ").pop() || "";
    if (!last || last.length < 1) return [];
    return SUGGESTIONS.filter(s => s.toLowerCase().startsWith(last.toLowerCase()) && s !== last).slice(0, 6);
  }, [query]);

  const fieldStats = useMemo(() => {
    return [
      { name: "source_ip", count: new Set(logs.map(l => l.srcIp)).size },
      { name: "event_id", count: new Set(logs.map(l => l.eventId)).size },
      { name: "host", count: new Set(logs.map(l => l.host)).size },
      { name: "severity", count: new Set(logs.map(l => l.severity)).size },
      { name: "format", count: new Set(logs.map(l => l.format)).size },
      { name: "dst_ip", count: new Set(logs.map(l => l.dstIp)).size },
      { name: "protocol", count: new Set(logs.map(l => l.format)).size },
    ];
  }, [logs]);

  const histogram = useMemo(() => {
    const buckets: Record<string, number> = {};
    displayLogs.forEach(l => {
      const k = new Date(l.ts).getMinutes().toString().padStart(2, "0");
      buckets[k] = (buckets[k] || 0) + 1;
    });
    return Object.entries(buckets).map(([t, v]) => ({ t, v })).slice(0, 30);
  }, [displayLogs]);

  const pieData = useMemo(() => {
    const counts: Record<string, number> = {};
    displayLogs.forEach(l => { counts[l.severity] = (counts[l.severity] || 0) + 1; });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [displayLogs]);

  const runQuery = useCallback(() => {
    setRunning(true);
    setShowSuggestions(false);
    setSearchHistory(prev => [query, ...prev.filter(h => h !== query)].slice(0, 10));
    setTimeout(() => setRunning(false), 400);
  }, [query]);

  const saveSearch = () => {
    const name = prompt("Save search as:");
    if (name) {
      setSavedSearches(prev => [...prev, { name, query }]);
      toast.success("Search saved");
    }
  };

  const handleCellRightClick = (e: React.MouseEvent, value: string, field: string) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, value, field });
  };

  useEffect(() => {
    const close = () => { setContextMenu(null); setShowSuggestions(false); setShowHistory(false); };
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, []);

  const renderRaw = (raw: string) => {
    return raw.split(/(\s+)/).map((token, i) => {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(token)) return <span key={i} className="text-warning">{token}</span>;
      if (/^[a-z_]+=/.test(token)) {
        const [k, ...v] = token.split("=");
        return <span key={i}><span className="text-primary">{k}</span>=<span className="text-success">{v.join("=")}</span></span>;
      }
      return <span key={i}>{token}</span>;
    });
  };

  return (
    <div className="p-5 space-y-4" onClick={() => setContextMenu(null)}>
      {/* Query bar */}
      <div className="siem-card p-3 space-y-2">
        <div className="flex gap-2 relative">
          <div className="relative flex-1">
            <input
              ref={inputRef}
              value={query}
              onChange={e => { setQuery(e.target.value); setShowSuggestions(true); }}
              onKeyDown={e => { if (e.key === "Enter") runQuery(); if (e.key === "Escape") setShowSuggestions(false); }}
              onFocus={() => setShowSuggestions(true)}
              className="w-full h-10 px-3 bg-background border border-border rounded font-mono text-xs outline-none focus:border-primary/40 text-success"
              placeholder='source="*" severity="critical" | last 24h'
            />
            {/* Autocomplete */}
            {showSuggestions && activeSuggestions.length > 0 && (
              <div className="absolute top-full left-0 right-0 mt-1 z-50 bg-popover border border-border rounded shadow-xl overflow-hidden">
                {activeSuggestions.map(s => (
                  <button key={s} className="w-full text-left px-3 py-1.5 text-xs font-mono hover:bg-surface-2 text-primary"
                    onMouseDown={e => { e.preventDefault(); const parts = query.split(" "); parts[parts.length - 1] = s; setQuery(parts.join(" ")); setShowSuggestions(false); }}>
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button onClick={runQuery} className="h-10 px-4 rounded bg-primary text-primary-foreground text-xs font-semibold flex items-center gap-1.5 hover:opacity-90">
            {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            {running ? "Searching…" : "Search"}
          </button>
          <button onClick={saveSearch} className="h-10 px-3 rounded border border-border bg-surface-2 text-xs flex items-center gap-1.5 hover:border-primary/40"><Save className="w-3.5 h-3.5" /> Save</button>
          <button onClick={() => { toast.success("Exported as CSV"); }} className="h-10 px-3 rounded border border-border bg-surface-2 text-xs flex items-center gap-1.5 hover:border-primary/40"><Download className="w-3.5 h-3.5" /> Export</button>
          <div className="relative">
            <button onClick={e => { e.stopPropagation(); setShowHistory(!showHistory); setShowSuggestions(false); }} className="h-10 px-3 rounded border border-border bg-surface-2 flex items-center gap-1.5 text-xs hover:border-primary/40"><History className="w-3.5 h-3.5" /></button>
            {showHistory && (
              <div className="absolute top-full right-0 mt-1 z-50 w-80 bg-popover border border-border rounded shadow-xl overflow-hidden" onClick={e => e.stopPropagation()}>
                <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-muted-foreground border-b border-border">Recent Searches</div>
                {searchHistory.map((h, i) => (
                  <button key={i} className="w-full text-left px-3 py-2 text-xs font-mono hover:bg-surface-2 text-foreground truncate" onClick={() => { setQuery(h); setShowHistory(false); }}>{h}</button>
                ))}
                <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-muted-foreground border-t border-border mt-1">Saved Searches</div>
                {savedSearches.map(s => (
                  <button key={s.name} className="w-full text-left px-3 py-2 text-xs hover:bg-surface-2 flex items-center gap-2" onClick={() => { setQuery(s.query); setShowHistory(false); }}>
                    <Star className="w-3 h-3 text-warning shrink-0" /><span className="truncate">{s.name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-[11px] font-mono text-success">● {logs.length.toLocaleString()} total sandbox logs · showing {displayLogs.length} filtered</div>
          <div className="flex gap-1 ml-auto">
            {(["table", "histogram", "pie"] as const).map(v => {
              const Icon = v === "table" ? Table : v === "histogram" ? BarChart2 : PieChart;
              return (
                <button key={v} onClick={() => setVizMode(v)} className={cn("w-8 h-7 rounded border flex items-center justify-center transition", vizMode === v ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
                  <Icon className="w-3.5 h-3.5" />
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {["Source: All", "Severity: Critical", "Event Type: Any", "Time: Last 24h", "Host: Any"].map(p => (
            <button key={p} className="px-2 h-7 rounded border border-border bg-surface-2 text-[10px] font-mono text-muted-foreground hover:text-foreground hover:border-primary/40 flex items-center gap-1">
              {p} <ChevronRight className="w-3 h-3 rotate-90" />
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Field browser */}
        <div className="col-span-2 siem-card p-3 max-h-[600px] overflow-auto flex flex-col">
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Fields</div>
          <div className="space-y-1 flex-1 overflow-auto">
            {fieldStats.map(f => (
              <button key={f.name} onClick={() => { setQuery(prev => `${prev} ${f.name}="`); inputRef.current?.focus(); }} className="w-full text-left p-2 rounded hover:bg-surface-2 border border-transparent hover:border-primary/30 group transition">
                <div className="text-xs font-mono text-primary">{f.name}</div>
                <div className="text-[10px] font-mono text-muted-foreground">{f.count} unique</div>
              </button>
            ))}
          </div>
        </div>

        {/* Results */}
        <div className="col-span-10 siem-card overflow-hidden flex flex-col max-h-[600px]">
          {running && <div className="h-0.5 bg-primary animate-pulse w-full" />}

          {vizMode === "table" && (
            <div className="overflow-auto flex-1">
              <table className="w-full text-xs">
                <thead className="bg-surface-2 sticky top-0 z-10">
                  <tr className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    {["Time", "Sev", "Host", "Event ID", "Message", "Src IP", "Dst IP", "Format"].map(h => <th key={h} className="text-left px-3 py-2 font-medium">{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {displayLogs.map(l => (
                    <React.Fragment key={l.id}>
                      <tr onClick={() => setExpanded(expanded === l.id ? null : l.id)} className="border-t border-border hover:bg-surface-2 cursor-pointer">
                        <td className="px-3 py-2 font-mono text-[10px] text-muted-foreground whitespace-nowrap">{fmtTime(l.ts)}</td>
                        <td className="px-3"><span className={cn("inline-block w-2 h-2 rounded-full", SEV_DOT[l.severity] || "bg-sev-info")} /></td>
                        <td className="px-3 font-mono text-[11px]" onContextMenu={e => handleCellRightClick(e, l.host || "", "host")}>{l.host}</td>
                        <td className="px-3 font-mono text-[11px] text-primary" onContextMenu={e => handleCellRightClick(e, l.eventId || "", "event_id")}>{l.eventId}</td>
                        <td className="px-3 truncate max-w-[280px]">{l.message}</td>
                        <td className="px-3 font-mono text-[11px] text-warning" onContextMenu={e => handleCellRightClick(e, l.srcIp || "", "source_ip")}>{l.srcIp}</td>
                        <td className="px-3 font-mono text-[11px]" onContextMenu={e => handleCellRightClick(e, l.dstIp || "", "dst_ip")}>{l.dstIp}</td>
                        <td className="px-3 text-[10px] font-mono text-muted-foreground uppercase">{l.format}</td>
                      </tr>
                      {expanded === l.id && (
                        <tr className="bg-background">
                          <td colSpan={8} className="px-4 py-3">
                            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Raw {l.format}</div>
                            <pre className="font-mono text-[11px] whitespace-pre-wrap break-all leading-relaxed">{renderRaw(l.raw || l.message || "")}</pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {vizMode === "histogram" && (
            <div className="flex-1 p-4">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Event Histogram (minute buckets)</div>
              <div className="h-full">
                <ResponsiveContainer width="100%" height="90%">
                  <BarChart data={histogram}>
                    <XAxis dataKey="t" stroke="hsl(var(--muted-foreground))" fontSize={9} tickLine={false} />
                    <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", fontSize: 11 }} />
                    <Bar dataKey="v" fill="hsl(var(--primary))" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {vizMode === "pie" && (
            <div className="flex-1 p-4 flex items-center gap-8">
              <div className="h-[300px] w-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <RechartsPie>
                    <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={110} stroke="hsl(var(--background))" strokeWidth={2}>
                      {pieData.map((entry, i) => <Cell key={i} fill={SEV_COLORS[entry.name] || "hsl(var(--primary))"} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", fontSize: 11 }} />
                  </RechartsPie>
                </ResponsiveContainer>
              </div>
              <div className="space-y-2">
                {pieData.map(d => (
                  <div key={d.name} className="flex items-center gap-2 text-xs font-mono">
                    <span className="w-3 h-3 rounded-sm" style={{ background: SEV_COLORS[d.name] || "hsl(var(--primary))" }} />
                    <span className="text-muted-foreground capitalize">{d.name}</span>
                    <span className="ml-auto font-semibold">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <div
          className="fixed z-[100] bg-popover border border-border rounded shadow-xl py-1 min-w-[200px]"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={e => e.stopPropagation()}
        >
          <div className="px-3 py-1.5 text-[10px] font-mono text-muted-foreground border-b border-border mb-1">{contextMenu.field} = "{contextMenu.value}"</div>
          <button className="w-full text-left px-3 py-1.5 text-xs hover:bg-surface-2 flex items-center gap-2" onClick={() => { setQuery(prev => `${prev} ${contextMenu.field}="${contextMenu.value}"`); setContextMenu(null); runQuery(); }}>
            <Search className="w-3 h-3 text-primary" /> Filter for this value
          </button>
          <button className="w-full text-left px-3 py-1.5 text-xs hover:bg-surface-2 flex items-center gap-2" onClick={() => { setQuery(prev => `${prev} NOT ${contextMenu.field}="${contextMenu.value}"`); setContextMenu(null); runQuery(); }}>
            <X className="w-3 h-3 text-danger" /> Exclude this value
          </button>
          <button className="w-full text-left px-3 py-1.5 text-xs hover:bg-surface-2 flex items-center gap-2" onClick={() => { toast.success(`${contextMenu.value} added to watchlist`); setContextMenu(null); }}>
            <Star className="w-3 h-3 text-warning" /> Add to watchlist
          </button>
          {contextMenu.field === "source_ip" && (
            <button className="w-full text-left px-3 py-1.5 text-xs hover:bg-surface-2 flex items-center gap-2" onClick={() => { window.open(`https://www.abuseipdb.com/check/${contextMenu.value}`, "_blank"); setContextMenu(null); }}>
              <ExternalLink className="w-3 h-3 text-muted-foreground" /> Lookup IP (AbuseIPDB)
            </button>
          )}
          <button className="w-full text-left px-3 py-1.5 text-xs hover:bg-surface-2 flex items-center gap-2" onClick={() => { toast.success("New search opened"); setContextMenu(null); }}>
            <Plus className="w-3 h-3 text-muted-foreground" /> New search from here
          </button>
        </div>
      )}
    </div>
  );
}
