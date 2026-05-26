import { useState, useEffect, useRef, useCallback } from "react";
import { useSiem } from "@/lib/siemContext";
import { SeverityPill } from "@/components/siem/SeverityPill";
import { cn } from "@/lib/utils";
import { ExternalLink, ShieldOff, ShieldCheck, Wifi, WifiOff, Zap, Target, Activity, Terminal, X } from "lucide-react";

// ─── Severity badge colour helper ─────────────────────────────────────────
const SEV_CLASS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/30",
  info:     "text-slate-400 bg-slate-500/10 border-slate-500/30",
};

const ATTACK_ICON: Record<string, string> = {
  BRUTE_FORCE:       "🔑",  DDOS:             "🌊",
  SQL_INJECTION:     "💉",  PORT_SCAN:        "📡",
  FILE_EXFILTRATION: "📤",  LATERAL_MOVEMENT: "↔️",
  DNS_C2:            "📶",  RANSOMWARE:       "🔒",
  PHISHING:          "🎣",
};

// ─── Types ─────────────────────────────────────────────────────────────────
interface SandboxEvent {
  id: string;
  ts: number;
  severity: string;
  eventType: string;
  sourceIp: string;
  sourceHost: string;
  destIp: string;
  destHostname: string;
  mitre: string | null;
  mitreTactic: string | null;
  message: string;
  category: string;
  action: string;
}

// ─── Component ──────────────────────────────────────────────────────────────
export default function SandboxFeed() {
  const { incidents, isolateAsset, remediateAsset, blockIp, assets, kpis } = useSiem();
  const [events, setEvents]       = useState<SandboxEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [cursor, setCursor]       = useState(0);
  const [selectedEvt, setSelectedEvt] = useState<SandboxEvent | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);
  const esRef   = useRef<EventSource | null>(null);

  // ── SSE connection to relay ────────────────────────────────────────────
  const connect = useCallback(() => {
    const es = new EventSource(`/sandbox/api/logs/stream?since=${cursor}`);
    esRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => {
      setConnected(false);
      es.close();
      setTimeout(connect, 3000);
    };

    es.onmessage = (e) => {
      try {
        const d = JSON.parse(e.data);
        if (d.__clear) { setEvents([]); setCursor(0); return; }
        if (d.cursor) setCursor(d.cursor);
        if (d.eventType?.startsWith("RESPONSE_")) return; // skip response echoes

        const evt: SandboxEvent = {
          id:           d.id,
          ts:           new Date(d.timestamp).getTime(),
          severity:     d.severity || "info",
          eventType:    d.eventType || "UNKNOWN",
          sourceIp:     d.sourceIp || d.sourceHost || "—",
          sourceHost:   d.sourceHost || d.sourceIp || "—",
          destIp:       d.destIp || "—",
          destHostname: d.destHostname || d.destIp || "—",
          mitre:        d.mitre || null,
          mitreTactic:  d.mitreTactic || null,
          message:      d.message || "",
          category:     d.category || "Attack",
          action:       d.action || "Detected",
        };
        setEvents(prev => [evt, ...prev].slice(0, 200));
      } catch { /* ignore */ }
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    connect();
    return () => { esRef.current?.close(); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Active attacks from incidents
  const activeIncidents = incidents.filter(i => i.status !== "Resolved" && i.status !== "Contained");
  const sandboxEvents   = events.filter(e => e.severity !== "info");

  const sev = (s: string) => s as "critical" | "high" | "medium" | "low" | "info";

  return (
    <div className="flex h-full gap-4 p-4 overflow-hidden">

      {/* ── Left: Live event feed ─────────────────────────────────────── */}
      <div className="flex flex-col flex-1 min-w-0 gap-3">

        {/* Top status bar */}
        <div className="flex items-center justify-between gap-4 h-10 px-4 bg-card border border-border rounded-lg shrink-0">
          <div className="flex items-center gap-3">
            <div className={cn("flex items-center gap-2 text-xs font-mono font-semibold",
              connected ? "text-emerald-400" : "text-red-400")}>
              {connected
                ? <><Wifi className="w-3.5 h-3.5" /> SANDBOX CONNECTED</>
                : <><WifiOff className="w-3.5 h-3.5" /> RECONNECTING…</>}
            </div>
            <div className="w-px h-4 bg-border" />
            <a
              href="http://localhost:5174"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-[11px] font-mono text-primary hover:text-primary/80 transition"
            >
              <ExternalLink className="w-3 h-3" />
              Open Attack Simulator
            </a>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span className="text-muted-foreground">Total events: <span className="text-foreground">{kpis.totalEvents}</span></span>
            <span className="text-orange-400">High: <span className="font-semibold">{kpis.high}</span></span>
            <span className="text-red-400">Critical: <span className="font-semibold">{kpis.critical}</span></span>
          </div>
        </div>

        {/* Feed header */}
        <div className="grid grid-cols-[80px_100px_120px_120px_80px_80px_1fr] gap-2 px-3 py-1.5
          text-[10px] font-mono uppercase text-muted-foreground tracking-wide border-b border-border shrink-0">
          <span>Time</span>
          <span>Severity</span>
          <span>Source</span>
          <span>Target</span>
          <span>MITRE</span>
          <span>Action</span>
          <span>Message</span>
        </div>

        {/* Scrollable feed */}
        <div ref={feedRef} className="flex-1 overflow-y-auto space-y-0.5 pr-1">
          {sandboxEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 gap-3 text-muted-foreground">
              <Terminal className="w-8 h-8 opacity-30" />
              <p className="text-sm font-mono">Waiting for sandbox attacks…</p>
              <p className="text-xs opacity-50">Launch an attack from the simulator to see live events here.</p>
            </div>
          ) : (
            sandboxEvents.map(evt => (
              <div
                key={evt.id}
                onClick={() => setSelectedEvt(evt)}
                className={cn(
                  "grid grid-cols-[80px_100px_120px_120px_80px_80px_1fr] gap-2 px-3 py-1.5 rounded",
                  "text-[11px] font-mono cursor-pointer transition-colors hover:bg-surface-2",
                  selectedEvt?.id === evt.id && "bg-surface-2 ring-1 ring-primary/30",
                  evt.severity === "critical" && "border-l-2 border-red-500/60",
                  evt.severity === "high" && "border-l-2 border-orange-500/60",
                )}
              >
                <span className="text-muted-foreground text-[10px] tabular-nums">
                  {new Date(evt.ts).toLocaleTimeString("en-IN", { hour12: false })}
                </span>
                <span>
                  <SeverityPill severity={sev(evt.severity)} />
                </span>
                <span className="truncate text-slate-300" title={evt.sourceIp}>
                  {ATTACK_ICON[evt.eventType] ?? "⚡"} {evt.sourceIp}
                </span>
                <span className="truncate text-slate-300" title={evt.destHostname}>
                  {evt.destHostname}
                </span>
                <span className="text-purple-400 text-[10px]">{evt.mitre ?? "—"}</span>
                <span className={cn("text-[10px]",
                  evt.action === "Blocked" ? "text-emerald-400" : "text-red-400")}>
                  {evt.action}
                </span>
                <span className="truncate text-slate-400" title={evt.message}>
                  {evt.message}
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* ── Right panel: Active incidents + detail ─────────────────────── */}
      <div className="w-80 shrink-0 flex flex-col gap-3 overflow-hidden">

        {/* Active sandbox incidents */}
        <div className="bg-card border border-border rounded-lg flex flex-col overflow-hidden" style={{ maxHeight: 340 }}>
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border shrink-0">
            <Activity className="w-3.5 h-3.5 text-red-400" />
            <span className="text-xs font-semibold">Active Incidents</span>
            {activeIncidents.length > 0 && (
              <span className="ml-auto text-[10px] bg-red-500/15 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-mono">
                {activeIncidents.length}
              </span>
            )}
          </div>

          <div className="overflow-y-auto flex-1">
            {activeIncidents.length === 0 ? (
              <div className="flex items-center justify-center h-20 text-xs text-muted-foreground font-mono">
                No active incidents
              </div>
            ) : (
              activeIncidents.slice(0, 8).map(inc => (
                <div key={inc.id} className="px-3 py-2 border-b border-border/50 last:border-0 hover:bg-surface-2 transition">
                  <div className="flex items-start gap-2">
                    <span className="text-lg leading-none mt-0.5">{ATTACK_ICON[inc.eventType] ?? "⚡"}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-medium truncate">{inc.title}</div>
                      <div className="text-[10px] text-muted-foreground font-mono truncate mt-0.5">
                        {inc.sourceIp} → {inc.destIp || inc.destHost}
                      </div>
                      <div className="flex gap-1 mt-1.5">
                        <button
                          onClick={() => isolateAsset(inc.destHost || inc.destIp, inc.id)}
                          className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono
                            bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 transition"
                        >
                          <ShieldOff className="w-2.5 h-2.5" /> Isolate
                        </button>
                        <button
                          onClick={() => blockIp(inc.sourceIp, inc.id)}
                          className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono
                            bg-orange-500/10 border border-orange-500/30 text-orange-400 hover:bg-orange-500/20 transition"
                        >
                          <Target className="w-2.5 h-2.5" /> Block IP
                        </button>
                        <button
                          onClick={() => remediateAsset(inc.destHost || inc.destIp)}
                          className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono
                            bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 transition"
                        >
                          <ShieldCheck className="w-2.5 h-2.5" /> Clear
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Asset status grid */}
        <div className="bg-card border border-border rounded-lg flex flex-col overflow-hidden flex-1">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border shrink-0">
            <Zap className="w-3.5 h-3.5 text-primary" />
            <span className="text-xs font-semibold">Asset Status</span>
          </div>
          <div className="overflow-y-auto flex-1 p-2 grid grid-cols-1 gap-1">
            {assets.map(a => (
              <div key={a.id} className={cn(
                "flex items-center gap-2 px-2 py-1.5 rounded text-[11px] font-mono border",
                a.status === "compromised"  && "border-red-500/40 bg-red-500/5",
                a.status === "quarantined"  && "border-orange-500/40 bg-orange-500/5",
                a.status === "online"       && "border-border/50 bg-transparent",
              )}>
                <span className={cn("w-1.5 h-1.5 rounded-full shrink-0",
                  a.status === "compromised" ? "bg-red-500 animate-pulse"   :
                  a.status === "quarantined" ? "bg-orange-500"              :
                  "bg-emerald-500")} />
                <span className="flex-1 truncate text-[10px]" title={a.hostname}>{a.hostname}</span>
                <span className="text-[9px] text-muted-foreground tabular-nums">{a.ip}</span>
                {a.alerts > 0 && (
                  <span className="text-[9px] bg-red-500/15 text-red-400 border border-red-500/30 px-1 rounded font-mono">
                    {a.alerts}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Event detail drawer ──────────────────────────────────────────── */}
      {selectedEvt && (
        <div className="fixed inset-y-0 right-0 w-[420px] bg-card border-l border-border flex flex-col z-50 shadow-2xl">
          <div className="flex items-center gap-3 px-5 py-3 border-b border-border">
            <span className="text-lg">{ATTACK_ICON[selectedEvt.eventType] ?? "⚡"}</span>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold truncate">{selectedEvt.category}</div>
              <div className="text-[10px] font-mono text-muted-foreground">{selectedEvt.id}</div>
            </div>
            <button onClick={() => setSelectedEvt(null)}
              className="w-7 h-7 rounded hover:bg-surface-2 flex items-center justify-center text-muted-foreground hover:text-foreground transition">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-5 space-y-4 text-[12px] font-mono">
            <div className={cn("px-3 py-2 rounded border", SEV_CLASS[selectedEvt.severity])}>
              {selectedEvt.severity.toUpperCase()} — {selectedEvt.eventType.replace(/_/g, " ")}
            </div>

            {[
              ["Time",         new Date(selectedEvt.ts).toLocaleString("en-IN", { hour12: false })],
              ["Source IP",    selectedEvt.sourceIp],
              ["Source Host",  selectedEvt.sourceHost],
              ["Target IP",    selectedEvt.destIp],
              ["Target Host",  selectedEvt.destHostname],
              ["MITRE Tactic", selectedEvt.mitreTactic ?? "Unknown"],
              ["Technique",    selectedEvt.mitre ?? "—"],
              ["Action",       selectedEvt.action],
            ].map(([k, v]) => (
              <div key={k} className="flex gap-2 items-start">
                <span className="w-28 text-muted-foreground shrink-0">{k}</span>
                <span className="text-foreground break-all">{v}</span>
              </div>
            ))}

            <div>
              <div className="text-muted-foreground mb-1">Message</div>
              <div className="bg-surface-2 rounded p-3 text-[11px] text-slate-300 leading-relaxed">
                {selectedEvt.message}
              </div>
            </div>

            {/* Response actions */}
            <div className="pt-2 border-t border-border">
              <div className="text-muted-foreground mb-2">SOC Response</div>
              <div className="flex flex-col gap-2">
                {(() => {
                  const inc = incidents.find(i => i.sourceIp === selectedEvt.sourceIp && i.status !== "Resolved");
                  return (
                    <>
                      <button
                        onClick={() => { if (inc) isolateAsset(selectedEvt.destHostname, inc.id); }}
                        className="flex items-center gap-2 px-3 py-2 rounded border border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition text-[11px]"
                      >
                        <ShieldOff className="w-3.5 h-3.5" /> Isolate {selectedEvt.destHostname}
                      </button>
                      <button
                        onClick={() => { if (inc) blockIp(selectedEvt.sourceIp, inc?.id ?? ""); }}
                        className="flex items-center gap-2 px-3 py-2 rounded border border-orange-500/40 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 transition text-[11px]"
                      >
                        <Target className="w-3.5 h-3.5" /> Block {selectedEvt.sourceIp}
                      </button>
                      <button
                        onClick={() => remediateAsset(selectedEvt.destHostname)}
                        className="flex items-center gap-2 px-3 py-2 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition text-[11px]"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" /> Clear / Remediate
                      </button>
                    </>
                  );
                })()}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
