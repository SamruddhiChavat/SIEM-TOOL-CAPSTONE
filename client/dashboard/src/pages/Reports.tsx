import { useState } from "react";
import { FileBarChart, Calendar, Download, Play, Shield, Network, User, Activity, Plus, Clock, Trash2, BarChart2 } from "lucide-react";
import { toast } from "sonner";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, PieChart, Pie, Cell } from "recharts";
import { useSiem } from "@/lib/siemContext";
import { cn } from "@/lib/utils";

const TEMPLATES = [
  { id: "exec",    name: "Executive Summary",          desc: "High-level overview: KPIs, top incidents, posture score.", icon: Shield,       last: "2026-04-28", tag: "C-Suite" },
  { id: "mitre",   name: "MITRE ATT&CK Coverage",      desc: "Heatmap coverage, detected techniques, gaps analysis.",   icon: FileBarChart,  last: "2026-04-25", tag: "SOC" },
  { id: "mttd",    name: "MTTD / MTTR Metrics",        desc: "Detection and response time trends per severity level.",  icon: Clock,         last: "2026-04-29", tag: "SOC" },
  { id: "incident",name: "Incident Report",             desc: "Per-incident deep dive: timeline, evidence, root cause.", icon: FileBarChart,  last: "2026-04-29", tag: "Analyst" },
  { id: "comply",  name: "Compliance Report",           desc: "ISO 27001 / PCI-DSS / HIPAA control mapping.",           icon: Shield,        last: "2026-04-15", tag: "Audit" },
  { id: "threat",  name: "Threat Intelligence Summary", desc: "External threat feeds, IOCs, observed campaigns.",       icon: Activity,      last: "2026-04-26", tag: "SOC" },
  { id: "user",    name: "User Activity Report",        desc: "Per-user logon, file access, UEBA risk scores.",         icon: User,          last: "2026-04-22", tag: "HR/Legal" },
  { id: "net",     name: "Network Traffic Report",      desc: "Top talkers, blocked connections, geo distribution.",    icon: Network,       last: "2026-04-27", tag: "Analyst" },
];

const SCHEDULES = [
  { name: "Executive Summary", freq: "Weekly — Monday 08:00 IST", recipients: "ceo@securewatch.com, ciso@securewatch.com", active: true },
  { name: "MTTD / MTTR Metrics", freq: "Daily — 07:00 IST", recipients: "soc@securewatch.com", active: true },
  { name: "Compliance Report", freq: "Monthly — 1st of month", recipients: "audit@securewatch.com", active: false },
];

const REPORT_HISTORY = [
  { name: "Executive Summary", date: "2026-04-28 08:00", by: "Scheduler", size: "2.4 MB" },
  { name: "Incident Report",   date: "2026-04-29 14:23", by: "Jesal Shah", size: "1.1 MB" },
  { name: "MTTD / MTTR Metrics", date: "2026-04-29 07:00", by: "Scheduler", size: "640 KB" },
  { name: "Network Traffic",   date: "2026-04-27 09:45", by: "Samruddhi Chavat", size: "3.8 MB" },
];

export default function Reports() {
  const [generating, setGenerating] = useState<string | null>(null);
  const [progress, setProgress]     = useState(0);
  const [preview, setPreview]       = useState<string | null>(null);
  const [activeTab, setActiveTab]   = useState<"templates" | "schedules" | "history" | "builder">("templates");
  const [timeRange, setTimeRange]   = useState("Last 7 days");
  const [schedules, setSchedules]   = useState(SCHEDULES);
  const { kpis } = useSiem();

  const generate = (name: string) => {
    setGenerating(name); setProgress(0); setPreview(null);
    const i = setInterval(() => {
      setProgress(p => {
        if (p >= 100) { clearInterval(i); setGenerating(null); setPreview(name); return 100; }
        return p + 10;
      });
    }, 80);
  };

  return (
    <div className="p-5 space-y-4">
      {/* Tab nav */}
      <div className="flex border-b border-border gap-1">
        {(["templates", "schedules", "history", "builder"] as const).map(t => (
          <button key={t} onClick={() => setActiveTab(t)} className={cn("px-4 h-10 text-xs font-medium border-b-2 capitalize transition", activeTab === t ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}>{t}</button>
        ))}
        {/* Time range picker */}
        <div className="ml-auto flex items-center gap-2 pb-1">
          <select value={timeRange} onChange={e => setTimeRange(e.target.value)} className="h-8 px-2 bg-surface-2 border border-border rounded text-[11px] font-mono outline-none focus:border-primary/40">
            {["Last 24h","Last 7 days","Last 30 days","Last Quarter","Custom Range"].map(o => <option key={o}>{o}</option>)}
          </select>
        </div>
      </div>

      {/* Templates */}
      {activeTab === "templates" && (
        <div className="grid grid-cols-4 gap-3">
          {TEMPLATES.map(t => {
            const Icon = t.icon;
            const isGen = generating === t.id;
            return (
              <div key={t.id} className="siem-card p-4 flex flex-col">
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0"><Icon className="w-5 h-5 text-primary" /></div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold leading-tight">{t.name}</div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-border bg-surface-2 text-muted-foreground">{t.tag}</span>
                      <span className="text-[10px] font-mono text-muted-foreground">Last: {t.last}</span>
                    </div>
                  </div>
                </div>
                <p className="text-[11px] text-muted-foreground mt-2 flex-1 leading-relaxed">{t.desc}</p>
                {isGen ? (
                  <div className="mt-3">
                    <div className="h-1.5 bg-surface-2 rounded overflow-hidden border border-border">
                      <div className="h-full bg-primary transition-all duration-100" style={{ width: `${progress}%` }} />
                    </div>
                    <div className="text-[10px] font-mono text-primary mt-1">Generating… {progress}%</div>
                  </div>
                ) : (
                  <div className="mt-3 flex gap-2">
                    <button onClick={() => generate(t.id)} className="flex-1 h-8 rounded bg-primary text-primary-foreground text-[11px] font-medium flex items-center justify-center gap-1.5 hover:opacity-90">
                      <Play className="w-3 h-3" /> Generate
                    </button>
                    <button onClick={() => toast("Schedule dialog opened")} className="flex-1 h-8 rounded border border-border bg-surface-2 text-[11px] flex items-center justify-center gap-1.5 hover:border-primary/40">
                      <Calendar className="w-3 h-3" /> Schedule
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Schedules */}
      {activeTab === "schedules" && (
        <div className="siem-card overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-border">
            <div className="font-semibold text-sm">Scheduled Reports</div>
            <button onClick={() => toast("Schedule builder opened")} className="h-8 px-3 rounded bg-primary text-primary-foreground text-xs flex items-center gap-1.5"><Plus className="w-3.5 h-3.5" /> New Schedule</button>
          </div>
          <table className="w-full text-xs">
            <thead className="bg-surface-2"><tr className="text-[10px] font-mono uppercase text-muted-foreground">{["Report","Frequency","Recipients","Status",""].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}</tr></thead>
            <tbody>
              {schedules.map((s, i) => (
                <tr key={i} className="border-t border-border hover:bg-surface-2">
                  <td className="px-4 py-3 font-medium">{s.name}</td>
                  <td className="px-4 text-muted-foreground font-mono text-[11px]">{s.freq}</td>
                  <td className="px-4 text-muted-foreground font-mono text-[11px]">{s.recipients}</td>
                  <td className="px-4">
                    <span className={cn("px-2 py-0.5 rounded border text-[9px] font-mono uppercase", s.active ? "border-success/40 text-success bg-success/10" : "border-border text-muted-foreground")}>
                      {s.active ? "Active" : "Paused"}
                    </span>
                  </td>
                  <td className="px-4 text-right">
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => { setSchedules(prev => prev.map((x, j) => j === i ? { ...x, active: !x.active } : x)); toast(s.active ? "Schedule paused" : "Schedule activated"); }} className="text-[10px] font-mono text-primary hover:underline">{s.active ? "Pause" : "Activate"}</button>
                      <button onClick={() => { setSchedules(prev => prev.filter((_, j) => j !== i)); toast("Schedule deleted"); }} className="text-danger"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* History */}
      {activeTab === "history" && (
        <div className="siem-card overflow-hidden">
          <div className="p-4 border-b border-border font-semibold text-sm">Report Archive</div>
          <table className="w-full text-xs">
            <thead className="bg-surface-2"><tr className="text-[10px] font-mono uppercase text-muted-foreground">{["Report","Generated At","Generated By","Size",""].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}</tr></thead>
            <tbody>
              {REPORT_HISTORY.map((r, i) => (
                <tr key={i} className="border-t border-border hover:bg-surface-2">
                  <td className="px-4 py-3 font-medium">{r.name}</td>
                  <td className="px-4 font-mono text-[11px] text-muted-foreground">{r.date}</td>
                  <td className="px-4 text-muted-foreground">{r.by}</td>
                  <td className="px-4 font-mono text-[11px] text-muted-foreground">{r.size}</td>
                  <td className="px-4 text-right">
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => toast.success("PDF downloaded")} className="text-[10px] font-mono text-primary flex items-center gap-1 hover:underline"><Download className="w-3 h-3" />PDF</button>
                      <button onClick={() => toast.success("CSV downloaded")} className="text-[10px] font-mono text-muted-foreground flex items-center gap-1 hover:underline"><Download className="w-3 h-3" />CSV</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Builder */}
      {activeTab === "builder" && (
        <div className="space-y-4">
          <div className="siem-card p-4 flex items-center gap-4">
            <BarChart2 className="w-8 h-8 text-primary/50" />
            <div className="flex-1">
              <div className="font-semibold text-sm">Interactive Report Builder</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Drag and drop widgets to construct a custom report layout</div>
            </div>
            <button onClick={() => toast("Report saved")} className="h-8 px-3 rounded bg-primary text-primary-foreground text-xs">Save Report</button>
            <button onClick={() => toast.success("PDF exported")} className="h-8 px-3 rounded border border-border text-xs flex items-center gap-1.5"><Download className="w-3.5 h-3.5" />Export PDF</button>
          </div>
          <div className="grid grid-cols-3 gap-3">
            {["KPI Summary Widget","Event Volume Chart","Severity Breakdown Pie","Top Incidents Table","MITRE Coverage Heatmap","Analyst Workload Bar Chart"].map(w => (
              <div key={w} className="siem-card p-3 border-dashed cursor-grab hover:border-primary/40 transition flex items-center gap-3">
                <div className="w-8 h-8 rounded bg-surface-2 border border-border flex items-center justify-center"><BarChart2 className="w-4 h-4 text-muted-foreground" /></div>
                <div>
                  <div className="text-xs font-medium">{w}</div>
                  <div className="text-[10px] text-muted-foreground">Drag to add</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live Report Preview */}
      {preview && (
        <div className="siem-card p-6 animate-fade-in">
          <div className="flex items-start justify-between border-b border-border pb-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded bg-primary/15 border border-primary/40 flex items-center justify-center"><Shield className="w-6 h-6 text-primary" /></div>
              <div>
                <div className="text-[10px] font-mono text-primary tracking-[0.2em]">SENTINEL-WATCH SIEM</div>
                <h2 className="text-lg font-semibold">{TEMPLATES.find(t => t.id === preview)?.name ?? preview}</h2>
                <div className="text-[10px] font-mono text-muted-foreground">{timeRange} • Generated by Jesal Shah</div>
              </div>
            </div>
            <div className="flex gap-2">
              <button onClick={() => toast.success("PDF downloaded")} className="h-8 px-3 rounded bg-primary text-primary-foreground text-[11px] flex items-center gap-1"><Download className="w-3 h-3" />PDF</button>
              <button onClick={() => toast.success("CSV downloaded")} className="h-8 px-3 rounded border border-border text-[11px] flex items-center gap-1"><Download className="w-3 h-3" />CSV</button>
              <button onClick={() => toast.success("JSON downloaded")} className="h-8 px-3 rounded border border-border text-[11px] flex items-center gap-1"><Download className="w-3 h-3" />JSON</button>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-4">
            {[["Events Ingested", kpis.totalEvents.toLocaleString()], ["Incidents", kpis.openIncidents], ["Blocked Threats", kpis.blocked], ["MTTD", `${kpis.mttd}m`]].map(([l, v]) => (
              <div key={String(l)} className="p-3 rounded border border-border bg-surface-2">
                <div className="text-[10px] font-mono uppercase text-muted-foreground">{l}</div>
                <div className="text-xl font-mono text-primary mt-1">{v}</div>
              </div>
            ))}
          </div>
          <div className="mt-4">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Events per Day</div>
            <div className="h-40">
              <ResponsiveContainer>
                <BarChart data={Array.from({ length: 7 }, (_, i) => ({ d: `Day ${i + 1}`, v: Math.round(1000 + Math.random() * 4000) }))}>
                  <XAxis dataKey="d" stroke="hsl(var(--muted-foreground))" fontSize={10} tickLine={false} />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", fontSize: 11 }} />
                  <Bar dataKey="v" fill="hsl(var(--primary))" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="mt-6 pt-4 border-t border-border text-[10px] font-mono text-muted-foreground">Confidential • SOC Internal • Approved by: Jesal Shah (SOC Lead)</div>
        </div>
      )}
    </div>
  );
}
