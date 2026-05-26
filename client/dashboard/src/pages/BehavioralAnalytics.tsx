import { useState, useEffect, useCallback } from "react";
import { Brain, Activity, Clock, Users, AlertTriangle, TrendingUp, RefreshCw, Wifi, Save, CheckCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useSiem } from "@/lib/siemContext";
import { HourlyChart } from "@/components/siem/HourlyChart";

// ─── Types ────────────────────────────────────────────────────────────────────
type Risk = "critical" | "high" | "medium" | "low";
type AnomalyEntry = {
  id: string; ts: number; entity: string; type: string;
  anomaly: string; risk: Risk; delta: string; dismissed: boolean;
};

// ─── Static seed data (dummy) ─────────────────────────────────────────────────
const SEED_ANOMALIES: AnomalyEntry[] = [
  { id:"A001", ts:Date.now()-1000*60*14,  entity:"rohan.k",    type:"User",    anomaly:"Data download 4.2 GB at 02:17 IST (off-hours)",              risk:"critical", delta:"+3400% vs baseline", dismissed:false },
  { id:"A002", ts:Date.now()-1000*60*52,  entity:"10.2.0.102", type:"Host",    anomaly:"Outbound to 185.220.101.34 — never seen in 30-day baseline",  risk:"high",     delta:"New destination",    dismissed:false },
  { id:"A003", ts:Date.now()-1000*60*120, entity:"priya.s",    type:"User",    anomaly:"Login from Mumbai — usual location is Pune (440 km diff)",    risk:"high",     delta:"440 km deviation",   dismissed:false },
  { id:"A004", ts:Date.now()-1000*60*190, entity:"srv-ad",     type:"Service", anomaly:"LDAP query volume 8× above 30-day average at peak hour",      risk:"medium",   delta:"+680% vs baseline",  dismissed:false },
  { id:"A005", ts:Date.now()-1000*60*300, entity:"arjuna.p",   type:"User",    anomaly:"12 failed MFA attempts in 3 min (30-day baseline: 0)",        risk:"medium",   delta:"New pattern",        dismissed:false },
  { id:"A006", ts:Date.now()-1000*60*480, entity:"printer-it", type:"Device",  anomaly:"Printer initiated SMB connection — not in device profile",    risk:"low",      delta:"New protocol",       dismissed:false },
];

const LIVE_POOL: Omit<AnomalyEntry,"id"|"ts"|"dismissed">[] = [
  { entity:"harsh.m",    type:"User",    anomaly:"Login at 23:41 IST — outside work hours (09:00-17:00)",       risk:"medium", delta:"Off-hours" },
  { entity:"10.1.0.103", type:"Host",    anomaly:"DNS queries to *.onion domain — not in 30-day whitelist",    risk:"high",   delta:"New domain class" },
  { entity:"rohan.k",    type:"User",    anomaly:"Sequential file access: 340 documents in 4 min (avg: 12/hr)",risk:"high",   delta:"+1600% vs baseline" },
  { entity:"srv-mail",   type:"Service", anomaly:"SMTP relay volume 4× daily avg — potential spam campaign",   risk:"medium", delta:"+290% vs baseline" },
  { entity:"ws-ceo",     type:"Host",    anomaly:"Powershell execution from Office process — rare in baseline", risk:"critical",delta:"New process chain" },
];

const USER_PROFILES = [
  { user:"jesal.s",   dept:"Engineering", loginHour:"09:00", dataGB:1.2, geo:"Pune",   devices:2, risk:12 },
  { user:"rohan.k",   dept:"Finance",     loginHour:"08:00", dataGB:0.8, geo:"Mumbai", devices:1, risk:91 },
  { user:"priya.s",   dept:"HR",          loginHour:"10:00", dataGB:0.4, geo:"Pune",   devices:2, risk:67 },
  { user:"harsh.m",   dept:"Engineering", loginHour:"09:00", dataGB:2.1, geo:"Pune",   devices:3, risk:28 },
  { user:"arjuna.p",  dept:"Engineering", loginHour:"09:00", dataGB:1.8, geo:"Pune",   devices:2, risk:45 },
  { user:"nikhita.s", dept:"Marketing",   loginHour:"10:00", dataGB:0.3, geo:"Pune",   devices:1, risk:18 },
];

const ADAPTIVE_RULES = [
  { id:"ABR-001", trigger:"User activity outside 09:00–17:00 IST on workdays", src:"30d hourly login logs",  updated:"2026-05-07", status:"active"   },
  { id:"ABR-002", trigger:"Outbound transfer > 2× 30-day daily avg (>24.8 GB)", src:"30d network flows",    updated:"2026-05-06", status:"active"   },
  { id:"ABR-003", trigger:"Login from geo not seen in last 30 days",             src:"30d geo-login map",    updated:"2026-05-05", status:"active"   },
  { id:"ABR-004", trigger:"New protocol from device type not in baseline",        src:"30d device map",      updated:"2026-05-04", status:"active"   },
  { id:"ABR-005", trigger:"LDAP/AD queries > 5× hourly average",                 src:"30d AD event logs",   updated:"2026-05-03", status:"learning" },
];

// ─── Rich hardcoded 30-day baseline + today's activity (dummy) ────────────────
// baseline: 30-day average events/hour for a 09:00–17:00 org
// current:  today's observed events/hour (with 02:00 anomaly spike)
const HOUR_DUMMY: { h: number; baseline: number; current: number; anomaly: boolean; label: string }[] = [
  { h: 0,  baseline: 18,  current: 22,  anomaly: false, label: "00:00 · Midnight" },
  { h: 1,  baseline: 12,  current: 14,  anomaly: false, label: "01:00 · Night" },
  { h: 2,  baseline: 10,  current: 318, anomaly: true,  label: "02:00 · ⚠ ANOMALY — off-hours data exfiltration (+3100%)" },
  { h: 3,  baseline: 11,  current: 13,  anomaly: false, label: "03:00 · Night" },
  { h: 4,  baseline: 13,  current: 15,  anomaly: false, label: "04:00 · Night" },
  { h: 5,  baseline: 16,  current: 19,  anomaly: false, label: "05:00 · Pre-dawn" },
  { h: 6,  baseline: 32,  current: 38,  anomaly: false, label: "06:00 · Early risers" },
  { h: 7,  baseline: 78,  current: 85,  anomaly: false, label: "07:00 · Early logins" },
  { h: 8,  baseline: 190, current: 204, anomaly: false, label: "08:00 · Pre-work logins" },
  { h: 9,  baseline: 310, current: 328, anomaly: false, label: "09:00 · Work starts" },
  { h: 10, baseline: 390, current: 402, anomaly: false, label: "10:00 · Morning peak" },
  { h: 11, baseline: 430, current: 448, anomaly: false, label: "11:00 · Peak hour" },
  { h: 12, baseline: 280, current: 265, anomaly: false, label: "12:00 · Lunch dip" },
  { h: 13, baseline: 260, current: 271, anomaly: false, label: "13:00 · Lunch end" },
  { h: 14, baseline: 420, current: 437, anomaly: false, label: "14:00 · Afternoon peak" },
  { h: 15, baseline: 405, current: 418, anomaly: false, label: "15:00 · Busy afternoon" },
  { h: 16, baseline: 360, current: 344, anomaly: false, label: "16:00 · End-of-day" },
  { h: 17, baseline: 210, current: 198, anomaly: false, label: "17:00 · Work ends" },
  { h: 18, baseline: 95,  current: 102, anomaly: false, label: "18:00 · After-hours" },
  { h: 19, baseline: 55,  current: 60,  anomaly: false, label: "19:00 · Evening" },
  { h: 20, baseline: 38,  current: 41,  anomaly: false, label: "20:00 · Evening wind-down" },
  { h: 21, baseline: 28,  current: 30,  anomaly: false, label: "21:00 · Late evening" },
  { h: 22, baseline: 22,  current: 25,  anomaly: false, label: "22:00 · Late night" },
  { h: 23, baseline: 16,  current: 18,  anomaly: false, label: "23:00 · Night" },
];

function makeHourProfile(seed = 0) {
  // On retrain, add small deterministic noise to "current" values to simulate model refresh
  return HOUR_DUMMY.map(row => ({
    ...row,
    current: row.anomaly
      ? row.current                                        // keep anomaly spike exact
      : Math.max(8, row.current + ((seed * 7 + row.h * 11) % 22) - 11),
  }));
}

const RISK_CLS: Record<Risk, string> = {
  critical: "text-red-400 bg-red-400/10 border-red-400/30",
  high:     "text-orange-400 bg-orange-400/10 border-orange-400/30",
  medium:   "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  low:      "text-sky-400 bg-sky-400/10 border-sky-400/30",
};

function relTime(ts: number) {
  const d = Math.floor((Date.now()-ts)/1000);
  if (d < 60)   return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  return `${Math.floor(d/3600)}h ago`;
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function BehavioralAnalytics() {
  const { pushNotification, incidents, setIncidents: _si } = useSiem() as any;

  const [tab,        setTab]        = useState<"anomalies"|"profiles"|"baseline"|"rules">("anomalies");
  const [anomalies,  setAnomalies]  = useState<AnomalyEntry[]>(SEED_ANOMALIES);
  const [hourData,   setHourData]   = useState(() => makeHourProfile(0));
  const [retraining, setRetraining] = useState(false);
  const [seed,       setSeed]       = useState(0);
  const [ruleStates, setRuleStates] = useState(() => ADAPTIVE_RULES.map(r => ({ ...r })));
  const [baseline,   setBaseline]   = useState({
    workStart:"09:00", workEnd:"17:00", peakHour:"11:00",
    dailyDataGB:"12.4", geo:"Pune, MH, India", windowDays:"30",
  });
  const [savedBaseline, setSavedBaseline] = useState(false);

  // Live anomaly feed — new entry every 35 s
  useEffect(() => {
    const id = setInterval(() => {
      const pick = LIVE_POOL[Math.floor(Math.random() * LIVE_POOL.length)];
      const entry: AnomalyEntry = {
        ...pick, id: `A${Date.now()}`, ts: Date.now(), dismissed: false,
      };
      setAnomalies(prev => [entry, ...prev].slice(0, 20));
      if (pick.risk === "critical" || pick.risk === "high") {
        toast.warning(`⚠ Behavioral Anomaly: ${pick.entity}`, { description: pick.anomaly });
        pushNotification?.({ type: "warning", message: `UEBA: ${pick.anomaly}` });
      }
    }, 35000);
    return () => clearInterval(id);
  }, [pushNotification]);

  // Retrain: regenerates hour profile, marks ABR-005 active
  const retrain = useCallback(() => {
    setRetraining(true);
    setTimeout(() => {
      const ns = seed + 1;
      setSeed(ns);
      setHourData(makeHourProfile(ns));
      setRuleStates(prev => prev.map(r => r.id === "ABR-005" ? { ...r, status: "active", updated: "2026-05-08" } : r));
      setRetraining(false);
      toast.success("Baseline retrained", { description: "30-day behavioral model updated on latest logs." });
      pushNotification?.({ type: "success", message: "UEBA baseline retrained successfully" });
    }, 2200);
  }, [seed, pushNotification]);

  // Dismiss anomaly
  const dismiss = (id: string) => {
    setAnomalies(prev => prev.map(a => a.id === id ? { ...a, dismissed: true } : a));
    toast("Anomaly dismissed");
  };

  // Open Incident from anomaly (creates real incident in siemContext)
  const openIncident = (a: AnomalyEntry) => {
    const inc = {
      id: `INC-UEBA-${a.id}`, title: `[UEBA] ${a.anomaly}`,
      severity: a.risk, status: "New" as const,
      sourceIp: a.type === "Host" ? a.entity : "internal",
      destIp: "internal", destHost: a.entity,
      mitre: "Behavioral Anomaly", mitreTechnique: "T1078",
      eventType: "BEHAVIORAL_ANOMALY", created: Date.now(),
      rawLog: JSON.stringify(a, null, 2),
      blockedIps: [], notes: "", rootCause: "",
    };
    // inject into siemContext incidents
    try {
      const key = "siem_incidents";
      const existing = JSON.parse(localStorage.getItem(key) || "[]");
      if (!existing.find((i: any) => i.id === inc.id)) {
        localStorage.setItem(key, JSON.stringify([inc, ...existing].slice(0, 50)));
      }
    } catch { /* ignore */ }
    setAnomalies(prev => prev.map(e => e.id === a.id ? { ...e, dismissed: true } : e));
    toast.success("Incident created", { description: `${inc.title} added to Incidents queue.` });
    pushNotification?.({ type: "warning", message: `New UEBA incident: ${a.entity}` });
  };

  // Save baseline config
  const saveBaseline = () => {
    setSavedBaseline(true);
    toast.success("Baseline configuration saved", { description: "Detection thresholds updated." });
    setTimeout(() => setSavedBaseline(false), 3000);
  };

  const active    = anomalies.filter(a => !a.dismissed);
  const critical  = active.filter(a => a.risk === "critical" || a.risk === "high").length;

  return (
    <div className="p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            <h2 className="text-sm font-semibold">Behavioral Analytics &amp; UEBA</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">ADAPTIVE · LIVE</span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Baseline from <span className="text-primary font-mono">30 days</span> · work hours <span className="text-primary font-mono">{baseline.workStart}–{baseline.workEnd} IST</span> · avg data <span className="text-primary font-mono">{baseline.dailyDataGB} GB/day</span>
          </p>
        </div>
        <button onClick={retrain} disabled={retraining}
          className="h-9 px-4 rounded-lg border border-primary/30 text-primary text-xs font-semibold flex items-center gap-2 hover:bg-primary/10 transition-all disabled:opacity-60">
          <RefreshCw className={cn("w-3.5 h-3.5", retraining && "animate-spin")} />
          {retraining ? "Retraining…" : "Retrain Baseline"}
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label:"Active Anomalies",   value:active.length,    sub:"Unresolved",        icon:AlertTriangle, cls:"text-red-400"    },
          { label:"Entities Monitored", value:USER_PROFILES.length+8, sub:"Users + Hosts", icon:Users,      cls:"text-primary"    },
          { label:"Baseline Accuracy",  value:"97.4%",           sub:"30-day model fit",  icon:TrendingUp,   cls:"text-green-400"  },
          { label:"Adaptive Rules",     value:ruleStates.filter(r=>r.status==="active").length, sub:"Auto-learned", icon:Brain, cls:"text-purple-400" },
        ].map(k => (
          <div key={k.label} className="siem-card p-4 flex items-center gap-4">
            <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center bg-surface-2 border border-border")}>
              <k.icon className={cn("w-5 h-5", k.cls)} />
            </div>
            <div>
              <div className={cn("text-xl font-bold font-mono", k.cls)}>{k.value}</div>
              <div className="text-[10px] text-muted-foreground">{k.label}</div>
              <div className="text-[9px] font-mono text-muted-foreground/60">{k.sub}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Hourly Chart — SVG area + line */}
      <div className="siem-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Activity className="w-4 h-4 text-primary" />
          <span className="text-xs font-semibold">Today vs 30-Day Baseline — Hourly Activity</span>
          <div className="flex items-center gap-4 ml-auto text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1.5"><span className="w-6 h-0.5 rounded bg-primary/30 inline-block"/><span className="w-2 h-2 rounded-sm bg-primary/20 inline-block"/>Baseline (30-day avg)</span>
            <span className="flex items-center gap-1.5"><span className="w-6 h-0.5 rounded bg-primary inline-block"/>Today</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-400 inline-block shadow-[0_0_6px_rgba(248,113,113,0.8)]"/>Anomaly</span>
          </div>
        </div>
        <HourlyChart data={hourData} />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {([["anomalies","Anomaly Alerts",AlertTriangle],["profiles","User Profiles",Users],["baseline","Baseline Config",Clock],["rules","Adaptive Rules",Brain]] as const).map(([id,label,Icon]) => (
          <button key={id} onClick={() => setTab(id as any)}
            className={cn("flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 -mb-px transition-colors",
              tab===id ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}>
            <Icon className="w-3.5 h-3.5" />{label}
            {id==="anomalies" && active.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-red-400/20 text-red-400 text-[9px] font-bold">{active.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab: Anomalies */}
      {tab==="anomalies" && (
        <div className="siem-card overflow-hidden">
          {active.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground text-xs">
              <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-400" />
              All anomalies resolved. Live feed will generate new detections automatically.
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead className="bg-surface-2">
                <tr className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  {["Time","Entity","Type","Behavioural Anomaly Detected","Deviation","Risk","Actions"].map(h =>
                    <th key={h} className="text-left px-3 py-2.5 font-medium">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {active.map(a => (
                  <tr key={a.id} className="border-t border-border hover:bg-surface-2 group animate-fade-in">
                    <td className="px-3 py-3 font-mono text-[10px] text-muted-foreground whitespace-nowrap">{relTime(a.ts)}</td>
                    <td className="px-3 py-3 font-semibold font-mono text-[11px]">{a.entity}</td>
                    <td className="px-3 py-3"><span className="text-[10px] px-2 py-0.5 rounded border bg-surface-2 text-muted-foreground">{a.type}</span></td>
                    <td className="px-3 py-3 max-w-xs text-foreground/90 leading-snug">{a.anomaly}</td>
                    <td className="px-3 py-3 font-mono text-orange-400 text-[10px] font-bold">{a.delta}</td>
                    <td className="px-3 py-3"><span className={cn("text-[10px] font-bold px-2 py-0.5 rounded border capitalize", RISK_CLS[a.risk])}>{a.risk}</span></td>
                    <td className="px-3 py-3">
                      <div className="flex gap-1.5">
                        <button onClick={() => openIncident(a)}
                          className="text-[10px] px-2.5 py-1 rounded bg-primary/10 border border-primary/30 text-primary font-semibold hover:bg-primary/20 transition whitespace-nowrap">
                          Open Incident
                        </button>
                        <button onClick={() => dismiss(a.id)}
                          className="text-[10px] px-2.5 py-1 rounded border border-border text-muted-foreground hover:text-foreground transition whitespace-nowrap">
                          Dismiss
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab: Profiles */}
      {tab==="profiles" && (
        <div className="grid grid-cols-3 gap-4">
          {USER_PROFILES.map(u => (
            <div key={u.user} className="siem-card p-4 space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center text-primary text-xs font-bold">
                  {u.user.slice(0,2).toUpperCase()}
                </div>
                <div>
                  <div className="font-semibold text-xs">{u.user}</div>
                  <div className="text-[10px] text-muted-foreground">{u.dept}</div>
                </div>
                <div className="ml-auto text-right">
                  <div className={cn("text-sm font-bold font-mono", u.risk>=70?"text-red-400":u.risk>=40?"text-yellow-400":"text-green-400")}>{u.risk}</div>
                  <div className="text-[9px] text-muted-foreground">Risk Score</div>
                </div>
              </div>
              <div className="h-1.5 rounded-full bg-surface-2 overflow-hidden">
                <div className={cn("h-full rounded-full", u.risk>=70?"bg-red-400":u.risk>=40?"bg-yellow-400":"bg-green-400")} style={{width:`${u.risk}%`}} />
              </div>
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                {[["Avg Login",u.loginHour+" IST"],["Daily Data",u.dataGB+" GB"],["Usual Geo",u.geo],["Devices",u.devices+" enrolled"]].map(([l,v]) => (
                  <div key={l} className="bg-surface-2 rounded p-2">
                    <div className="text-muted-foreground uppercase tracking-wider text-[9px]">{l}</div>
                    <div className="font-mono font-semibold mt-0.5">{v}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab: Baseline */}
      {tab==="baseline" && (
        <div className="siem-card p-6 space-y-5">
          <p className="text-xs text-muted-foreground">These thresholds are auto-learned and retrain weekly. Override any value and save to update live detection.</p>
          <div className="grid grid-cols-2 gap-5">
            {([
              ["workStart","Work Hours Start","IST — before this is off-hours"],
              ["workEnd","Work Hours End","IST — after this is off-hours"],
              ["peakHour","Peak Login Hour","Highest expected login volume"],
              ["dailyDataGB","Avg Daily Data (GB)","Transfers >2× this trigger alert"],
              ["geo","Normal Login Geo","New geo location triggers alert"],
              ["windowDays","Baseline Window (days)","Rolling window for model training"],
            ] as const).map(([key, label, hint]) => (
              <div key={key} className="space-y-1.5">
                <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">{label}</div>
                <input value={baseline[key]} onChange={e => setBaseline(b => ({ ...b, [key]: e.target.value }))}
                  className="input" />
                <div className="text-[10px] text-muted-foreground">{hint}</div>
              </div>
            ))}
          </div>
          <button onClick={saveBaseline}
            className={cn("h-9 px-5 rounded-lg text-xs font-bold flex items-center gap-2 transition-all",
              savedBaseline ? "bg-green-500/20 border border-green-500/40 text-green-400" : "bg-primary text-primary-foreground shadow-lg shadow-primary/25 hover:-translate-y-0.5")}>
            {savedBaseline ? <><CheckCircle className="w-4 h-4"/>Saved!</> : <><Save className="w-4 h-4"/>Save Baseline Config</>}
          </button>
        </div>
      )}

      {/* Tab: Adaptive Rules */}
      {tab==="rules" && (
        <div className="space-y-3">
          <div className="siem-card overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-surface-2">
                <tr className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  {["Rule ID","Trigger Condition","Learned From","Last Updated","Status"].map(h =>
                    <th key={h} className="text-left px-3 py-2.5 font-medium">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {ruleStates.map(r => (
                  <tr key={r.id} className="border-t border-border hover:bg-surface-2">
                    <td className="px-3 py-3 font-mono text-primary text-[10px]">{r.id}</td>
                    <td className="px-3 py-3 max-w-xs">{r.trigger}</td>
                    <td className="px-3 py-3 text-[10px] font-mono text-muted-foreground">{r.src}</td>
                    <td className="px-3 py-3 font-mono text-[10px] text-muted-foreground">{r.updated}</td>
                    <td className="px-3 py-3">
                      <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded border",
                        r.status==="active" ? "text-green-400 bg-green-400/10 border-green-400/30" : "text-yellow-400 bg-yellow-400/10 border-yellow-400/30")}>
                        {r.status==="active" ? "● Active" : "◌ Learning"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-start gap-3 bg-primary/5 border border-primary/20 rounded-lg p-4 text-xs">
            <Wifi className="w-4 h-4 text-primary shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-primary mb-1">How Adaptive Detection Works</div>
              <div className="text-muted-foreground leading-relaxed">
                The engine ingests 30 days of logs and builds a statistical profile of "normal" for each user, host, and service.
                Every week it retrains on new data. When any metric deviates beyond the learned threshold — even an unknown attack method — an anomaly alert is raised.
                <strong className="text-foreground"> Click "Retrain Baseline"</strong> above to update the model immediately — watch ABR-005 switch from <em>Learning</em> to <em>Active</em>.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
