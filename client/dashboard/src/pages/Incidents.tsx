import { useMemo, useState, useEffect, useCallback } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { SeverityPill, SeverityBar } from "@/components/siem/SeverityPill";
import { Search, Plus, X, FileDown, UserPlus, ShieldAlert, CheckCircle2, RefreshCw, Clock, Play, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { fmtDateTime, relTime, Incident } from "@/lib/siemData";
import { useSiem, ActiveIncident } from "@/lib/siemContext";
import { getPlaybook } from "@/lib/playbooks";

const STATUS_CLR: Record<string, string> = {
  New: "bg-danger/15 text-danger border-danger/40",
  Investigating: "bg-warning/15 text-warning border-warning/40",
  Contained: "bg-primary/15 text-primary border-primary/40",
  Resolved: "bg-success/15 text-success border-success/40",
  new: "bg-danger/15 text-danger border-danger/40",
  investigating: "bg-warning/15 text-warning border-warning/40",
  open: "bg-warning/15 text-warning border-warning/40",
  closed: "bg-success/15 text-success border-success/40",
};
const STEPS = ["Created", "Triaged", "Investigating", "Contained", "Resolved"];

export default function Incidents() {
  const { incidents, alerts, apiError, isolateAsset, blockIp, captureSnapshot, disableAccount, closeIncident, updateIncidentStatus, remediateAsset } = useSiem();
  const loc = useLocation();
  const navigate = useNavigate();
  
  const [q, setQ] = useState(loc.state?.search || "");
  const [statusF, setStatusF] = useState("All");
  const [sevF, setSevF] = useState("All");
  
  // Merge live incidents (from sandbox attacks) with alert-derived rows
  const allRows = useMemo(() => {
    // Prefer real incidents
    const incRows = incidents.map(inc => ({
      id: inc.id,
      title: inc.title,
      severity: inc.severity as Incident["severity"],
      status: inc.status,
      assignee: "Unassigned",
      affected: inc.destHost || inc.destIp || "Unknown",
      created: inc.created,
      updated: inc.created,
      mitre: inc.mitre || "Unknown",
      sourceIp: inc.sourceIp || "",
      isGroup: false,
      groupType: "",
      childCount: 0,
      isFp: false,
      fpMsg: "",
      rawLog: inc.rawLog,
      recommendation: `Isolate ${inc.destHost || inc.destIp} and block ${inc.sourceIp}`,
      _isLive: true,
      _incidentRef: inc,
    }));
    // Fallback to alerts if no incidents yet
    if (incRows.length > 0) return incRows;
    return alerts.map(a => ({
      id: a.id,
      title: a.title,
      severity: a.severity as Incident["severity"],
      status: (a.status?.charAt(0).toUpperCase() + a.status?.slice(1)) || "New",
      assignee: "Unassigned",
      affected: a.dst || "Unknown",
      created: a.ts,
      updated: a.ts,
      mitre: a.rule || "Unknown",
      sourceIp: a.src || "",
      isGroup: false,
      groupType: "",
      childCount: 0,
      isFp: false,
      fpMsg: "",
      rawLog: a.rawLog,
      recommendation: a.recommendation,
      _isLive: false,
      _incidentRef: null as ActiveIncident | null,
    }));
  }, [incidents, alerts]);

  const rows = useMemo(() => allRows.filter(i =>
    (q === "" || i.title.toLowerCase().includes(q.toLowerCase()) || i.id.toLowerCase().includes(q.toLowerCase())) &&
    (statusF === "All" || i.status.toLowerCase() === statusF.toLowerCase()) &&
    (sevF === "All" || i.severity === sevF.toLowerCase())
  ), [allRows, q, statusF, sevF]);

  const [sel, setSel] = useState<typeof allRows[0] | null>(null);
  const [tab, setTab] = useState<"Overview" | "Timeline" | "MITRE" | "Threat Intel" | "Evidence" | "Assets" | "Playbook" | "Response" | "Notes" | "Audit Log">("Overview");

  // Track playbook step completion per incident
  const [playbookState, setPlaybookState] = useState<Record<string, number[]>>(() => {
    try { const local = localStorage.getItem("siem_playbook"); return local ? JSON.parse(local) : {}; } catch { return {}; }
  });
  const [runningStep, setRunningStep] = useState<string | null>(null); // "incId-stepId"
  useEffect(() => { localStorage.setItem("siem_playbook", JSON.stringify(playbookState)); }, [playbookState]);

  const executePlaybookStep = useCallback(async (
    incidentId: string, stepId: number, action: string | undefined, inc: typeof sel
  ) => {
    const key = `${incidentId}-${stepId}`;
    setRunningStep(key);
    // Simulate 1-2s execution delay for realism
    await new Promise(r => setTimeout(r, 800 + Math.random() * 800));

    try {
      if (action === "BLOCK_IP" && inc?.sourceIp) {
        if (inc._incidentRef) blockIp(inc.sourceIp, incidentId);
        else toast.success(`IP ${inc.sourceIp} blocked at perimeter firewall`);
      } else if (action === "ISOLATE_HOST" && inc?.affected) {
        if (inc._incidentRef) isolateAsset(inc.affected, incidentId);
        else { updateIncidentStatus(incidentId, "Contained"); toast.success(`Host ${inc.affected} isolated — network access cut off`); }
      } else if (action === "DISABLE_ACCOUNT") {
        if (inc._incidentRef) disableAccount(incidentId);
        else toast.success("User account disabled in Active Directory");
      } else if (action === "CAPTURE_SNAPSHOT") {
        if (inc._incidentRef) captureSnapshot(incidentId);
        else toast.success("Forensic snapshot queued — EDR collecting memory dump");
      } else if (action === "CLOSE_INCIDENT") {
        // Auto-remediate the asset when final step is done
        if (inc?.affected) remediateAsset(inc.affected);
        updateIncidentStatus(incidentId, "Resolved");
        toast.success("Incident resolved — asset status restored to Online", { duration: 4000 });
      } else {
        toast.success(`Step completed: action logged to SIEM audit trail`);
      }
      setPlaybookState(prev => ({ ...prev, [incidentId]: [...(prev[incidentId] || [1]), stepId] }));
    } catch (e) {
      toast.error("Action failed — check backend connectivity");
    } finally {
      setRunningStep(null);
    }
  }, [blockIp, isolateAsset, disableAccount, captureSnapshot, updateIncidentStatus, remediateAsset]);

  const togglePlaybookTask = useCallback((incidentId: string, taskId: number) => {
    setPlaybookState(prev => {
      const current = prev[incidentId] || [1];
      if (current.includes(taskId)) return { ...prev, [incidentId]: current.filter(id => id !== taskId) };
      return { ...prev, [incidentId]: [...current, taskId] };
    });
  }, []);

  // Auto-sync sel so response actions (isolate/block) reflect immediately
  useEffect(() => {
    if (!sel?._isLive) return;
    const fresh = allRows.find(r => r.id === sel.id);
    if (fresh) setSel(fresh);
  }, [allRows]); // eslint-disable-line react-hooks/exhaustive-deps

  const [closeModal, setCloseModal] = useState(false);
  const [rootCause, setRootCause] = useState("");

  const handleClose = async () => {
    if (!rootCause) { toast.error("Root Cause is mandatory to close the incident."); return; }
    if (sel?._incidentRef) closeIncident(sel.id, rootCause);
    else toast.success("Incident closed and recorded with root cause");
    setCloseModal(false);
    setRootCause("");
  };

  // MITRE data per attack type
  const MITRE_INFO: Record<string, { tactic: string; technique: string; id: string; desc: string; detection: string; mitigation: string }> = {
    "Brute Force": { tactic: "Credential Access", technique: "Brute Force", id: "T1110", desc: "Adversaries use brute-force techniques to gain access to accounts by trying many passwords.", detection: "Monitor failed authentication attempts, especially in rapid succession from a single IP.", mitigation: "Enable account lockout policies, MFA, and rate-limiting on authentication endpoints." },
    "Credential Access": { tactic: "Credential Access", technique: "Brute Force", id: "T1110", desc: "Adversaries attempt to gain unauthorized access to credentials.", detection: "Monitor authentication logs for anomalies.", mitigation: "Enforce MFA and strong password policies." },
    "Initial Access": { tactic: "Initial Access", technique: "Phishing / Exploit Public App", id: "T1566", desc: "Adversaries attempt to gain initial access via phishing or exploiting public-facing applications.", detection: "Monitor email gateways and web server logs for suspicious requests.", mitigation: "Patch public-facing applications. Train users to identify phishing." },
    "Phishing": { tactic: "Initial Access", technique: "Phishing", id: "T1566", desc: "Adversaries send malicious emails to gain initial access.", detection: "Monitor email gateway for suspicious links and attachments.", mitigation: "Email filtering, user awareness training, and DMARC enforcement." },
    "Impact": { tactic: "Impact", technique: "Network DoS / Data Destruction", id: "T1498", desc: "Adversaries disrupt availability by flooding network resources.", detection: "Monitor for traffic spikes and CPU saturation on edge devices.", mitigation: "Deploy DDoS mitigation services, rate-limiting, and geo-blocking." },
    "Privilege Escalation": { tactic: "Privilege Escalation", technique: "Abuse Elevation Control", id: "T1548", desc: "Adversaries attempt to gain higher-level permissions.", detection: "Monitor for unexpected privilege changes and use of admin tools.", mitigation: "Enforce least privilege and monitor for anomalous token use." },
    "Discovery": { tactic: "Discovery", technique: "Network Service Scan", id: "T1046", desc: "Adversaries scan the network to identify services and hosts.", detection: "Monitor for port scanning activity from internal and external IPs.", mitigation: "Segment networks and use intrusion detection rules for scans." },
    "Collection": { tactic: "Collection", technique: "Adversary-in-the-Middle", id: "T1557", desc: "Adversaries intercept communications between systems.", detection: "Monitor for ARP spoofing and abnormal network flows.", mitigation: "Use encrypted communications and network segmentation." },
    "Exfiltration": { tactic: "Exfiltration", technique: "Exfiltration Over Physical Medium", id: "T1052", desc: "Adversaries steal data via physical or logical exfiltration channels.", detection: "Monitor outbound traffic for large data transfers.", mitigation: "DLP tools, USB restrictions, and egress traffic monitoring." },
  };

  const getMitreInfo = (inc: typeof sel) => {
    if (!inc) return MITRE_INFO["Initial Access"];
    return MITRE_INFO[inc._incidentRef?.mitre || ""] || MITRE_INFO[inc.mitre || ""] || MITRE_INFO["Initial Access"];
  };

  return (
    <div className="p-5 space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search incident ID or title…" className="w-full h-9 pl-8 pr-3 bg-surface-2 border border-border rounded text-xs font-mono outline-none focus:border-primary/40" />
        </div>
        <Select value={statusF} onChange={setStatusF} options={["All", "New", "Investigating", "Contained", "Resolved"]} />
        <Select value={sevF} onChange={setSevF} options={["All", "Critical", "High", "Medium", "Low", "Info"]} />
        <button onClick={() => toast("Refreshed")} className="h-9 px-3 rounded border border-border bg-surface-2 text-xs flex items-center gap-1.5 hover:border-primary/40">
          <RefreshCw className={cn("w-3.5 h-3.5")} /> Refresh
        </button>
        <button onClick={() => toast.success("Incident creation form opened")} className="ml-auto h-9 px-3 rounded bg-primary text-primary-foreground text-xs font-medium flex items-center gap-1.5 hover:opacity-90">
          <Plus className="w-3.5 h-3.5" /> Create Incident
        </button>
      </div>

      <div className="siem-card overflow-hidden">
        {!apiError && (
          <div className="flex items-center gap-2 px-3 py-1.5 text-[11px] font-mono text-success border-b border-border bg-success/5">
            ● Live data — {allRows.length} incidents from sandbox
          </div>
        )}
        {apiError && (
          <div className="flex items-center gap-2 px-3 py-1.5 text-[11px] font-mono text-warning border-b border-border bg-warning/5">
            ● Simulation mode — backend unavailable
          </div>
        )}
        <table className="w-full text-xs">
          <thead className="bg-surface-2">
            <tr className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              {["ID", "Title", "Severity", "Status", "Assignee", "Affected", "Created", "Updated", ""].map(h => <th key={h} className="text-left px-3 py-2 font-medium">{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map(i => (
              <tr key={i.id} onClick={() => { setSel(i); setTab("Overview"); }} className={cn("relative border-t border-border hover:bg-surface-2 transition cursor-pointer", i.isGroup && "bg-primary/5", i.isFp && "opacity-60")}>
                <td className="px-3 py-2.5 relative">
                  <SeverityBar severity={i.severity} />
                  <span className="font-mono text-primary ml-1">{i.id}</span>
                  {i.isGroup && <span className="ml-1 text-[9px] font-mono text-primary border border-primary/40 px-1 rounded">GROUP</span>}
                </td>
                <td className="px-3 truncate max-w-[280px]">
                  {i.title}
                  {i.isFp && <span className="ml-1 text-[9px] text-warning font-mono">[FP?]</span>}
                </td>
                <td className="px-3"><SeverityPill severity={i.severity} pulse /></td>
                <td className="px-3"><span className={cn("px-2 py-0.5 rounded border text-[10px] font-mono uppercase tracking-wider", STATUS_CLR[i.status] || STATUS_CLR.New)}>{i.status}</span></td>
                <td className="px-3 text-muted-foreground">{i.assignee}</td>
                <td className="px-3 font-mono">{i.affected}{i.isGroup && i.childCount > 0 ? ` (${i.childCount} alerts)` : ""}</td>
                <td className="px-3 text-[10px] font-mono text-muted-foreground">{fmtDateTime(i.created)}</td>
                <td className="px-3 text-[10px] font-mono">
                  {Date.now() - i.created > (i.severity === 'critical' ? 3600000 : 7200000) ? (
                    <span className="text-danger font-semibold bg-danger/10 px-1 py-0.5 rounded border border-danger/40 flex items-center w-max gap-1">
                      <Clock className="w-3 h-3" /> SLA BREACH
                    </span>
                  ) : (
                    <span className="text-success">{Math.max(0, Math.floor(((i.severity === 'critical' ? 3600000 : 7200000) - (Date.now() - i.created)) / 60000))}m left</span>
                  )}
                </td>
                <td className="px-3 text-primary text-[10px]">Open →</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={9} className="px-3 py-6 text-center text-muted-foreground">No incidents found</td></tr>
            )}
          </tbody>
        </table>
        <div className="flex items-center justify-between p-3 border-t border-border text-[10px] font-mono text-muted-foreground">
          <span>Showing {rows.length} of {allRows.length} incidents</span>
          <div className="flex gap-1">
            {[1, 2, 3].map(p => <button key={p} className={cn("w-7 h-7 rounded border", p === 1 ? "border-primary text-primary" : "border-border")}>{p}</button>)}
          </div>
        </div>
      </div>

      {sel && (
        <>
          <div className="fixed inset-0 z-40 bg-background/50 backdrop-blur-sm" onClick={() => setSel(null)} />
          <aside className="fixed right-0 top-0 bottom-0 z-50 w-[640px] bg-card border-l border-border flex flex-col animate-slide-in-right">
            <div className="p-4 border-b border-border">
              <div className="flex items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="text-[10px] font-mono text-primary">{sel.id}</div>
                  <h2 className="text-base font-semibold mt-0.5">{sel.title}</h2>
                  <div className="flex items-center gap-2 mt-2">
                    <SeverityPill severity={sel.severity} pulse />
                    <span className={cn("px-2 py-0.5 rounded border text-[10px] font-mono uppercase", STATUS_CLR[sel.status] || STATUS_CLR.New)}>{sel.status}</span>
                    <span className="text-[10px] font-mono text-muted-foreground">{relTime(sel.created)}</span>
                    {Date.now() - sel.created > (sel.severity === 'critical' ? 3600000 : 7200000) && (
                      <span className="text-[9px] text-danger font-mono font-semibold uppercase tracking-wider bg-danger/15 px-1.5 py-0.5 rounded border border-danger/40">SLA Breached</span>
                    )}
                  </div>
                </div>
                <button onClick={() => setSel(null)} className="w-8 h-8 rounded hover:bg-surface-2 flex items-center justify-center"><X className="w-4 h-4" /></button>
              </div>

              <div className="mt-4 flex items-center gap-1">
                {STEPS.map((s, i) => {
                  const stepIdx = STEPS.indexOf(sel.status === "New" || sel.status === "new" ? "Created" : sel.status);
                  const done = i <= stepIdx;
                  return (
                    <div key={s} className="flex-1 flex items-center gap-1">
                      <div className={cn("w-6 h-6 rounded-full border flex items-center justify-center text-[10px] font-mono", done ? "bg-primary border-primary text-primary-foreground" : "border-border text-muted-foreground")}>{i + 1}</div>
                      <span className={cn("text-[10px] font-mono", done ? "text-primary" : "text-muted-foreground")}>{s}</span>
                      {i < STEPS.length - 1 && <div className={cn("flex-1 h-px", done ? "bg-primary" : "bg-border")} />}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="flex border-b border-border overflow-x-auto custom-scrollbar">
              {(["Overview", "Timeline", "MITRE", "Threat Intel", "Evidence", "Assets", "Playbook", "Response", "Notes", "Audit Log"] as const).map(t => (
                <button key={t} onClick={() => setTab(t)} className={cn("px-4 h-10 text-xs font-medium border-b-2 transition whitespace-nowrap", tab === t ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}>{t}</button>
              ))}
            </div>

            <div className="flex-1 overflow-auto p-4 text-xs space-y-3">

              {tab === "Overview" && (<>
                <Field label="Description" value={`${sel.title} — detected from ${sel.sourceIp || "unknown source"}`} />
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Attack Vector" value={sel.mitre || "Unknown"} />
                  <Field label="MITRE Tactic" value={sel.mitre || "Unknown"} />
                  <Field label="Assignee" value={sel.assignee} />
                  <Field label="Affected Assets" value={sel.affected} />
                </div>
                {sel.recommendation && (
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Recommended Actions</div>
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 p-2 rounded bg-surface-2 border border-border text-[11px]">
                        <span className="text-primary font-mono">1.</span> {sel.recommendation}
                      </div>
                    </div>
                  </div>
                )}
              </>)}

              {tab === "Timeline" && (
                <div className="space-y-2">
                  <div className="flex gap-3 p-2 rounded bg-surface-2 border border-border">
                    <div className="text-[10px] font-mono text-muted-foreground w-20 shrink-0">{new Date(sel.created).toLocaleTimeString("en-IN", { hour12: false })}</div>
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px]">Event correlated on {sel.affected}</div>
                      <div className="font-mono text-[10px] text-muted-foreground truncate">src={sel.sourceIp}</div>
                    </div>
                  </div>
                </div>
              )}

              {tab === "MITRE" && (() => {
                const mi = getMitreInfo(sel);
                return (
                  <div className="space-y-4">
                    <div className="p-3 rounded border border-border bg-surface-2">
                      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Observed Tactics &amp; Techniques</div>
                      <div className="flex flex-col gap-2">
                        <div className="p-2 rounded bg-background border border-border flex items-center gap-3">
                          <div className="w-8 h-8 rounded bg-primary/10 flex items-center justify-center font-mono text-primary text-[10px]">TA</div>
                          <div className="flex-1">
                            <div className="font-semibold text-primary">{mi.tactic}</div>
                            <div className="text-[10px] text-muted-foreground mt-0.5">{mi.desc}</div>
                          </div>
                        </div>
                        <div className="w-px h-3 bg-border ml-7" />
                        <div className="p-2 rounded bg-background border border-danger/30 flex items-center gap-3">
                          <div className="w-8 h-8 rounded bg-danger/10 flex items-center justify-center font-mono text-danger text-[10px]">T1</div>
                          <div className="flex-1">
                            <div className="font-semibold text-danger">{mi.technique}</div>
                            <div className="text-[10px] text-muted-foreground mt-0.5">{mi.id} · {mi.tactic}</div>
                          </div>
                          <a href={`https://attack.mitre.org/techniques/${mi.id}/`} target="_blank" rel="noreferrer" className="text-[10px] font-mono text-primary hover:underline shrink-0">{mi.id}</a>
                        </div>
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Detection &amp; Mitigation Guidance</div>
                      <div className="p-3 text-[11px] leading-relaxed rounded bg-surface-2 border border-border text-muted-foreground space-y-2">
                        <p><strong>Detection:</strong> {mi.detection}</p>
                        <p><strong>Mitigation:</strong> {mi.mitigation}</p>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {tab === "Threat Intel" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Automated Indicator Enrichment</div>
                    <button onClick={() => toast("Enrichment refreshed")} className="text-[10px] text-primary flex items-center gap-1 hover:underline"><RefreshCw className="w-3 h-3" /> Rescan</button>
                  </div>
                  
                  <div className="p-3 rounded border border-danger/40 bg-danger/5">
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex items-center gap-2">
                        <div className="px-1.5 py-0.5 bg-danger text-danger-foreground text-[10px] font-mono rounded">IP</div>
                        <div className="font-mono text-danger font-semibold">{sel.sourceIp || "192.168.1.50"}</div>
                      </div>
                      <div className="text-danger font-semibold">98/100 Risk</div>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[10px] text-muted-foreground font-mono">
                      <div><span className="text-foreground">Provider:</span> AlienVault OTX</div>
                      <div><span className="text-foreground">Tags:</span> malware, c2, botnet</div>
                      <div><span className="text-foreground">Location:</span> Moscow, RU</div>
                      <div><span className="text-foreground">Last Seen:</span> 12 mins ago</div>
                    </div>
                  </div>
                  
                  <div className="p-3 rounded border border-border bg-surface-2">
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex items-center gap-2">
                        <div className="px-1.5 py-0.5 bg-primary text-primary-foreground text-[10px] font-mono rounded">HASH</div>
                        <div className="font-mono text-primary truncate max-w-[200px]">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</div>
                      </div>
                      <div className="text-success font-semibold">Clean</div>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[10px] text-muted-foreground font-mono">
                      <div><span className="text-foreground">Provider:</span> VirusTotal</div>
                      <div><span className="text-foreground">Score:</span> 0/72 engines</div>
                    </div>
                  </div>
                </div>
              )}

              {tab === "Evidence" && (
                <div className="space-y-2">
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Supporting log entries</div>
                    <pre className="bg-background border border-border rounded p-2 text-[10px] overflow-auto leading-relaxed">{sel.rawLog || "No raw log available"}</pre>
                  </div>
                </div>
              )}

              {tab === "Assets" && (
                <div className="space-y-2">
                  <div className="p-3 rounded bg-surface-2 border border-border flex flex-col gap-3">
                    <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full bg-danger animate-pulse" />
                      <div className="flex-1">
                        <div className="font-medium">{sel.affected}</div>
                        <div className="text-[10px] font-mono text-muted-foreground">
                          Status: Under Investigation • Risk Score: 85/100
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {tab === "Playbook" && (() => {
                const pb = getPlaybook(sel._incidentRef?.eventType || sel.mitre || "", sel.mitre);
                const completedTasks = new Set(playbookState[sel.id] || [1]);
                // Auto-sync with response actions
                if (sel._incidentRef?.isolatedAt) completedTasks.add(2);
                if (sel._incidentRef?.snapshotAt) completedTasks.add(pb.steps.findIndex(s => s.action==="CAPTURE_SNAPSHOT")+1);
                if (sel._incidentRef?.accountDisabledAt) completedTasks.add(pb.steps.findIndex(s => s.action==="DISABLE_ACCOUNT")+1);
                if (sel.status === "Resolved") pb.steps.forEach(s => completedTasks.add(s.id));

                const progress = Math.round((completedTasks.size / pb.steps.length) * 100);
                const allDone = progress === 100;

                return (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{pb.id} — {pb.name}</div>
                        <div className="text-[9px] font-mono text-primary mt-0.5">{pb.mitreTactic}</div>
                      </div>
                      <span className={cn("px-2 py-0.5 rounded border text-[9px] font-mono uppercase", allDone ? "bg-success/15 text-success border-success/40" : "bg-warning/15 text-warning border-warning/40")}>
                        {allDone ? "✓ Completed" : `${completedTasks.size}/${pb.steps.length} steps`}
                      </span>
                    </div>
                    <div className="w-full bg-surface-2 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-primary h-full transition-all duration-700" style={{ width: `${progress}%` }} />
                    </div>
                    {allDone && (
                      <div className="p-3 rounded border border-success/40 bg-success/5 text-[11px] text-success">
                        ✓ All playbook steps completed. Incident resolved and asset status restored to Online.
                      </div>
                    )}
                    <div className="space-y-2">
                      {pb.steps.map(step => {
                        const isDone = completedTasks.has(step.id);
                        const isRunning = runningStep === `${sel.id}-${step.id}`;
                        const isLocked = !isDone && step.id > 1 && !completedTasks.has(step.id - 1);
                        return (
                          <div key={step.id} className={cn(
                            "flex items-start gap-3 p-3 rounded border transition",
                            isDone ? "border-success/30 bg-success/5" : isLocked ? "border-border opacity-50" : "border-border bg-surface-2 hover:border-primary/40"
                          )}>
                            <div className={cn(
                              "w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-mono font-bold mt-0.5 shrink-0 border",
                              isDone ? "bg-success border-success text-success-foreground" : isRunning ? "border-primary" : "border-border text-muted-foreground"
                            )}>
                              {isRunning ? <Loader2 className="w-3 h-3 animate-spin text-primary" /> : isDone ? <CheckCircle2 className="w-3 h-3" /> : step.id}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className={cn("text-xs font-medium", isDone && "line-through text-muted-foreground")}>{step.task}</div>
                              <div className="text-[10px] text-muted-foreground mt-0.5 leading-relaxed">{step.detail}</div>
                              {isDone && <div className="text-[9px] font-mono text-success mt-1">✓ Executed · logged to SIEM audit trail</div>}
                            </div>
                            {!isDone && !isLocked && (
                              <button
                                disabled={isRunning}
                                onClick={() => executePlaybookStep(sel.id, step.id, step.action, sel)}
                                className={cn(
                                  "shrink-0 h-7 px-2.5 rounded text-[10px] font-mono font-semibold flex items-center gap-1.5 transition",
                                  step.action ? "bg-primary text-primary-foreground hover:bg-primary/80" : "border border-border text-muted-foreground hover:border-primary/40 hover:text-primary"
                                )}
                              >
                                {isRunning ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                                {step.action ? "Execute" : "Mark Done"}
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {tab === "Response" && (
                <div className="space-y-4">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Active Response Actions</div>
                  
                  <div className="grid grid-cols-2 gap-3">
                    <button onClick={() => {
                      if (sel._incidentRef) isolateAsset(sel.affected, sel.id);
                      else toast.success(`Isolated asset ${sel.affected}`);
                    }} className="flex flex-col items-start p-3 rounded border border-danger/40 bg-danger/5 hover:bg-danger/10 transition group text-left">
                      <div className="flex items-center gap-2 mb-1">
                        <ShieldAlert className="w-4 h-4 text-danger group-hover:animate-pulse" />
                        <span className="font-semibold text-danger">Isolate Asset</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground">Cut network traffic to {sel.affected}.</span>
                    </button>
                    
                    <button onClick={() => {
                      if (sel._incidentRef) blockIp(sel.sourceIp, sel.id);
                      else toast.success(`Blocked IP ${sel.sourceIp}`);
                    }} className="flex flex-col items-start p-3 rounded border border-border bg-surface-2 hover:border-primary/40 transition group text-left">
                      <div className="flex items-center gap-2 mb-1">
                        <X className="w-4 h-4 text-warning" />
                        <span className="font-semibold text-warning">Block Source IP</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground">Add {sel.sourceIp} to perimeter blocklist.</span>
                    </button>
                    
                    <button onClick={() => { 
                      if (sel._incidentRef) captureSnapshot(sel.id);
                      else toast("Forensic collection started"); 
                    }} className="flex flex-col items-start p-3 rounded border border-border bg-surface-2 hover:border-primary/40 transition group text-left">
                      <div className="flex items-center gap-2 mb-1">
                        <FileDown className="w-4 h-4 text-primary" />
                        <span className="font-semibold text-primary">Capture Snapshot</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground">Trigger EDR to pull memory and disk.</span>
                    </button>
                    
                    <button onClick={() => {
                      if (sel._incidentRef) disableAccount(sel.id);
                      else {
                        updateIncidentStatus(sel.id, "Investigating");
                        toast("User account disabled");
                      }
                    }} className="flex flex-col items-start p-3 rounded border border-border bg-surface-2 hover:border-primary/40 transition group text-left">
                      <div className="flex items-center gap-2 mb-1">
                        <UserPlus className="w-4 h-4 text-muted-foreground" />
                        <span className="font-semibold">Disable Account</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground">Lock AD account mapped to this host.</span>
                    </button>
                  </div>
                  
                  {sel._incidentRef && (
                    <div className="p-3 rounded border border-border bg-surface-2 text-[11px] space-y-1">
                      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Response Status</div>
                      {sel._incidentRef.isolatedAt && <div className="text-success">✓ Host isolated at {new Date(sel._incidentRef.isolatedAt).toLocaleTimeString()}</div>}
                      {sel._incidentRef.snapshotAt && <div className="text-success">✓ Snapshot captured at {new Date(sel._incidentRef.snapshotAt).toLocaleTimeString()}</div>}
                      {sel._incidentRef.accountDisabledAt && <div className="text-success">✓ AD Account disabled at {new Date(sel._incidentRef.accountDisabledAt).toLocaleTimeString()}</div>}
                      {sel._incidentRef.blockedIps.length > 0 && <div className="text-success">✓ {sel._incidentRef.blockedIps.length} IP(s) blocked: {sel._incidentRef.blockedIps.join(", ")}</div>}
                      {!sel._incidentRef.isolatedAt && !sel._incidentRef.snapshotAt && !sel._incidentRef.accountDisabledAt && sel._incidentRef.blockedIps.length === 0 && <div className="text-muted-foreground">No containment actions taken yet.</div>}
                    </div>
                  )}
                </div>
              )}

              {tab === "Notes" && (
                <div className="space-y-3">
                  <textarea placeholder="Add an analyst note… (Use @ to tag)" className="w-full h-24 bg-background border border-border rounded p-2 text-xs outline-none focus:border-primary/40" />
                  <button className="px-3 h-8 rounded bg-primary text-primary-foreground text-xs">Add Note</button>
                  <div className="space-y-1.5">
                    {[
                      { who: "Jesal Shah", t: 1000 * 60 * 40, note: "Confirmed source IP is on AbuseIPDB. Blocking at perimeter." },
                      { who: "Samruddhi Chavat", t: 1000 * 60 * 120, note: "Initial triage complete. Escalating to L2." },
                    ].map((n, i) => (
                      <div key={i} className="p-2 rounded bg-surface-2 border border-border">
                        <div className="flex justify-between text-[10px] font-mono text-muted-foreground mb-1"><span className="text-primary">{n.who}</span><span>{relTime(Date.now() - n.t)}</span></div>
                        <div className="text-xs">{n.note}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {tab === "Audit Log" && (
                <div className="space-y-3">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2 flex items-center justify-between">
                    <span>Immutable Activity Log</span>
                    <button className="text-primary hover:underline">Export JSON</button>
                  </div>
                  <div className="relative pl-3 border-l-2 border-border space-y-4">
                    {[
                      { msg: "System auto-assigned incident based on SLA rules to team SOC-L1", by: "System", t: Date.now() - 3600000 },
                      { msg: "Threat Intel automated enrichment completed (2 indicators found)", by: "System", t: Date.now() - 3605000 },
                      { msg: "Incident created automatically from Correlation Rule 'T1190 Exploit Public-Facing Application'", by: "System", t: Date.now() - 3610000 },
                    ].map((l, i) => (
                      <div key={i} className="relative">
                        <div className="absolute -left-[17px] top-1.5 w-2 h-2 rounded-full bg-border" />
                        <div className="text-xs">{l.msg}</div>
                        <div className="text-[9px] font-mono text-muted-foreground mt-0.5">{new Date(l.t).toISOString()} • {l.by}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="border-t border-border p-3 flex items-center gap-2">
              <button onClick={() => toast("Incident escalated", { description: sel.id })} className="flex-1 h-9 rounded bg-danger/15 border border-danger/40 text-danger text-xs flex items-center justify-center gap-1.5"><ShieldAlert className="w-3.5 h-3.5" /> Escalate</button>
              <button onClick={() => toast("Added to Watchlist")} className="flex-1 h-9 rounded bg-surface-2 border border-border text-xs flex items-center justify-center gap-1.5 hover:border-primary/40"><Search className="w-3.5 h-3.5" /> Watch</button>
              <button onClick={() => toast("Reassigned")} className="flex-1 h-9 rounded bg-surface-2 border border-border text-xs flex items-center justify-center gap-1.5 hover:border-primary/40"><UserPlus className="w-3.5 h-3.5" /> Assign</button>
              <button onClick={() => setCloseModal(true)} className="flex-1 h-9 rounded bg-success/15 border border-success/40 text-success text-xs flex items-center justify-center gap-1.5 hover:bg-success/25"><CheckCircle2 className="w-3.5 h-3.5" /> Close</button>
              <button onClick={() => toast("PDF exported")} className="flex-1 h-9 rounded bg-primary/15 border border-primary/40 text-primary text-xs flex items-center justify-center gap-1.5 hover:bg-primary/25"><FileDown className="w-3.5 h-3.5" /> Export PDF</button>
            </div>
            
            {closeModal && (
              <div className="absolute inset-0 bg-background/90 backdrop-blur-sm z-50 flex items-center justify-center p-6 animate-fade-in">
                <div className="siem-card w-full max-w-sm p-4 flex flex-col shadow-2xl">
                  <h3 className="font-semibold text-danger mb-1">Close Incident</h3>
                  <p className="text-xs text-muted-foreground mb-4">Mandatory root cause analysis is required to close.</p>
                  
                  <label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1 block">Root Cause Summary *</label>
                  <textarea 
                    value={rootCause} onChange={e => setRootCause(e.target.value)} 
                    className="w-full h-24 bg-surface-2 border border-border rounded p-2 text-xs outline-none focus:border-danger/40 mb-4" 
                    placeholder="Describe how the threat was neutralized..."
                  />
                  
                  <div className="flex gap-2 justify-end">
                    <button onClick={() => setCloseModal(false)} className="px-3 h-8 rounded border border-border text-xs">Cancel</button>
                    <button onClick={handleClose} className="px-3 h-8 rounded bg-danger text-primary-foreground text-xs font-semibold">Confirm Close</button>
                  </div>
                </div>
              </div>
            )}
          </aside>
        </>
      )}
    </div>
  );
}

function Select({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)} className="h-9 px-2 bg-surface-2 border border-border rounded text-xs font-mono outline-none focus:border-primary/40">
      {options.map(o => <option key={o} value={o} className="bg-card">{o}</option>)}
    </select>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">{label}</div>
      <div className="text-xs">{value}</div>
    </div>
  );
}
