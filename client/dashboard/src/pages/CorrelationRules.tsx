import { useState } from "react";
import { RULES_LIB, RuleDef, RuleCondition, RuleAction, relTime } from "@/lib/siemData";
import { SeverityPill } from "@/components/siem/SeverityPill";
import { Plus, Edit, Copy, Trash2, X, Play, ShieldCheck, Shield, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// ─── colour helpers ──────────────────────────────────────────────────────────
const MATCH_COLORS: Record<string, string> = {
  ALL:      "bg-blue-500/10  text-blue-400  border-blue-500/30",
  ANY:      "bg-amber-500/10 text-amber-400 border-amber-500/30",
  SEQUENCE: "bg-purple-500/10 text-purple-400 border-purple-500/30",
};

const MITRE_TACTIC_COLORS: Record<string, string> = {
  "Discovery":         "text-yellow-400",
  "Credential Access": "text-orange-400",
  "Impact":            "text-red-400",
  "Initial Access":    "text-rose-400",
  "Exfiltration":      "text-violet-400",
  "Lateral Movement":  "text-sky-400",
};

const BLANK_RULE: RuleDef = {
  id: "new", name: "", category: "Network", severity: "medium", enabled: true,
  triggers7d: 0, lastTriggered: Date.now(), description: "",
  mitreTactic: "Initial Access", mitreId: "",
  matchType: "ALL",
  conditions: [
    { id: 1, field: "Event ID / Action", operator: "contains", value: "" },
  ],
  threshold: 5, timeframe: 5, timeUnit: "minutes", groupBy: "Source IP",
  actions: [
    { key: "CREATE_ALERT",  label: "Create High-Priority Alert",  enabled: true  },
    { key: "OPEN_INCIDENT", label: "Open an Incident Ticket",     enabled: true  },
    { key: "EMAIL_SOC",     label: "Send Email to SOC Team",      enabled: false },
    { key: "ISOLATE_HOST",  label: "Isolate Host (Endpoint)",     enabled: false },
    { key: "BLOCK_IP",      label: "Block Source IP (Firewall)",  enabled: false },
  ],
};

// ─── Main page ───────────────────────────────────────────────────────────────
export default function CorrelationRules() {
  const [rules, setRules] = useState<RuleDef[]>(RULES_LIB);
  const [edit, setEdit] = useState<RuleDef | null>(null);
  const [creating, setCreating] = useState(false);

  const openCreate = () => { setCreating(true); setEdit({ ...BLANK_RULE, id: `R${Date.now()}` }); };
  const openEdit   = (r: RuleDef) => { setCreating(false); setEdit(JSON.parse(JSON.stringify(r))); };

  const saveRule = (updated: RuleDef) => {
    if (creating) {
      setRules(rs => [...rs, updated]);
      toast.success("Rule created and enabled.");
    } else {
      setRules(rs => rs.map(r => r.id === updated.id ? updated : r));
      toast.success("Rule updated successfully.");
    }
    setEdit(null);
  };

  const toggle  = (id: string) => setRules(rs => rs.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  const clone   = (r: RuleDef) => { setRules(rs => [...rs, { ...r, id: `R${Date.now()}`, name: `${r.name} (copy)` }]); toast.success("Rule cloned."); };
  const remove  = (id: string) => { setRules(rs => rs.filter(r => r.id !== id)); toast("Rule deleted."); };

  return (
    <div className="p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <h2 className="text-sm font-semibold">Correlation Rules</h2>
          <div className="text-[11px] font-mono text-muted-foreground">
            {rules.filter(r => r.enabled).length} of {rules.length} rules enabled
          </div>
        </div>
        <button onClick={openCreate}
          className="h-9 px-4 rounded-lg bg-primary text-primary-foreground text-xs font-semibold flex items-center gap-1.5 hover:-translate-y-0.5 transition-all shadow-lg shadow-primary/25">
          <Plus className="w-3.5 h-3.5" /> Create Rule
        </button>
      </div>

      {/* Rules table */}
      <div className="siem-card overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-surface-2">
            <tr className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              {["Rule / Description", "MITRE", "Match", "Category", "Severity", "Triggers (7d)", "Status", ""].map(h =>
                <th key={h} className="text-left px-3 py-2.5 font-medium">{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rules.map(r => (
              <tr key={r.id} className="border-t border-border hover:bg-surface-2 group">
                <td className="px-3 py-3 max-w-[240px]">
                  <div className="font-semibold truncate">{r.name}</div>
                  <div className="text-[10px] text-muted-foreground line-clamp-1 mt-0.5">{r.description}</div>
                </td>
                <td className="px-3 py-3 whitespace-nowrap">
                  <div className={cn("text-[10px] font-mono font-bold", MITRE_TACTIC_COLORS[r.mitreTactic] ?? "text-muted-foreground")}>{r.mitreId}</div>
                  <div className="text-[10px] text-muted-foreground">{r.mitreTactic}</div>
                </td>
                <td className="px-3 py-3">
                  <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded border", MATCH_COLORS[r.matchType] ?? "text-muted-foreground border-border")}>
                    {r.matchType}
                  </span>
                </td>
                <td className="px-3 py-3 text-muted-foreground">{r.category}</td>
                <td className="px-3 py-3"><SeverityPill severity={r.severity} /></td>
                <td className="px-3 py-3 font-mono text-primary">{r.triggers7d}</td>
                <td className="px-3 py-3">
                  <button onClick={() => toggle(r.id)}
                    className={cn("relative w-9 h-5 rounded-full transition", r.enabled ? "bg-primary" : "bg-border")}>
                    <span className={cn("absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all", r.enabled ? "left-[18px]" : "left-0.5")} />
                  </button>
                </td>
                <td className="px-3 py-3">
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => openEdit(r)} title="Edit"
                      className="w-7 h-7 rounded border border-border hover:border-primary/50 flex items-center justify-center transition-colors">
                      <Edit className="w-3 h-3" />
                    </button>
                    <button onClick={() => clone(r)} title="Clone"
                      className="w-7 h-7 rounded border border-border hover:border-primary/50 flex items-center justify-center transition-colors">
                      <Copy className="w-3 h-3" />
                    </button>
                    <button onClick={() => remove(r.id)} title="Delete"
                      className="w-7 h-7 rounded border border-border hover:border-danger/50 hover:text-danger flex items-center justify-center transition-colors">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Editor */}
      {edit && <RuleEditorDrawer rule={edit} creating={creating} onSave={saveRule} onClose={() => setEdit(null)} />}
    </div>
  );
}

// ─── Editor drawer ────────────────────────────────────────────────────────────
function RuleEditorDrawer({
  rule, creating, onSave, onClose,
}: { rule: RuleDef; creating: boolean; onSave: (r: RuleDef) => void; onClose: () => void; }) {
  const [draft, setDraft] = useState<RuleDef>(rule);

  const set = (key: keyof RuleDef, val: any) => setDraft(d => ({ ...d, [key]: val }));

  // conditions
  const addCond = () =>
    setDraft(d => ({ ...d, conditions: [...d.conditions, { id: Date.now(), field: "Event ID / Action", operator: "contains", value: "" }] }));
  const remCond = (id: number) =>
    setDraft(d => ({ ...d, conditions: d.conditions.length > 1 ? d.conditions.filter(c => c.id !== id) : d.conditions }));
  const updCond = (id: number, k: keyof RuleCondition, v: string) =>
    setDraft(d => ({ ...d, conditions: d.conditions.map(c => c.id === id ? { ...c, [k]: v } : c) }));

  // actions
  const toggleAction = (key: string) =>
    setDraft(d => ({ ...d, actions: d.actions.map(a => a.key === key ? { ...a, enabled: !a.enabled } : a) }));

  const FIELDS = ["Source IP Address","Destination IP Address","Event ID / Action","Event Severity","Hostname","Username","Destination Port","Process Name","File Path"];
  const OPS    = ["equals","does not equal","contains","does not contain","starts with","matches regex","is greater than"];
  const MITRE_TACTICS = ["Discovery","Credential Access","Impact","Initial Access","Exfiltration","Lateral Movement","Execution","Persistence","Defense Evasion","Command and Control"];

  return (
    <>
      <div className="fixed inset-0 z-40 bg-background/60 backdrop-blur-sm" onClick={onClose} />
      <aside className="fixed right-0 top-0 bottom-0 z-50 w-[800px] bg-card border-l border-border flex flex-col shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border bg-surface-1 flex items-start justify-between">
          <div>
            <div className="text-[10px] font-mono text-primary tracking-widest mb-1">
              {creating ? "RULE BUILDER" : `EDITING · ${rule.id}`}
            </div>
            <h2 className="text-base font-semibold">
              {creating ? "Create New Detection Rule" : draft.name || "Edit Rule"}
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Configure correlation logic to detect and respond to threats automatically.
            </p>
          </div>
          <button onClick={onClose} className="w-8 h-8 rounded hover:bg-surface-2 flex items-center justify-center text-muted-foreground">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-8 text-sm">

          {/* ── Section 1: General ───────────────────────────────────── */}
          <Section num={1} title="General Details" icon={<Shield className="w-4 h-4" />}>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Rule Name">
                <input value={draft.name} onChange={e => set("name", e.target.value)}
                  placeholder="e.g., Excessive Failed Logins"
                  className="input" />
              </Field>
              <Field label="Severity Level">
                <select value={draft.severity} onChange={e => set("severity", e.target.value)} className="input">
                  {["critical","high","medium","low","info"].map(s => <option key={s}>{s}</option>)}
                </select>
              </Field>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Category">
                <select value={draft.category} onChange={e => set("category", e.target.value)} className="input">
                  {["Authentication","Network","Endpoint","Malware","Insider Threat"].map(s => <option key={s}>{s}</option>)}
                </select>
              </Field>
              <Field label="MITRE ATT&CK Tactic">
                <select value={draft.mitreTactic} onChange={e => set("mitreTactic", e.target.value)} className="input">
                  {MITRE_TACTICS.map(t => <option key={t}>{t}</option>)}
                </select>
              </Field>
            </div>

            <Field label="MITRE Technique ID (e.g. T1110.001)">
              <input value={draft.mitreId} onChange={e => set("mitreId", e.target.value)}
                placeholder="e.g., T1190"
                className="input font-mono" />
            </Field>

            <Field label="Description — What does this rule detect and why?">
              <textarea value={draft.description} onChange={e => set("description", e.target.value)}
                rows={3} placeholder="Plain-English explanation of the attack pattern this rule detects..."
                className="input resize-none" />
            </Field>
          </Section>

          {/* ── Section 2: Detection Logic ───────────────────────────── */}
          <Section num={2} title="Detection Logic Builder" icon={<ShieldCheck className="w-4 h-4" />}>
            <p className="text-xs text-muted-foreground -mt-2 mb-3">
              Construct the exact log field criteria an event must meet to fire this rule.
            </p>

            {/* Match type selector */}
            <div className="flex items-center gap-3 bg-surface-2 p-3.5 rounded-lg border border-border mb-5">
              <span className="text-xs text-foreground/80 font-medium">Fire this rule when an event matches</span>
              <select value={draft.matchType} onChange={e => set("matchType", e.target.value as any)}
                className={cn("h-8 px-3 rounded-md text-xs font-bold border outline-none cursor-pointer transition-all", MATCH_COLORS[draft.matchType])}>
                <option value="ALL">ALL conditions (AND)</option>
                <option value="ANY">ANY condition (OR)</option>
                <option value="SEQUENCE">SEQUENCE — events in order (THEN)</option>
              </select>
              <span className="text-xs text-foreground/80 font-medium">of the criteria below:</span>
            </div>

            {/* Conditions list */}
            <div className="space-y-3 pl-4 border-l-2 border-primary/20">
              {draft.conditions.map((cond, i) => (
                <div key={cond.id} className="relative">
                  {i > 0 && (
                    <div className="absolute -top-3 left-[-17px] px-1.5 py-0.5 rounded text-[9px] font-bold bg-card border border-primary/20 text-primary shadow-sm">
                      {draft.matchType === "SEQUENCE" ? "THEN" : draft.matchType}
                    </div>
                  )}
                  <div className="flex items-center gap-2 bg-surface-1/60 p-3 rounded-lg border border-border/60 hover:border-primary/30 transition-all mt-2 group">
                    <div className="w-7 h-7 rounded bg-surface-2 border border-border flex items-center justify-center text-[10px] font-bold text-muted-foreground group-hover:text-primary transition-colors shrink-0">
                      {i + 1}
                    </div>
                    <select value={cond.field} onChange={e => updCond(cond.id, "field", e.target.value)}
                      className="h-9 px-2 bg-black/20 border border-border/50 rounded text-xs font-medium text-foreground outline-none focus:border-primary/50 flex-[1.5]">
                      {FIELDS.map(f => <option key={f}>{f}</option>)}
                    </select>
                    <select value={cond.operator} onChange={e => updCond(cond.id, "operator", e.target.value)}
                      className="h-9 px-2 bg-primary/10 border border-primary/20 rounded text-xs font-semibold text-primary outline-none focus:border-primary/50 flex-1">
                      {OPS.map(o => <option key={o}>{o}</option>)}
                    </select>
                    <input value={cond.value} onChange={e => updCond(cond.id, "value", e.target.value)}
                      placeholder="Enter value…"
                      className="h-9 px-2 bg-black/20 border border-border/50 rounded text-xs font-mono text-foreground flex-[2] outline-none focus:border-primary/50 placeholder:text-muted-foreground/40 placeholder:font-sans" />
                    <button onClick={() => remCond(cond.id)} disabled={draft.conditions.length === 1}
                      className="w-8 h-8 rounded flex items-center justify-center text-muted-foreground hover:bg-danger/10 hover:text-danger disabled:opacity-30 transition-all shrink-0">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
            <button onClick={addCond}
              className="mt-4 w-full py-2.5 rounded-lg border border-dashed border-primary/40 text-primary text-xs font-medium hover:bg-primary/10 transition-all flex items-center justify-center gap-2">
              <Plus className="w-3.5 h-3.5" /> Add Condition
            </button>
          </Section>

          {/* ── Section 3: Threshold ─────────────────────────────────── */}
          <Section num={3} title="Threshold & Timeframe" icon={<AlertTriangle className="w-4 h-4" />}>
            <p className="text-xs text-muted-foreground -mt-2 mb-3">
              How many times must the conditions match before triggering an alert?
            </p>
            <div className="flex flex-wrap items-center gap-3 bg-surface-2 p-4 rounded-lg border border-border text-xs">
              <span className="font-medium text-foreground/80">Trigger when</span>
              <input type="number" value={draft.threshold} onChange={e => set("threshold", Number(e.target.value))}
                className="w-16 h-9 text-center bg-background border border-border rounded font-mono outline-none focus:border-primary/50" />
              <span className="font-medium text-foreground/80">events match within</span>
              <input type="number" value={draft.timeframe} onChange={e => set("timeframe", Number(e.target.value))}
                className="w-16 h-9 text-center bg-background border border-border rounded font-mono outline-none focus:border-primary/50" />
              <select value={draft.timeUnit} onChange={e => set("timeUnit", e.target.value as any)}
                className="h-9 px-3 bg-background border border-border rounded outline-none focus:border-primary/50">
                <option value="seconds">seconds</option>
                <option value="minutes">minutes</option>
                <option value="hours">hours</option>
              </select>
              <span className="font-medium text-foreground/80">grouped by</span>
              <select value={draft.groupBy} onChange={e => set("groupBy", e.target.value)}
                className="h-9 px-3 bg-background border border-border rounded outline-none focus:border-primary/50">
                {["Source IP","Destination IP","User Account","Host","No Grouping"].map(g => <option key={g}>{g}</option>)}
              </select>
            </div>
            <p className="text-[11px] text-muted-foreground mt-2 pl-1">
              💡 Example: Brute Force fires when <span className="text-primary font-bold">50</span> failed-login events match within <span className="text-primary font-bold">5 minutes</span> grouped by <span className="text-primary font-bold">Source IP</span>.
            </p>
          </Section>

          {/* ── Section 4: Actions ───────────────────────────────────── */}
          <Section num={4} title="Automated Response Actions" icon={<ShieldCheck className="w-4 h-4" />}>
            <p className="text-xs text-muted-foreground -mt-2 mb-3">
              What should SecureWatch automatically do when this rule fires?
            </p>
            <div className="grid grid-cols-2 gap-3">
              {draft.actions.map(a => (
                <label key={a.key}
                  className={cn(
                    "flex items-center gap-3 p-3.5 rounded-lg border cursor-pointer transition-all group",
                    a.enabled
                      ? "border-primary/40 bg-primary/5 hover:bg-primary/10"
                      : "border-border bg-surface-2 hover:border-primary/30"
                  )}>
                  <input type="checkbox" checked={a.enabled} onChange={() => toggleAction(a.key)}
                    className="w-4 h-4 accent-primary rounded cursor-pointer" />
                  <div>
                    <div className={cn("font-semibold text-xs transition-colors", a.enabled ? "text-primary" : "group-hover:text-primary")}>
                      {a.label}
                    </div>
                    <div className="text-[10px] font-mono text-muted-foreground mt-0.5">{a.key}</div>
                  </div>
                </label>
              ))}
            </div>
          </Section>

          {/* Test button */}
          <div className="pb-2">
            <button onClick={() => toast.success("Dry-run complete", { description: `Matched ${Math.floor(Math.random()*80)+5} events in the last 24h against this rule logic.` })}
              className="w-full h-10 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-bold flex items-center justify-center gap-2 hover:bg-primary/20 transition-all">
              <Play className="w-4 h-4 fill-current" /> Dry-run Against Last 24h Logs
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-border px-6 py-4 bg-surface-1 flex justify-end gap-3">
          <button onClick={onClose}
            className="h-10 px-5 rounded-lg border border-border hover:bg-surface-2 text-xs font-semibold transition-colors">
            Cancel
          </button>
          <button onClick={() => onSave(draft)}
            className="h-10 px-6 rounded-lg bg-primary text-primary-foreground text-xs font-bold shadow-lg shadow-primary/25 hover:-translate-y-0.5 transition-all">
            {creating ? "Create & Enable Rule" : "Save Changes"}
          </button>
        </div>
      </aside>
    </>
  );
}

// ─── helpers ─────────────────────────────────────────────────────────────────
function Section({ num, title, icon, children }: { num: number; title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="space-y-4">
      <div className="flex items-center gap-3 border-b border-border pb-2">
        <div className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold">{num}</div>
        <div className="flex items-center gap-1.5 text-primary/60">{icon}</div>
        <h3 className="font-semibold text-sm">{title}</h3>
      </div>
      {children}
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">{label}</div>
      {children}
    </div>
  );
}
