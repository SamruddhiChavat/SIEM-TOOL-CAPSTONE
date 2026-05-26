import { useState, ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Slack, Mail, Cloud, Shield, Eye, Plus, Copy, RotateCcw, Trash2, Check, AlertCircle, Database, Bell, Users, Key, Rss, BookOpen, Timer, Archive, ClipboardList } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const TABS = ["General","Data Sources","User Management","Notifications","Integrations","Playbooks","SLA Config","Retention","Threat Feeds","Audit Log","API Keys"] as const;

function Toggle({ on }: { on: boolean }) {
  const [v, setV] = useState(on);
  return (
    <button onClick={() => { setV(!v); toast(`${!v ? "Enabled" : "Disabled"}`); }} className={cn("relative w-9 h-5 rounded-full transition", v ? "bg-primary" : "bg-border")}>
      <span className={cn("absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all", v ? "left-[18px]" : "left-0.5")} />
    </button>
  );
}

function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("siem-card p-4", className)}>{children}</div>;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{label}</div>
      {children}
    </div>
  );
}

function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn("h-9 px-3 bg-background border border-border rounded text-xs font-mono outline-none focus:border-primary/40 w-full", props.className)} />;
}

function SectionHeader({ title, icon: Icon }: { title: string; icon: LucideIcon }) {
  return (
    <div className="flex items-center gap-2 mb-3 pb-2 border-b border-border">
      <Icon className="w-4 h-4 text-primary" />
      <span className="text-sm font-semibold">{title}</span>
    </div>
  );
}

function GeneralTab() {
  return (
    <Card className="grid grid-cols-2 gap-4 max-w-3xl">
      <Field label="Organisation Name"><Input defaultValue="Secure Watch Pvt Ltd" /></Field>
      <Field label="Timezone">
        <select className="h-9 px-3 bg-background border border-border rounded text-xs font-mono w-full outline-none focus:border-primary/40">
          <option>Asia/Kolkata (IST, UTC+5:30)</option><option>UTC</option><option>America/New_York</option>
        </select>
      </Field>
      <Field label="Date Format">
        <select className="h-9 px-3 bg-background border border-border rounded text-xs font-mono w-full outline-none focus:border-primary/40">
          <option>YYYY-MM-DD HH:mm:ss</option><option>DD/MM/YYYY HH:mm</option>
        </select>
      </Field>
      <Field label="Default Language">
        <select className="h-9 px-3 bg-background border border-border rounded text-xs font-mono w-full outline-none focus:border-primary/40">
          <option>English (US)</option><option>English (UK)</option>
        </select>
      </Field>
      <div className="col-span-2">
        <button onClick={() => toast.success("Settings saved")} className="h-9 px-4 rounded bg-primary text-primary-foreground text-xs font-medium">Save Changes</button>
      </div>
    </Card>
  );
}

function DataSourcesTab() {
  const sources = [
    { name: "Windows Security Logs", type: "Syslog/WEF", status: "healthy", eps: 142, lastEvent: "2s ago" },
    { name: "Firewall (Cisco ASA)", type: "Syslog UDP", status: "healthy", eps: 87, lastEvent: "1s ago" },
    { name: "EDR (CrowdStrike)", type: "API Pull", status: "healthy", eps: 31, lastEvent: "4s ago" },
    { name: "AWS CloudTrail", type: "S3 Bucket", status: "degraded", eps: 0, lastEvent: "14m ago" },
    { name: "Azure AD Audit", type: "API Pull", status: "disconnected", eps: 0, lastEvent: "2h ago" },
  ];
  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <button onClick={() => toast("Add Data Source wizard opened")} className="h-8 px-3 rounded bg-primary text-primary-foreground text-xs flex items-center gap-1.5"><Plus className="w-3.5 h-3.5" />Add Source</button>
      </div>
      <Card>
        <table className="w-full text-xs">
          <thead><tr className="text-[10px] font-mono uppercase text-muted-foreground border-b border-border">{["Name","Type","Status","EPS","Last Event",""].map(h=><th key={h} className="text-left py-2 px-2">{h}</th>)}</tr></thead>
          <tbody>
            {sources.map(s => (
              <tr key={s.name} className="border-b border-border/50 hover:bg-surface-2">
                <td className="py-2.5 px-2 font-medium">{s.name}</td>
                <td className="px-2 font-mono text-[11px] text-muted-foreground">{s.type}</td>
                <td className="px-2">
                  <span className={cn("flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-mono uppercase w-max",
                    s.status === "healthy" ? "border-success/40 text-success bg-success/10" :
                    s.status === "degraded" ? "border-warning/40 text-warning bg-warning/10" :
                    "border-danger/40 text-danger bg-danger/10")}>
                    {s.status === "healthy" ? <Check className="w-2.5 h-2.5" /> : <AlertCircle className="w-2.5 h-2.5" />}
                    {s.status}
                  </span>
                </td>
                <td className="px-2 font-mono text-primary">{s.eps}/s</td>
                <td className="px-2 text-muted-foreground">{s.lastEvent}</td>
                <td className="px-2 text-right">
                  <button onClick={() => toast("Source config opened")} className="text-[10px] text-primary hover:underline">Configure</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function UsersTab() {
  const ROLES = ["Admin","Analyst","Read Only","Incident Manager"];
  const MOCK_USERS = [
    { name: "Jesal Shah", email: "jesal@securewatch.com", role: "Admin", status: "active" },
    { name: "Samruddhi Chavat", email: "samruddhi@securewatch.com", role: "Analyst", status: "active" },
    { name: "Harsh Zavare", email: "harsh@securewatch.com", role: "Incident Manager", status: "active" },
    { name: "Nikhita Ghule", email: "nikhita@securewatch.com", role: "Read Only", status: "inactive" },
    { name: "Arjuna Patel", email: "arjuna@securewatch.com", role: "Analyst", status: "active" },
  ];
  const [users, setUsers] = useState(MOCK_USERS);
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-muted-foreground">{users.length} users • RBAC enforced</div>
        <button onClick={() => toast("Invite sent")} className="h-8 px-3 rounded bg-primary text-primary-foreground text-xs flex items-center gap-1.5"><Plus className="w-3.5 h-3.5" />Invite User</button>
      </div>
      <Card>
        <table className="w-full text-xs">
          <thead><tr className="text-[10px] font-mono uppercase text-muted-foreground border-b border-border">{["User","Email","Role","Status",""].map(h=><th key={h} className="text-left py-2">{h}</th>)}</tr></thead>
          <tbody>
            {users.map((u, i) => (
              <tr key={u.email} className="border-b border-border/50 hover:bg-surface-2">
                <td className="py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="w-7 h-7 rounded-full bg-primary/15 border border-primary/30 flex items-center justify-center text-[10px] text-primary font-semibold">{u.name.split(" ").map(n=>n[0]).join("")}</div>
                    {u.name}
                  </div>
                </td>
                <td className="text-muted-foreground font-mono text-[11px]">{u.email}</td>
                <td>
                  <select defaultValue={u.role} onChange={e => { setUsers(prev => prev.map((x,j)=>j===i?{...x,role:e.target.value}:x)); toast("Role updated"); }}
                    className="h-7 px-2 bg-background border border-border rounded font-mono text-[11px] outline-none focus:border-primary/40">
                    {ROLES.map(r=><option key={r}>{r}</option>)}
                  </select>
                </td>
                <td><span className={cn("px-2 py-0.5 rounded border text-[9px] font-mono uppercase", u.status==="active"?"border-success/40 text-success bg-success/10":"border-border text-muted-foreground")}>{u.status}</span></td>
                <td className="text-right">
                  <button onClick={() => { setUsers(prev => prev.filter((_,j)=>j!==i)); toast("User removed"); }} className="text-danger"><Trash2 className="w-3.5 h-3.5" /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card>
        <SectionHeader title="Role Permissions Matrix" icon={Shield} />
        <table className="w-full text-xs">
          <thead><tr className="text-[10px] font-mono uppercase text-muted-foreground border-b border-border">{["Permission","Admin","Analyst","Incident Manager","Read Only"].map(h=><th key={h} className="text-left py-2 pr-4">{h}</th>)}</tr></thead>
          <tbody>
            {[
              ["View Dashboards",true,true,true,true],
              ["Manage Incidents",true,true,true,false],
              ["Create Rules",true,true,false,false],
              ["Active Response",true,false,true,false],
              ["Manage Users",true,false,false,false],
              ["View Reports",true,true,true,true],
              ["Export Data",true,true,false,false],
            ].map(([perm,...vals])=>(
              <tr key={perm as string} className="border-b border-border/40">
                <td className="py-1.5 pr-4 font-medium">{perm}</td>
                {(vals as boolean[]).map((v,i)=>(
                  <td key={i} className="pr-4">{v ? <Check className="w-3.5 h-3.5 text-success" /> : <span className="text-muted-foreground text-xs">—</span>}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function NotificationsTab() {
  return (
    <div className="space-y-3">
      <Card>
        <SectionHeader title="Notification Channels" icon={Bell} />
        <div className="space-y-2">
          {[
            { name: "Slack #soc-alerts", status: "connected", type: "Critical + High alerts" },
            { name: "Email SMTP", status: "connected", type: "All severities digest" },
            { name: "PagerDuty", status: "disconnected", type: "Critical only — on-call" },
            { name: "Microsoft Teams", status: "disconnected", type: "Incident updates" },
          ].map(c => (
            <div key={c.name} className="flex items-center gap-3 p-3 rounded border border-border bg-surface-2">
              <div className="flex-1">
                <div className="font-medium text-xs">{c.name}</div>
                <div className="text-[10px] text-muted-foreground">{c.type}</div>
              </div>
              <span className={cn("text-[10px] font-mono", c.status==="connected"?"text-success":"text-muted-foreground")}>
                {c.status==="connected"?"● Connected":"○ Disconnected"}
              </span>
              <button onClick={()=>toast(c.status==="connected"?"Disconnected":"Connected")} className={cn("h-7 px-3 rounded text-[11px] border", c.status==="connected"?"border-border text-muted-foreground":"bg-primary text-primary-foreground border-transparent")}>
                {c.status==="connected"?"Disconnect":"Connect"}
              </button>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <SectionHeader title="Alert Routing Rules" icon={Bell} />
        <table className="w-full text-xs">
          <thead><tr className="text-[10px] font-mono uppercase text-muted-foreground border-b border-border">{["Condition","Channel","Recipients",""].map(h=><th key={h} className="text-left py-2">{h}</th>)}</tr></thead>
          <tbody>
            {[
              ["Severity = Critical","Slack + Email","soc@securewatch.com, jesal@securewatch.com"],
              ["New Incident Created","Email","jesal@securewatch.com"],
              ["Status Changed to Contained","Slack","#soc-alerts"],
              ["Malware Detected","Webhook","https://api.securewatch.com/webhook"],
              ["Failed Logins > 20 in 5m","Email","soc@securewatch.com"],
            ].map((r,i)=>(
              <tr key={i} className="border-b border-border/50 hover:bg-surface-2">
                <td className="py-2.5">{r[0]}</td>
                <td className="text-primary font-mono text-[11px]">{r[1]}</td>
                <td className="text-muted-foreground font-mono text-[11px]">{r[2]}</td>
                <td className="text-right"><button onClick={()=>toast("Edit rule")} className="text-[10px] text-primary hover:underline">Edit</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function IntegrationsTab() {
  const items = [
    { name: "Jira",         status: "connected",    desc: "Auto-create tickets from Critical incidents" },
    { name: "ServiceNow",   status: "disconnected",  desc: "ITSM ticket sync for compliance workflows" },
    { name: "Slack",        status: "connected",    desc: "Alert delivery to #soc-alerts channel" },
    { name: "VirusTotal",   status: "connected",    desc: "IOC enrichment via API" },
    { name: "Shodan",       status: "disconnected",  desc: "External attack surface reconnaissance" },
    { name: "AWS CloudTrail",status:"disconnected",  desc: "Ingest AWS audit and VPC flow logs" },
    { name: "Azure AD",     status: "disconnected",  desc: "Identity and access log ingestion" },
    { name: "Active Directory",status:"connected",   desc: "Account lockout and user enrichment" },
  ];
  return (
    <div className="grid grid-cols-3 gap-3">
      {items.map(item => {
        const connected = item.status === "connected";
        return (
          <Card key={item.name}>
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded bg-primary/10 border border-primary/20 flex items-center justify-center"><Cloud className="w-5 h-5 text-primary" /></div>
              <div>
                <div className="font-semibold text-sm">{item.name}</div>
                <div className={cn("text-[10px] font-mono", connected?"text-success":"text-muted-foreground")}>{connected?"● Connected":"○ Disconnected"}</div>
              </div>
            </div>
            <p className="text-[11px] text-muted-foreground mb-3">{item.desc}</p>
            <button onClick={()=>toast(connected?"Disconnected":"Connected")} className={cn("w-full h-8 rounded text-[11px] font-medium border", connected?"border-border text-muted-foreground":"bg-primary text-primary-foreground border-transparent")}>
              {connected?"Disconnect":"Connect"}
            </button>
          </Card>
        );
      })}
    </div>
  );
}

function PlaybooksTab() {
  const playbooks = [
    { name: "Compromised Host Isolation", trigger: "Asset status → Compromised", steps: 7, enabled: true },
    { name: "Brute Force Response", trigger: "Rule: Failed logins > 20 in 5m", steps: 5, enabled: true },
    { name: "Phishing Email Triage", trigger: "Rule: Suspicious email attachment", steps: 6, enabled: false },
    { name: "Ransomware Containment", trigger: "Rule: Mass file encryption detected", steps: 9, enabled: true },
  ];
  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <button onClick={()=>toast("Playbook builder opened")} className="h-8 px-3 rounded bg-primary text-primary-foreground text-xs flex items-center gap-1.5"><Plus className="w-3.5 h-3.5"/>New Playbook</button>
      </div>
      <div className="space-y-2">
        {playbooks.map(p => (
          <div key={p.name} className="siem-card p-4 flex items-center gap-4">
            <BookOpen className="w-8 h-8 text-primary/40 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="font-semibold text-sm">{p.name}</div>
              <div className="text-[10px] font-mono text-muted-foreground">Trigger: {p.trigger} • {p.steps} steps</div>
            </div>
            <Toggle on={p.enabled} />
            <button onClick={()=>toast("Playbook editor opened")} className="text-[10px] font-mono text-primary hover:underline">Edit</button>
            <button onClick={()=>toast("Test run started")} className="h-7 px-3 rounded border border-border text-[11px] hover:border-primary/40">Test Run</button>
          </div>
        ))}
      </div>
    </div>
  );
}

function SLATab() {
  return (
    <Card className="max-w-2xl space-y-4">
      <SectionHeader title="SLA Configuration by Severity" icon={Timer} />
      {[
        { sev: "Critical", color: "text-danger", triage: "15", resolve: "60" },
        { sev: "High",     color: "text-orange-400", triage: "30", resolve: "240" },
        { sev: "Medium",   color: "text-warning", triage: "120", resolve: "1440" },
        { sev: "Low",      color: "text-success", triage: "480", resolve: "4320" },
      ].map(s => (
        <div key={s.sev} className="grid grid-cols-3 items-center gap-4 p-3 rounded bg-surface-2 border border-border">
          <div className={cn("font-semibold font-mono uppercase tracking-wider", s.color)}>{s.sev}</div>
          <Field label="Triage SLA (mins)"><Input defaultValue={s.triage} /></Field>
          <Field label="Resolve SLA (mins)"><Input defaultValue={s.resolve} /></Field>
        </div>
      ))}
      <button onClick={()=>toast.success("SLA config saved")} className="h-9 px-4 rounded bg-primary text-primary-foreground text-xs font-medium">Save SLA Policy</button>
    </Card>
  );
}

function RetentionTab() {
  return (
    <Card className="max-w-2xl space-y-4">
      <SectionHeader title="Data Retention Policy" icon={Archive} />
      {[
        { label: "Raw Logs (Hot Tier)", value: "90 days" },
        { label: "Raw Logs (Cold Tier / S3)", value: "2 years" },
        { label: "Incident Records", value: "5 years" },
        { label: "Audit Logs", value: "Indefinite (compliance)" },
        { label: "Reports Archive", value: "3 years" },
      ].map(r => (
        <div key={r.label} className="flex items-center gap-4">
          <div className="flex-1 text-xs font-medium">{r.label}</div>
          <Input defaultValue={r.value} className="w-48" />
        </div>
      ))}
      <button onClick={()=>toast.success("Retention policy saved")} className="h-9 px-4 rounded bg-primary text-primary-foreground text-xs font-medium">Save Policy</button>
    </Card>
  );
}

function ThreatFeedsTab() {
  const feeds = [
    { name: "AbuseIPDB",        desc: "Crowdsourced abusive IP database",    on: true },
    { name: "AlienVault OTX",   desc: "Open Threat Exchange IOCs",           on: true },
    { name: "Emerging Threats", desc: "Suricata rule sets",                  on: true },
    { name: "Feodo Tracker",    desc: "Banking trojan C2 list",              on: false },
    { name: "MISP Community",   desc: "Community shared threat intelligence",on: false },
  ];
  return (
    <Card>
      <SectionHeader title="Threat Intelligence Feeds" icon={Rss} />
      <div className="space-y-2">
        {feeds.map(f => (
          <div key={f.name} className="flex items-center gap-3 p-3 rounded border border-border bg-surface-2">
            <div className="flex-1">
              <div className="text-sm font-medium">{f.name}</div>
              <div className="text-[10px] text-muted-foreground">{f.desc}</div>
            </div>
            <Toggle on={f.on} />
          </div>
        ))}
      </div>
    </Card>
  );
}

function AuditLogTab() {
  const logs = [
    { user: "Jesal Shah", action: "Closed Incident INC-10042 with root cause", ts: Date.now()-60000 },
    { user: "System",         action: "SLA breach auto-escalated INC-10041",      ts: Date.now()-300000 },
    { user: "Samruddhi Chavat",  action: "Enabled Correlation Rule: Brute Force SSH", ts: Date.now()-900000 },
    { user: "Jesal Shah", action: "Blocked IP 185.220.101.42 via firewall rule",ts: Date.now()-1800000 },
    { user: "System",         action: "Scheduled Report: Executive Summary sent",  ts: Date.now()-3600000 },
    { user: "Harsh Zavare",    action: "User Nikhita Ghule role changed to Read Only", ts: Date.now()-7200000 },
  ];
  return (
    <Card>
      <div className="flex items-center justify-between mb-3">
        <SectionHeader title="Administrative Audit Log" icon={ClipboardList} />
        <button onClick={()=>toast.success("Exported")} className="text-[10px] font-mono text-primary hover:underline -mt-3">Export JSON</button>
      </div>
      <div className="relative pl-3 border-l-2 border-border space-y-3">
        {logs.map((l,i) => (
          <div key={i} className="relative">
            <div className="absolute -left-[17px] top-1.5 w-2 h-2 rounded-full bg-border" />
            <div className="text-xs">{l.action}</div>
            <div className="text-[9px] font-mono text-muted-foreground mt-0.5">
              {new Date(l.ts).toISOString()} • {l.user}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function ApiKeysTab() {
  return (
    <Card className="max-w-2xl space-y-4">
      <SectionHeader title="API Keys" icon={Key} />
      <Field label="Production API Key">
        <div className="flex gap-2">
          <Input readOnly value="sk_live_••••••••••••••••••••3f7b" />
          <button onClick={()=>toast.success("Copied")} className="h-9 px-3 rounded border border-border text-[11px] flex items-center gap-1 shrink-0"><Copy className="w-3 h-3"/>Copy</button>
          <button onClick={()=>toast("Key revoked")} className="h-9 px-3 rounded border border-danger/40 text-danger text-[11px] flex items-center gap-1 shrink-0"><RotateCcw className="w-3 h-3"/>Revoke</button>
        </div>
      </Field>
      <div className="text-[10px] font-mono text-muted-foreground">Created 2026-01-12 by Jesal Shah • Last used 4 minutes ago</div>
      <button className="h-9 px-3 rounded bg-primary text-primary-foreground text-xs font-medium flex items-center gap-1.5"><Plus className="w-3.5 h-3.5"/>Generate New Key</button>
    </Card>
  );
}

const TAB_COMPONENTS: Record<typeof TABS[number], () => JSX.Element> = {
  "General": GeneralTab,
  "Data Sources": DataSourcesTab,
  "User Management": UsersTab,
  "Notifications": NotificationsTab,
  "Integrations": IntegrationsTab,
  "Playbooks": PlaybooksTab,
  "SLA Config": SLATab,
  "Retention": RetentionTab,
  "Threat Feeds": ThreatFeedsTab,
  "Audit Log": AuditLogTab,
  "API Keys": ApiKeysTab,
};

export default function Settings() {
  const [tab, setTab] = useState<typeof TABS[number]>("General");
  const Component = TAB_COMPONENTS[tab];
  return (
    <div className="p-5">
      <div className="flex border-b border-border mb-4 gap-0.5 flex-wrap">
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)} className={cn("px-3 h-10 text-xs font-medium border-b-2 transition whitespace-nowrap", tab===t?"border-primary text-primary":"border-transparent text-muted-foreground hover:text-foreground")}>{t}</button>
        ))}
      </div>
      <Component />
    </div>
  );
}
