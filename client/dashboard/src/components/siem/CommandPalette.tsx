import { useEffect, useMemo, useState } from "react";
import { Search, FileText, AlertTriangle, Server, GitBranch, type LucideIcon } from "lucide-react";
import { useSiem } from "@/lib/siemContext";
import { INCIDENTS, RULES_LIB } from "@/lib/siemData";
import { useNavigate } from "react-router-dom";

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void; }) {
  const { logs, assets } = useSiem();
  const [q, setQ] = useState("");
  const navigate = useNavigate();

  useEffect(() => { if (open) setQ(""); }, [open]);

  const results = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return { logs: logs.slice(0,4), incidents: INCIDENTS.slice(0,4), assets: assets.slice(0,4), rules: RULES_LIB.slice(0,4) };
    return {
      logs: logs.filter(l => l.message.toLowerCase().includes(s) || l.srcIp.includes(s) || l.host.toLowerCase().includes(s)).slice(0,5),
      incidents: INCIDENTS.filter(i => i.title.toLowerCase().includes(s) || i.id.toLowerCase().includes(s)).slice(0,5),
      assets: assets.filter(a => a.hostname.toLowerCase().includes(s) || a.ip.includes(s)).slice(0,5),
      rules: RULES_LIB.filter(r => r.name.toLowerCase().includes(s)).slice(0,5),
    };
  }, [q, logs, assets]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-sm flex items-start justify-center pt-[12vh] animate-fade-in" onClick={onClose}>
      <div className="w-full max-w-2xl mx-4 siem-card overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="flex items-center px-4 h-14 border-b border-border">
          <Search className="w-4 h-4 text-primary" />
          <input
            autoFocus
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Search logs, IPs, hostnames, incidents, rules…"
            className="flex-1 ml-3 bg-transparent outline-none text-sm font-mono placeholder:text-muted-foreground"
          />
          <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-border text-muted-foreground">Esc</kbd>
        </div>
        <div className="max-h-[60vh] overflow-auto p-2 space-y-3">
          <Group label="Logs" icon={FileText} items={results.logs.map(l => ({ key: l.id, primary: l.message, secondary: `${l.srcIp} → ${l.host}` }))} onPick={() => { navigate("/logs"); onClose(); }} />
          <Group label="Incidents" icon={AlertTriangle} items={results.incidents.map(i => ({ key: i.id, primary: i.title, secondary: `${i.id} • ${i.status}` }))} onPick={() => { navigate("/incidents"); onClose(); }} />
          <Group label="Assets" icon={Server} items={results.assets.map(a => ({ key: a.id, primary: a.hostname, secondary: `${a.ip} • ${a.os}` }))} onPick={() => { navigate("/assets"); onClose(); }} />
          <Group label="Rules" icon={GitBranch} items={results.rules.map(r => ({ key: r.id, primary: r.name, secondary: `${r.category} • ${r.severity}` }))} onPick={() => { navigate("/rules"); onClose(); }} />
        </div>
      </div>
    </div>
  );
}

function Group({ label, icon: Icon, items, onPick }: { label: string; icon: LucideIcon; items: Array<{key: string; primary: string; secondary: string}>; onPick: () => void }) {
  if (!items.length) return null;
  return (
    <div>
      <div className="flex items-center gap-2 px-2 pb-1 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
        <Icon className="w-3 h-3" /> {label}
      </div>
      <div className="space-y-0.5">
        {items.map((it) => (
          <button key={it.key} onClick={onPick} className="w-full text-left px-2 py-2 rounded hover:bg-surface-2 transition group">
            <div className="text-xs text-foreground truncate">{it.primary}</div>
            <div className="text-[10px] font-mono text-muted-foreground truncate">{it.secondary}</div>
          </button>
        ))}
      </div>
    </div>
  );
}
