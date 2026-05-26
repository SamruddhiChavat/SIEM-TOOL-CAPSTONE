import { X, AlertTriangle, Info, CheckCircle2, AlertCircle } from "lucide-react";
import { useSiem } from "@/lib/siemContext";
import { relTime } from "@/lib/siemData";
import { cn } from "@/lib/utils";

export function NotificationPanel({ open, onClose }: { open: boolean; onClose: () => void; }) {
  const { notifications, markAllRead } = useSiem();
  if (!open) return null;

  const today = notifications.filter(n => Date.now() - n.ts < 86400000);
  const yest = notifications.filter(n => Date.now() - n.ts >= 86400000);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-background/40 backdrop-blur-[1px] animate-fade-in" onClick={onClose} />
      <aside className="fixed right-0 top-0 bottom-0 z-50 w-[380px] bg-card border-l border-border shadow-2xl animate-slide-in-right flex flex-col">
        <div className="h-14 flex items-center justify-between px-4 border-b border-border">
          <div>
            <h3 className="text-sm font-semibold">Notifications</h3>
            <p className="text-[10px] font-mono text-muted-foreground">{notifications.filter(n => !n.read).length} unread</p>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={markAllRead} className="text-[10px] font-mono text-primary hover:underline px-2">Mark all read</button>
            <button onClick={onClose} className="w-8 h-8 rounded hover:bg-surface-2 flex items-center justify-center"><X className="w-4 h-4" /></button>
          </div>
        </div>
        <div className="flex-1 overflow-auto p-3 space-y-4">
          {today.length > 0 && <Group title="Today" items={today} />}
          {yest.length > 0 && <Group title="Yesterday" items={yest} />}
          {notifications.length === 0 && <div className="text-center text-xs text-muted-foreground pt-12">No notifications.</div>}
        </div>
      </aside>
    </>
  );
}

function Group({ title, items }: { title: string; items: ReturnType<typeof useSiem>["notifications"] }) {
  return (
    <div>
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">{title}</div>
      <div className="space-y-1.5">
        {items.map(n => {
          const Icon = n.type === "critical" ? AlertCircle : n.type === "warning" ? AlertTriangle : n.type === "success" ? CheckCircle2 : Info;
          const color = n.type === "critical" ? "text-danger" : n.type === "warning" ? "text-warning" : n.type === "success" ? "text-success" : "text-primary";
          return (
            <div key={n.id} className={cn("p-3 rounded border border-border bg-surface-2 flex gap-3", !n.read && "border-primary/30")}>
              <Icon className={cn("w-4 h-4 mt-0.5 shrink-0", color)} />
              <div className="flex-1 min-w-0">
                <p className="text-xs leading-snug">{n.message}</p>
                <p className="text-[10px] font-mono text-muted-foreground mt-1">{relTime(n.ts)}</p>
              </div>
              {!n.read && <span className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5" />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
