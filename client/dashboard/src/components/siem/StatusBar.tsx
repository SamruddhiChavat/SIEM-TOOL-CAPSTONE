import { useSiem } from "@/lib/siemContext";

export function StatusBar() {
  const { kpis } = useSiem();
  return (
    <div className="h-7 bg-background border-t border-border px-4 flex items-center justify-between text-[10px] font-mono text-muted-foreground">
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1.5"><span className="live-dot" /> SIEM Engine: <span className="text-success">Running</span></span>
        <span className="flex items-center gap-1.5"><span className="live-dot" /> Log Ingestion: <span className="text-success">Active</span></span>
        <span className="flex items-center gap-1.5"><span className="live-dot" /> Correlation Engine: <span className="text-success">Active</span></span>
      </div>
      <div className="flex items-center gap-1">
        <span className="text-primary glow-text-primary">{kpis.eps}</span>
        <span>events/sec</span>
      </div>
      <div className="flex items-center gap-4">
        <span>DB: <span className="text-foreground">428.7 GB</span></span>
        <span>Last backup: <span className="text-foreground">02:14 IST</span></span>
      </div>
    </div>
  );
}
