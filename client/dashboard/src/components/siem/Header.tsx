import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { Bell, Search, ChevronRight, Activity } from "lucide-react";
import { useSiem } from "@/lib/siemContext";
import { cn } from "@/lib/utils";

const TITLES: Record<string, { title: string; crumb: string }> = {
  "/":          { title: "Operations Overview", crumb: "DASHBOARD" },
  "/threat-map":{ title: "Global Threat Map",  crumb: "THREAT INTELLIGENCE" },
  "/incidents": { title: "Incident Management",crumb: "INCIDENTS" },
  "/logs":      { title: "Log Explorer",       crumb: "INVESTIGATION" },
  "/rules":     { title: "Correlation Rules",  crumb: "DETECTION" },
  "/assets":    { title: "Asset Inventory",    crumb: "ASSETS" },
  "/reports":   { title: "Reports",            crumb: "REPORTS" },
  "/settings":  { title: "Settings",           crumb: "SETTINGS" },
};

export function Header({ onOpenSearch, onOpenNotifications }: { onOpenSearch: () => void; onOpenNotifications: () => void; }) {
  const loc = useLocation();
  const { notifications } = useSiem();
  const [now, setNow] = useState(new Date());
  const [range, setRange] = useState("24h");

  useEffect(() => {
    const i = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(i);
  }, []);

  const meta = TITLES[loc.pathname] || { title: "SECURE WATCH", crumb: "Home" };
  const unread = notifications.filter(n => !n.read).length;

  return (
    <header className="sticky top-0 z-30 h-14 bg-[#0d1117] border-b border-[#30363d] flex items-center px-5 gap-5 font-sans">
      <div className="min-w-[260px] flex items-center gap-3">
        <h1 className="text-[13px] font-bold text-white">{meta.title}</h1>
        <span className="text-[#30363d]">/</span>
        <span className="text-[10px] text-[#8b949e] font-mono tracking-widest uppercase">{meta.crumb}</span>
      </div>

      <button
        onClick={onOpenSearch}
        className="flex-1 max-w-[640px] mx-auto flex items-center gap-3 h-8 px-3 bg-[#161b22] border border-[#30363d] hover:border-[#8b949e] rounded-md text-left transition group"
      >
        <Search className="w-4 h-4 text-[#8b949e] group-hover:text-white" />
        <span className="text-[11px] text-[#8b949e] flex-1 font-mono">Search logs, IPs, hostnames, rules...</span>
        <kbd className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-[#30363d] text-[#8b949e] bg-[#0d1117]">Ctrl K</kbd>
      </button>

      <div className="flex items-center gap-4">
        <div className="flex items-center bg-[#161b22] border border-[#30363d] rounded-md px-3 h-8 cursor-pointer hover:border-[#8b949e] transition text-[11px] font-mono text-[#8b949e]">
          Last 24h <ChevronRight className="w-3 h-3 ml-2 rotate-90" />
        </div>

        <div className="font-mono text-[11px] text-[#8b949e] hidden md:flex items-center gap-2 bg-[#161b22] border border-[#30363d] h-8 px-3 rounded-md">
          <Activity className="w-3 h-3 text-[#00aaff]" />
          <span className="text-white">{now.toLocaleTimeString("en-IN", { hour12: false, timeZone: "Asia/Kolkata" })}</span>
          <span className="text-[10px]">IST</span>
        </div>

        <button
          onClick={onOpenNotifications}
          className="relative w-8 h-8 rounded-full border border-[#30363d] hover:border-[#8b949e] bg-[#161b22] flex items-center justify-center transition"
        >
          <Bell className="w-3.5 h-3.5 text-[#8b949e]" />
          {unread > 0 && (
            <span className="absolute -top-1 -right-1 min-w-[16px] h-[16px] px-1 rounded-full bg-[#ff3366] text-[9px] font-mono font-bold text-white flex items-center justify-center border border-[#0d1117]">
              {unread}
            </span>
          )}
        </button>

        <div className="flex items-center gap-1.5 px-2.5 h-7 rounded-full border border-[#00ff88]/30 bg-[#00ff88]/10">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
          <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-[#00ff88]">LIVE</span>
        </div>
      </div>
    </header>
  );
}
