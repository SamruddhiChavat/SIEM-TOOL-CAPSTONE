import { NavLink, useLocation } from "react-router-dom";
import {
  Shield, LayoutDashboard, Globe2, AlertTriangle, FileSearch,
  GitBranch, Server, FileBarChart, Settings, LogOut, Brain
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/",           label: "Dashboard",         icon: LayoutDashboard },
  { to: "/threat-map", label: "Threat Map",         icon: Globe2 },
  { to: "/incidents",  label: "Incidents",          icon: AlertTriangle },
  { to: "/logs",       label: "Log Explorer",       icon: FileSearch },
  { to: "/rules",      label: "Correlation Rules",  icon: GitBranch },
  { to: "/behavioral", label: "Behavioral UEBA",     icon: Brain },
  { to: "/assets",     label: "Assets",             icon: Server },
  { to: "/reports",    label: "Reports",            icon: FileBarChart },
  { to: "/settings",   label: "Settings",           icon: Settings },
];

export function Sidebar() {
  const loc = useLocation();
  return (
    <aside
      className="group/sidebar fixed left-0 top-0 z-40 h-screen w-[60px] hover:w-[220px] bg-sidebar border-r border-sidebar-border transition-[width] duration-200 flex flex-col overflow-hidden"
    >
      {/* Logo */}
      <div className="h-14 flex items-center px-[18px] border-b border-sidebar-border">
        <Shield className="w-6 h-6 text-primary shrink-0 glow-text-primary" strokeWidth={2.2} />
        <div className="ml-3 opacity-0 group-hover/sidebar:opacity-100 transition-opacity whitespace-nowrap">
          <div className="text-[13px] font-semibold tracking-[0.18em] text-primary glow-text-primary">SECURE WATCH</div>
          <div className="text-[10px] font-mono text-muted-foreground">v2.1</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-3 space-y-1 px-2">
        {NAV.map(item => {
          const active = loc.pathname === item.to || (item.to !== "/" && loc.pathname.startsWith(item.to));
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={cn(
                "relative flex items-center h-10 px-2.5 rounded-md text-sm transition-all",
                "text-muted-foreground hover:text-foreground hover:bg-sidebar-accent",
                active && "text-primary bg-sidebar-accent"
              )}
            >
              {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r bg-primary glow-text-primary" />}
              <Icon className={cn("w-[18px] h-[18px] shrink-0", active && "drop-shadow-[0_0_6px_hsl(var(--primary))]")} />
              <span className="ml-3 opacity-0 group-hover/sidebar:opacity-100 transition-opacity whitespace-nowrap">
                {item.label}
              </span>
            </NavLink>
          );
        })}
      </nav>

      {/* User */}
      <div className="border-t border-sidebar-border p-2">
        <div className="flex items-center h-12 px-1.5 rounded-md hover:bg-sidebar-accent transition">
          <div className="w-8 h-8 shrink-0 rounded-full bg-primary/15 border border-primary/40 flex items-center justify-center text-primary text-xs font-semibold">
            JP
          </div>
          <div className="ml-3 flex-1 min-w-0 opacity-0 group-hover/sidebar:opacity-100 transition-opacity whitespace-nowrap">
            <div className="text-xs font-medium truncate">Jesal Pavaskar</div>
            <div className="text-[10px] text-primary font-mono">SOC Analyst L2</div>
          </div>
          <LogOut className="w-4 h-4 text-muted-foreground hover:text-danger opacity-0 group-hover/sidebar:opacity-100 transition" />
        </div>
      </div>
    </aside>
  );
}
