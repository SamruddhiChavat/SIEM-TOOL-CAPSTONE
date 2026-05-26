import { ReactNode, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import { StatusBar } from "./StatusBar";
import { CommandPalette } from "./CommandPalette";
import { NotificationPanel } from "./NotificationPanel";

export function AppLayout({ children }: { children?: ReactNode }) {
  const [search, setSearch] = useState(false);
  const [notif, setNotif] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearch(s => !s);
      } else if (e.key === "Escape") {
        setSearch(false);
        setNotif(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      <Sidebar />
      <div className="pl-[60px] flex-1 flex flex-col min-w-0">
        <Header onOpenSearch={() => setSearch(true)} onOpenNotifications={() => setNotif(true)} />
        <main className="flex-1 overflow-x-hidden page-enter" key={location.pathname}>
          {children ?? <Outlet />}
        </main>
        <StatusBar />
      </div>
      <CommandPalette open={search} onClose={() => setSearch(false)} />
      <NotificationPanel open={notif} onClose={() => setNotif(false)} />
    </div>
  );
}
