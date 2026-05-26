import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SiemProvider } from "@/lib/siemContext";
import { AppLayout } from "@/components/siem/AppLayout";
import Dashboard from "./pages/Dashboard";
import ThreatMap from "./pages/ThreatMap";
import Incidents from "./pages/Incidents";
import LogExplorer from "./pages/LogExplorer";
import CorrelationRules from "./pages/CorrelationRules";
import BehavioralAnalytics from "./pages/BehavioralAnalytics";
import Assets from "./pages/Assets";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Sonner
        theme="dark"
        position="bottom-right"
        toastOptions={{
          style: {
            background: "hsl(var(--card))",
            border: "1px solid hsl(var(--border))",
            color: "hsl(var(--foreground))",
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
          },
        }}
      />
      <BrowserRouter>
        <SiemProvider>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/threat-map" element={<ThreatMap />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/logs" element={<LogExplorer />} />
              <Route path="/rules" element={<CorrelationRules />} />
              <Route path="/behavioral" element={<BehavioralAnalytics />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<Settings />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </SiemProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
