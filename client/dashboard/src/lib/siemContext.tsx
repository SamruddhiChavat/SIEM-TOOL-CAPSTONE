import { createContext, useContext, useEffect, useState, ReactNode, useCallback, useRef } from "react";
import { toast } from "sonner";
import {
  AlertEntry, LogEntry, makeAlert, makeLog, ASSETS,
  seedEventTimeline, RULES_LIB,
} from "@/lib/siemData";
import { DashboardSummary, ThreatMapData } from "@/lib/apiService";

// ─────────────────────────────────────────────
// MITRE ATT&CK mapping (matches relay server)
// ─────────────────────────────────────────────
const MITRE_MAP: Record<string, { tactic: string; technique: string; name: string }> = {
  "BRUTE_FORCE":          { tactic: "Credential Access",  technique: "T1110.001", name: "Brute Force" },
  "BRUTE-FORCE":          { tactic: "Credential Access",  technique: "T1110.001", name: "Brute Force" },
  "DDOS":                 { tactic: "Impact",             technique: "T1498.001", name: "Network DoS" },
  "DOS":                  { tactic: "Impact",             technique: "T1499",     name: "Endpoint DoS" },
  "SQL_INJECTION":        { tactic: "Initial Access",     technique: "T1190",     name: "SQL Injection" },
  "SQL-INJECTION":        { tactic: "Initial Access",     technique: "T1190",     name: "SQL Injection" },
  "PORT_SCAN":            { tactic: "Discovery",          technique: "T1046",     name: "Network Service Scan" },
  "PORT-SCAN":            { tactic: "Discovery",          technique: "T1046",     name: "Network Service Scan" },
  "PHISHING":             { tactic: "Initial Access",     technique: "T1566.001", name: "Spear Phishing" },
  "PRIVILEGE_ESCALATION": { tactic: "Privilege Escalation", technique: "T1548",  name: "Abuse Elevation Control" },
  "PRIVILEGE-ESCALATION": { tactic: "Privilege Escalation", technique: "T1548",  name: "Abuse Elevation Control" },
  "RANSOMWARE":           { tactic: "Impact",             technique: "T1486",     name: "Data Encrypted for Impact" },
  "FILE_EXFILTRATION":    { tactic: "Exfiltration",       technique: "T1041",     name: "Data Exfiltration" },
  "LATERAL_MOVEMENT":     { tactic: "Lateral Movement",   technique: "T1550.002", name: "Pass-the-Hash" },
  "DNS_C2":               { tactic: "Command & Control",  technique: "T1071.004", name: "DNS C2 Tunneling" },
  "INSIDER_THREAT":       { tactic: "Exfiltration",       technique: "T1052",     name: "Exfiltration Over Physical" },
  "INSIDER-THREAT":       { tactic: "Exfiltration",       technique: "T1052",     name: "Exfiltration Over Physical" },
  "MITM":                 { tactic: "Collection",         technique: "T1557",     name: "Adversary-in-the-Middle" },
};

function getMitre(eventType: string) {
  const key = (eventType || "").toUpperCase().replace(/^ATTACK_/, "").replace(/ /g, "_");
  return MITRE_MAP[key] || null;
}

// ─────────────────────────────────────────────
// Asset status tracking
// ─────────────────────────────────────────────
export type AssetStatus = "online" | "offline" | "compromised" | "quarantined";

export type LiveAsset = typeof ASSETS[number] & {
  status: AssetStatus;
  alerts: number;
  lastAttack?: string;
  lastAttackIp?: string;
  lastAttackTime?: number;
  mitre?: string;
  blockedIps: string[];
};

// ─────────────────────────────────────────────
// Active Incident type (derived from sandbox attack)
// ─────────────────────────────────────────────
export type ActiveIncident = {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "New" | "Investigating" | "Contained" | "Resolved";
  sourceIp: string;
  destIp: string;
  destHost: string;
  mitre: string;
  mitreTechnique: string;
  eventType: string;
  created: number;
  rawLog: string;
  isolatedAt?: number;
  snapshotAt?: number;
  accountDisabledAt?: number;
  blockedIps: string[];
  notes: string;
  rootCause: string;
};

type LiveState = {
  logs: LogEntry[];
  alerts: AlertEntry[];
  incidents: ActiveIncident[];
  timeline: ReturnType<typeof seedEventTimeline>;
  kpis: {
    totalEvents: number;
    blocked: number;
    eps: number;
    critical: number;
    high: number;
    medium: number;
    openIncidents: number;
    mttd: number;
  };
  notifications: { id: string; type: "info" | "warning" | "critical" | "success"; message: string; ts: number; read: boolean }[];
  assets: LiveAsset[];
  suspiciousIps: { ip: string; country: string; flag: string; events: number; threat: number; lastSeen: number; mitre: string; isBlocked?: boolean }[];
  mitreCoverage: Record<string, number>; // tactic → count triggered
  
  dashboardSummary: DashboardSummary | null;
  threatMapData: ThreatMapData | null;
  apiLoading: boolean;
  apiError: string | null;
  
  // Actions
  isolateAsset: (hostname: string, incidentId: string) => void;
  blockIp: (ip: string, incidentId: string) => void;
  captureSnapshot: (incidentId: string) => void;
  disableAccount: (incidentId: string) => void;
  remediateAsset: (hostname: string) => void;
  closeIncident: (id: string, rootCause: string) => void;
  updateIncidentStatus: (id: string, status: ActiveIncident["status"]) => void;
  pushNotification: (n: { type: "info" | "warning" | "critical" | "success"; message: string }) => void;
  markAllRead: () => void;
};

const SiemCtx = createContext<LiveState | null>(null);

// ─────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────

export function SiemProvider({ children }: { children: ReactNode }) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [incidents, setIncidents] = useState<ActiveIncident[]>(() => {
    try { const local = localStorage.getItem("siem_incidents"); return local ? JSON.parse(local) : []; } catch { return []; }
  });
  const [timeline] = useState(seedEventTimeline());

  // Live assets — ALWAYS start clean from canonical ASSETS definition.
  // We deliberately ignore stale localStorage so old fake data never persists.
  const [assets, setAssets] = useState<LiveAsset[]>(
    () => ASSETS.map(a => ({ ...a, status: "online" as AssetStatus, alerts: 0, blockedIps: [] }))
  );

  // Derived: suspicious IPs from live sandbox logs
  const [suspiciousIps, setSuspiciousIps] = useState<LiveState["suspiciousIps"]>(() => {
    try { const local = localStorage.getItem("siem_ips"); return local ? JSON.parse(local) : []; } catch { return []; }
  });

  // MITRE tactic hit counter (live from sandbox)
  const [mitreCoverage, setMitreCoverage] = useState<Record<string, number>>(() => {
    try { const local = localStorage.getItem("siem_mitre"); return local ? JSON.parse(local) : {}; } catch { return {}; }
  });

  // Persist state to localStorage (but NOT assets — they always boot from canonical ASSETS)
  useEffect(() => { localStorage.setItem("siem_incidents", JSON.stringify(incidents)); }, [incidents]);
  useEffect(() => { localStorage.setItem("siem_ips", JSON.stringify(suspiciousIps)); }, [suspiciousIps]);
  useEffect(() => { localStorage.setItem("siem_mitre", JSON.stringify(mitreCoverage)); }, [mitreCoverage]);
  // Wipe stale cached assets on mount so IPs from old siemData never block live sync
  useEffect(() => { localStorage.removeItem("siem_assets"); localStorage.removeItem("siem_ip_counts"); }, []);

  const [kpis, setKpis] = useState({
    totalEvents: 0, blocked: 0, eps: 0, critical: 0, high: 0, medium: 0, openIncidents: 0, mttd: 0,
  });
  const [notifications, setNotifications] = useState<LiveState["notifications"]>([]);
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [threatMapData, setThreatMapData] = useState<ThreatMapData | null>(null);
  const [apiLoading, setApiLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const cursorRef = useRef(0);
  const firstConnectRef = useRef(true);
  const ipCountRef = useRef<Record<string, { count: number; last: number; mitre: string; isBlocked?: boolean }>>({});
  
  // Load IP counts on mount
  useEffect(() => {
    try { const stored = localStorage.getItem("siem_ip_counts"); if (stored) ipCountRef.current = JSON.parse(stored); } catch (e) { /* ignore */ }
  }, []);

  // ─── Push notification ───────────────────────────────────────────────────────
  const pushNotification = useCallback((n: { type: "info" | "warning" | "critical" | "success"; message: string }) => {
    setNotifications(prev => [{ id: `n${Date.now()}`, ts: Date.now(), read: false, ...n }, ...prev].slice(0, 50));
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  }, []);

  // ─── Response Actions ────────────────────────────────────────────────────────

  const isolateAsset = useCallback((hostnameOrIp: string, incidentId: string) => {
    setAssets(prev => prev.map(a =>
      (a.hostname === hostnameOrIp || a.ip === hostnameOrIp)
        ? { ...a, status: "quarantined" as AssetStatus } : a
    ));
    setIncidents(prev => prev.map(i =>
      i.id === incidentId ? { ...i, status: "Contained" as const, isolatedAt: Date.now() } : i
    ));
    fetch("/sandbox/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventType: "RESPONSE_ISOLATE",
        severity: "info",
        srcIp: "10.0.0.1",
        srcHostname: "SIEM-Console",
        dstIp: hostnameOrIp,
        message: `[RESPONSE] Host ${hostnameOrIp} isolated by analyst`,
      }),
    }).catch(() => {});
    toast.success(`Host ${hostnameOrIp} isolated`, { description: "Network access cut off via EDR" });
    pushNotification({ type: "success", message: `${hostnameOrIp} isolated successfully` });
  }, [pushNotification]);

  const remediateAsset = useCallback((hostnameOrIp: string) => {
    if (!hostnameOrIp) return;
    const norm = hostnameOrIp.toLowerCase().replace(/[^a-z0-9]/g, "");

    // Restore asset status to online — fuzzy match on IP or hostname
    setAssets(prev => prev.map(a => {
      const ipMatch   = a.ip === hostnameOrIp;
      const normAsset = a.hostname.toLowerCase().replace(/[^a-z0-9]/g, "");
      const fuzzy     = norm.length >= 4 && (normAsset === norm || normAsset.startsWith(norm) || norm.startsWith(normAsset));
      if (!ipMatch && !fuzzy) return a;
      return { ...a, status: "online" as AssetStatus, alerts: 0, lastAttack: undefined, lastAttackIp: undefined, lastAttackTime: undefined };
    }));

    // Close all matching open incidents
    setIncidents(prev => prev.map(i => {
      const nd = (i.destHost || "").replace(/[^a-z0-9]/g, "");
      const hit = i.destIp === hostnameOrIp || i.destHost === hostnameOrIp ||
        (norm.length >= 4 && (nd === norm || nd.startsWith(norm) || norm.startsWith(nd)));
      return hit && i.status !== "Resolved" ? { ...i, status: "Resolved" as const } : i;
    }));

    // Notify relay so sandbox topology node clears too
    fetch("/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventType: "RESPONSE_REMEDIATE",
        severity: "info",
        srcIp: "10.6.0.10",
        srcHostname: "SecureWatch SIEM",
        dstIp: hostnameOrIp,
        message: `[RESPONSE] Host ${hostnameOrIp} remediated — restored to Online after playbook completion`,
      }),
    }).catch(() => {});

    toast.success(`✅ ${hostnameOrIp} restored to Online`, {
      description: "All playbook steps completed. Asset cleared and incidents resolved.",
      duration: 5000,
    });
    pushNotification({ type: "success", message: `${hostnameOrIp} remediated — status: Online` });
  }, [pushNotification]);


  const blockIp = useCallback((ip: string, incidentId: string) => {
    if (!ip) return;
    setAssets(prev => prev.map(a => ({ ...a, blockedIps: a.blockedIps.includes(ip) ? a.blockedIps : [...a.blockedIps, ip] })));
    setIncidents(prev => prev.map(i =>
      i.id === incidentId ? { ...i, blockedIps: i.blockedIps.includes(ip) ? i.blockedIps : [...i.blockedIps, ip] } : i
    ));
    // Update suspicious IP threat level to max and mark as blocked
    setSuspiciousIps(prev => prev.map(s => s.ip === ip ? { ...s, threat: 100, isBlocked: true } : s));
    fetch("/sandbox/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventType: "RESPONSE_BLOCK_IP",
        severity: "info",
        srcIp: "10.0.0.1",
        srcHostname: "SIEM-Console",
        dstIp: ip,
        message: `[RESPONSE] IP ${ip} blocked at perimeter firewall`,
      }),
    }).catch(() => {});
    toast.success(`IP ${ip} blocked`, { description: "Firewall rule applied" });
    pushNotification({ type: "success", message: `IP ${ip} added to blocklist` });
  }, [pushNotification]);

  const captureSnapshot = useCallback((incidentId: string) => {
    setIncidents(prev => prev.map(i => i.id === incidentId ? { ...i, snapshotAt: Date.now() } : i));
    fetch("/sandbox/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventType: "RESPONSE_SNAPSHOT",
        severity: "info",
        srcIp: "10.0.0.1",
        srcHostname: "SIEM-Console",
        message: `[RESPONSE] Forensic snapshot (memory & disk) initiated`,
      }),
    }).catch(() => {});
    toast.success("Forensic collection started", { description: "Triggered EDR snapshot" });
    pushNotification({ type: "info", message: "Forensic snapshot initiated" });
  }, [pushNotification]);

  const disableAccount = useCallback((incidentId: string) => {
    setIncidents(prev => prev.map(i => i.id === incidentId ? { ...i, accountDisabledAt: Date.now(), status: "Investigating" } : i));
    fetch("/sandbox/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventType: "RESPONSE_DISABLE_ACCT",
        severity: "info",
        srcIp: "10.0.0.1",
        srcHostname: "SIEM-Console",
        message: `[RESPONSE] User account locked in Active Directory`,
      }),
    }).catch(() => {});
    toast.success("User account disabled", { description: "Locked via Active Directory" });
    pushNotification({ type: "info", message: "User account disabled" });
  }, [pushNotification]);

  const closeIncident = useCallback((id: string, rootCause: string) => {
    setIncidents(prev => {
      const inc = prev.find(i => i.id === id);
      if (inc) {
        const hostname = inc.destHost || inc.destIp;
        if (hostname) {
          // Sync with Sandbox
          fetch("/sandbox/api/logs", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              eventType: "RESPONSE_REMEDIATE",
              severity: "info",
              srcIp: "10.0.0.1",
              srcHostname: "SIEM-Console",
              dstIp: hostname,
              message: `[RESPONSE] Host ${hostname} auto-remediated upon incident closure`,
            }),
          }).catch(() => {});
          
          // Update local assets
          setAssets(aPrev => aPrev.map(a =>
            a.hostname === hostname || a.ip === hostname ? { ...a, status: "online" as AssetStatus, alerts: 0, lastAttack: undefined, lastAttackIp: undefined } : a
          ));
        }
      }
      return prev.map(i => i.id === id ? { ...i, status: "Resolved" as const, rootCause } : i);
    });
    setKpis(prev => ({ ...prev, openIncidents: Math.max(0, prev.openIncidents - 1) }));
    toast.success("Incident closed & asset remediated", { description: rootCause });
  }, []);

  const updateIncidentStatus = useCallback((id: string, status: ActiveIncident["status"]) => {
    setIncidents(prev => prev.map(i => i.id === id ? { ...i, status } : i));
  }, []);

  // ─── Process incoming sandbox log ────────────────────────────────────────────
  const processLog = useCallback((data: Record<string, unknown>) => {
    const newLog: LogEntry = {
      id: String(data.id),
      ts: new Date(data.timestamp as string).getTime(),
      severity: (data.severity || "info") as ActiveIncident["severity"],
      host: (data.sourceHost as string) || "sandbox",
      eventId: (data.eventType as string) || "UNKNOWN",
      message: (data.message as string) || "",
      srcIp: (data.sourceIp as string) || "",
      dstIp: (data.destIp as string) || "",
      format: "json",
      raw: JSON.stringify(data, null, 2),
    };

    setLogs(prev => [newLog, ...prev].slice(0, 500));

    // Process attacks: critical + high create incidents; medium bumps alerts only
    const sev = String(data.severity || "info").toLowerCase();
    const isAttack = sev === "critical" || sev === "high" || sev === "medium";

    if (isAttack) {
      const eventType = String(data.eventType || "");
      const mitre = getMitre(eventType);

      // 1. Update suspicious IPs table
      const srcIp = String(data.sourceIp || "");
      if (srcIp) {
        const existing = ipCountRef.current[srcIp] || { count: 0, last: 0, mitre: "" };
        existing.count += 1;
        existing.last = Date.now();
        existing.mitre = mitre?.tactic || existing.mitre;
        ipCountRef.current[srcIp] = existing;

        setSuspiciousIps(() => {
          const entries = Object.entries(ipCountRef.current)
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, 10)
            .map(([ip, d]) => ({
              ip,
              country: ip.startsWith("185.") || ip.startsWith("91.") ? "Russia" : ip.startsWith("203.") ? "China" : ip.startsWith("198.") ? "United States" : "Unknown",
              flag: ip.startsWith("185.") || ip.startsWith("91.") ? "🇷🇺" : ip.startsWith("203.") ? "🇨🇳" : ip.startsWith("198.") ? "🇺🇸" : "🌐",
              events: d.count,
              threat: Math.min(100, Math.round((d.count / 20) * 100)),
              lastSeen: d.last,
              mitre: d.mitre,
              isBlocked: d.isBlocked,
            }));
          return entries;
        });
        localStorage.setItem("siem_ip_counts", JSON.stringify(ipCountRef.current));
      }

      // 2. Update MITRE coverage
      if (mitre?.tactic) {
        setMitreCoverage(prev => ({ ...prev, [mitre.tactic]: (prev[mitre.tactic] || 0) + 1 }));
      }

      // 3. Resolve source and destination from relay log fields
      // Relay sends: sourceIp / sourceHost / destIp / destHostname
      const destHost = String(data.destHostname || data.dstHostname || data.destHost || "").toLowerCase();
      const destIp   = String(data.destIp   || data.dstIp   || "");
      const srcHost  = String(data.sourceHost || data.srcHostname || data.sourceHostname || "").toLowerCase();
      const srcIpStr = String(data.sourceIp  || data.srcIp   || "");

      // 4. Update asset status — IP match is authoritative; hostname match is fuzzy fallback
      setAssets(prev => prev.map(a => {
        // IP-exact match against destination (victim)
        const ipMatch = destIp && destIp === a.ip;
        // Hostname fuzzy: only if IP didn't match and names are reasonably long
        const normDest  = destHost.replace(/[^a-z0-9]/g, "");
        const normAsset = a.hostname.toLowerCase().replace(/[^a-z0-9]/g, "");
        const hostMatch = !ipMatch && normDest.length >= 4 &&
          (normAsset === normDest ||
           normAsset.startsWith(normDest) ||
           normDest.startsWith(normAsset));

        if (!ipMatch && !hostMatch) return a;

        // Any attack severity (critical/high/medium) marks asset as compromised
        // unless already quarantined by analyst
        const newStatus: AssetStatus =
          a.status !== "quarantined" ? "compromised" : a.status;
        return {
          ...a,
          status: newStatus,
          alerts: a.alerts + 1,
          lastAttack: eventType,
          lastAttackIp: srcIpStr,
          lastAttackTime: Date.now(),
          mitre: mitre?.technique,
        };
      }));

      // Create incidents and alerts for ALL attack severities (critical, high, medium)

      // 4. Create or update incident
      const incidentTitle = mitre ? `${mitre.name} Detected` : `${eventType} Attack Detected`;
      const incidentId = `INC-${eventType?.replace(/\W/g, "_")}-${srcIp?.replace(/\./g, "")}`;

      setIncidents(prev => {
        const existingIdx = prev.findIndex(i => i.id === incidentId);
        if (existingIdx !== -1) {
          const existing = prev[existingIdx];
          if (existing.status !== "Resolved") {
            // Update existing incident (escalate if needed) and bump to top
            const updatedInc = {
              ...existing,
              severity: sev === "critical" ? "critical" : existing.severity,
              rawLog: JSON.stringify(data, null, 2),
            };
            const others = prev.filter((_, idx) => idx !== existingIdx);
            return [updatedInc, ...others].slice(0, 50);
          } else {
            // Re-open resolved incident and move it to the top
            const reopened: ActiveIncident = {
              ...existing,
              status: "New",
              severity: sev === "critical" ? "critical" : existing.severity,
              rawLog: JSON.stringify(data, null, 2),
              created: Date.now(),
            };
            const others = prev.filter((_, idx) => idx !== existingIdx);
            if (sev === "critical") {
              toast.error(`🚨 CRITICAL: ${incidentTitle}`, { description: `From ${srcIp} → ${destIp}` });
              pushNotification({ type: "critical", message: `${incidentTitle} from ${srcIp}` });
            }
            return [reopened, ...others].slice(0, 50);
          }
        }
        
        // Create new incident
        const newInc: ActiveIncident = {
          id: incidentId,
          title: incidentTitle,
          severity: sev as ActiveIncident["severity"],
          status: "New",
          sourceIp: srcIpStr,
          destIp: destIp,
          destHost: destHost,
          mitre: mitre?.tactic || "Unknown",
          mitreTechnique: mitre?.technique || "Unknown",
          eventType: eventType || "Unknown",
          created: Date.now(),
          rawLog: JSON.stringify(data, null, 2),
          blockedIps: [],
          notes: "",
          rootCause: "",
        };
        if (sev === "critical") {
          toast.error(`🚨 CRITICAL: ${incidentTitle}`, { description: `From ${srcIpStr} → ${destIp}` });
          pushNotification({ type: "critical", message: `${incidentTitle} from ${srcIpStr}` });
        } else if (sev === "high") {
          toast.warning(`⚠️ HIGH: ${incidentTitle}`, { description: `From ${srcIpStr} → ${destIp || destHost}` });
          pushNotification({ type: "warning", message: `${incidentTitle} from ${srcIpStr}` });
        } else if (sev === "medium") {
          toast.info(`🔍 MEDIUM: ${incidentTitle}`, { description: `From ${srcIpStr} → ${destIp || destHost}` });
          pushNotification({ type: "info", message: `${incidentTitle} from ${srcIpStr}` });
        }
        // Increment openIncidents KPI when new incident is created
        setKpis(prev => ({ ...prev, openIncidents: prev.openIncidents + 1 }));
        return [newInc, ...prev].slice(0, 50);
      });

      // 5. Create alert
      const newAlert: AlertEntry = {
        id: `ALT-${String(data.id)}`,
        ts: new Date(data.timestamp as string).getTime() || Date.now(),
        title: incidentTitle,
        severity: sev as ActiveIncident["severity"],
        src: srcIpStr,
        dst: destIp || destHost,
        status: "New",
        rule: mitre ? `${mitre.technique} · ${mitre.tactic}` : (data.category as string) || "Sandbox Rule",
        rawLog: JSON.stringify(data),
        recommendation: `Isolate ${destIp || destHost} and block ${srcIpStr}`,
      };
      setAlerts(prev => [newAlert, ...prev].slice(0, 200));

      // 6. Update KPIs — read fresh incidents inside functional updater
      setKpis(prev => ({
        ...prev,
        critical: sev === "critical" ? prev.critical + 1 : prev.critical,
        high: sev === "high" ? prev.high + 1 : prev.high,
        medium: sev === "medium" ? prev.medium + 1 : prev.medium,
      }));
    }

    // Always increment total events; open incidents derived from incidents array length
    setKpis(prev => ({ ...prev, totalEvents: prev.totalEvents + 1 }));
  }, [pushNotification]);

  // ─── SSE Stream ─────────────────────────────────────────────────────────────
  useEffect(() => {
    let es: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      es = new EventSource(`/sandbox/api/logs/stream?since=${cursorRef.current}`);

      es.onopen = () => {
        setApiError(null);
        setApiLoading(false);
        if (firstConnectRef.current) {
          toast.success("Connected to Attacking Sandbox", { description: "Receiving live attack simulation logs." });
          firstConnectRef.current = false;
        }
      };

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.__clear) { setLogs([]); setAlerts([]); setIncidents([]); cursorRef.current = 0; return; }
          if (data.cursor) cursorRef.current = Math.max(cursorRef.current, data.cursor);
          processLog(data);
        } catch (e) { console.error("SSE parse error", e); }
      };

      es.onerror = () => {
        es?.close();
        setApiError("Sandbox disconnected");
        reconnectTimer = setTimeout(connect, 3000);
      };
    };

    connect();
    return () => { es?.close(); clearTimeout(reconnectTimer); };
  }, [processLog]);

  // ─── Poll Stats for KPIs / Dashboard ────────────────────────────────────────
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch("/sandbox/api/stats");
        if (!res.ok) return;
        const stats = await res.json();

        setKpis(prev => ({
          ...prev,
          totalEvents: stats.total,
          blocked: stats.blocked,
          eps: Math.round(stats.total / 60),
          mttd: 2.4,
        }));

        setDashboardSummary({
          timestamp: new Date().toISOString(),
          total_events_24h: stats.total,
          active_alerts: stats.attacks,
          critical_count: stats.critical,
          high_count: stats.high,
          assets_at_risk: Math.max(0, stats.critical > 0 ? Math.ceil(stats.critical / 3) : 0),
          security_posture: {
            score: Math.max(0, 100 - stats.critical * 3 - stats.high),
            status: stats.critical > 5 ? "Critical Risk" : stats.high > 10 ? "Elevated" : "Healthy",
            color: stats.critical > 5 ? "danger" : "success",
            details: { critical_alerts: stats.critical, high_alerts: stats.high, assets_at_risk: 0, blind_spots: 0 },
          },
          alert_velocity: { status: "normal", severity: "low", message: "Normal", current_rate: 0, average_rate: 0, ratio: 1 },
          mttd: { average_mttd_minutes: 2.4, p95_mttd_minutes: 5, status: "good", color: "success", sample_size: 10 },
          mttr: { average_mttr_hours: 1.2, alerts_closed: stats.blocked, sample_size: 10 },
          mitre_coverage: mitreCoverage,
          alert_noise_ratio: { false_positive_ratio: 0.1, total_closed_alerts: 0, false_positives_count: 0, status: "good", color: "success", recommendation: "" },
          top_threats: alerts.slice(0, 5).map(a => ({
            alert_id: a.id, rule_name: a.title, severity: a.severity, source_ip: a.src,
            entity: a.dst, mitre_tactic: a.rule, timestamp: new Date(a.ts).toISOString(), urgency_score: a.severity === "critical" ? 95 : 75, status: "new",
          })),
          events_per_hour: [],
        });

        // Build ThreatMapData from live logs
        const evs = logs.slice(0, 60).filter(l => l.severity !== "info").map(l => ({
          id: l.id,
          timestamp: new Date(l.ts).toISOString(),
          source_ip: l.srcIp,
          destination_ip: l.dstIp,
          tactic: l.eventId,
          severity: l.severity,
          rule_name: l.message,
          geo: deriveGeo(l.srcIp),
        }));
        
        // Aggregate country risk from suspicious IPs
        const risk: Record<string, number> = {};
        suspiciousIps.forEach(ip => {
          if (ip.country !== "Unknown") {
            risk[ip.country] = (risk[ip.country] || 0) + ip.events;
          }
        });
        
        setThreatMapData({ country_risk: risk, events: evs, reputations: {} });

      } catch (_) { /* empty */ }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 4000);
    return () => clearInterval(interval);
  }, [logs, alerts, mitreCoverage, suspiciousIps]);

  return (
    <SiemCtx.Provider value={{
      logs, alerts, incidents, timeline, kpis, notifications, assets,
      suspiciousIps, mitreCoverage,
      dashboardSummary, threatMapData, apiLoading, apiError,
      isolateAsset, blockIp, captureSnapshot, disableAccount, remediateAsset, closeIncident, updateIncidentStatus,
      pushNotification, markAllRead,
    }}>
      {children}
    </SiemCtx.Provider>
  );
}

// ─── Geo helper (derive rough coords from IP prefix) ─────────────────────────
function deriveGeo(ip: string): { lat: number; lon: number } {
  if (!ip) return { lat: 0, lon: 0 };
  const first = parseInt(ip.split(".")[0], 10);
  // Very rough geo by first octet ranges
  if (first >= 185 && first <= 195) return { lat: 55.7 + Math.random() * 5, lon: 37.6 + Math.random() * 10 }; // Russia
  if (first >= 200 && first <= 210) return { lat: 39.9 + Math.random() * 5, lon: 116.4 + Math.random() * 10 }; // China
  if (first >= 50 && first <= 70)   return { lat: 37.8 + Math.random() * 5, lon: -95 + Math.random() * 20 };   // USA
  if (first >= 80 && first <= 95)   return { lat: 48.8 + Math.random() * 5, lon: 2.3 + Math.random() * 15 };   // Europe
  return { lat: (Math.random() - 0.5) * 120, lon: (Math.random() - 0.5) * 300 };
}

// eslint-disable-next-line react-refresh/only-export-components
export function useSiem() {
  const c = useContext(SiemCtx);
  if (!c) throw new Error("useSiem outside provider");
  return c;
}
