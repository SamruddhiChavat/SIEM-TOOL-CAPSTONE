// Central API Service — connects sentinel-watch frontend to realsiem backend
// All requests go to /api/* which Vite proxies to http://localhost:8000

const API_BASE = "/api";

// ──────────────────────────────────────────────
// Generic fetch helper with error handling
// ──────────────────────────────────────────────
async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `API Error ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ──────────────────────────────────────────────
// Types matching backend response shapes
// ──────────────────────────────────────────────

export interface DashboardSummary {
  timestamp: string;
  total_events_24h: number;
  active_alerts: number;
  critical_count: number;
  high_count: number;
  assets_at_risk: number;
  security_posture: {
    score: number;
    status: string;
    color: string;
    details: {
      critical_alerts: number;
      high_alerts: number;
      assets_at_risk: number;
      blind_spots: number;
    };
  };
  alert_velocity: {
    status: string;
    severity: string;
    message: string;
    current_rate: number;
    average_rate: number;
    ratio: number;
  };
  mttd: {
    average_mttd_minutes: number;
    p95_mttd_minutes: number;
    status: string;
    color: string;
    sample_size: number;
  };
  mttr: {
    average_mttr_hours: number;
    alerts_closed: number;
    sample_size: number;
  };
  mitre_coverage: Record<string, { rule_count: number; color: string; label: string }>;
  alert_noise_ratio: {
    false_positive_ratio: number;
    total_closed_alerts: number;
    false_positives_count: number;
    status: string;
    color: string;
    recommendation: string;
  };
  top_threats: Array<{
    alert_id: string;
    rule_name: string;
    severity: string;
    source_ip: string;
    entity: string;
    mitre_tactic: string;
    timestamp: string;
    urgency_score: number;
    status: string;
  }>;
  events_per_hour: Array<{ hour: string; count: number }>;
}

export interface IncidentItem {
  id: string;
  title: string;
  severity: string;
  status: string;
  assignee: string;
  affected: string;
  created: string;
  source_ip?: string;
  priority: number;
  is_fp?: boolean;
  fp_msg?: string;
  mitre?: string;
  // Group fields
  is_group?: boolean;
  type?: string;
  alerts?: IncidentItem[];
}

export interface IncidentDetail {
  alert: Record<string, unknown>;
  workflow: {
    step_a_timeline: Array<Record<string, unknown>>;
    step_b_source: Record<string, unknown>;
    step_c_asset: {
      name: string;
      criticality: string;
      risk_score: number;
      owner: string;
      open_incidents?: number;
    };
    step_d_related: {
      subnet: Array<{ id: string; title: string }>;
      asset_24h: unknown[];
      technique_1h: unknown[];
    };
    step_e_response: string[];
  };
}

export interface ThreatMapData {
  country_risk: Record<string, number>;
  events: Array<{
    id: string;
    timestamp: string;
    source_ip: string;
    destination_ip: string;
    tactic: string;
    severity: string;
    rule_name: string;
    geo: { lat: number; lon: number };
  }>;
  reputations: Record<string, { malicious: boolean; vt_hits?: number; confidence?: number }>;
}

export interface LogSearchResult {
  total: number;
  logs: Array<Record<string, unknown>>;
  stats: Record<string, Array<{ value: string; count: number }>>;
}

export interface LogSearchRequest {
  query_string: string;
  time_range?: string;
  from_time?: string;
  to_time?: string;
  size?: number;
}

// ──────────────────────────────────────────────
// API functions
// ──────────────────────────────────────────────

/** GET /api/v1/dashboard/summary */
export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  return apiFetch<DashboardSummary>("/v1/dashboard/summary");
}

/** GET /api/v1/incidents/triage */
export async function fetchIncidentTriage(): Promise<IncidentItem[]> {
  return apiFetch<IncidentItem[]>("/v1/incidents/triage");
}

/** GET /api/v1/incidents/:id/detail */
export async function fetchIncidentDetail(id: string): Promise<IncidentDetail> {
  return apiFetch<IncidentDetail>(`/v1/incidents/${id}/detail`);
}

/** POST /api/v1/incidents/:id/close */
export async function closeIncident(
  id: string,
  payload: {
    verdict: string;
    attack_confirmed: boolean;
    damage_done: boolean;
    root_cause: string;
    analyst: string;
    reason: string;
  }
): Promise<{ status: string; message: string }> {
  return apiFetch(`/v1/incidents/${id}/close`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** GET /api/v1/threat-map/data */
export async function fetchThreatMapData(): Promise<ThreatMapData> {
  return apiFetch<ThreatMapData>("/v1/threat-map/data");
}

/** POST /api/v1/logs/search */
export async function searchLogs(req: LogSearchRequest): Promise<LogSearchResult> {
  return apiFetch<LogSearchResult>("/v1/logs/search", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

/** GET /api/assets — agent-discovered assets */
export async function fetchAssets(): Promise<unknown[]> {
  return apiFetch<unknown[]>("/assets");
}

/** GET /api/alerts — alerts from Wazuh/ES */
export async function fetchAlerts(): Promise<unknown[]> {
  return apiFetch<unknown[]>("/alerts");
}

/** GET /api/rules — correlation rules from DB */
export async function fetchRules(): Promise<unknown[]> {
  return apiFetch<unknown[]>("/rules");
}

/** GET /health */
export async function checkHealth(): Promise<{ status: string; service: string }> {
  return fetch("/health").then((r) => r.json());
}
