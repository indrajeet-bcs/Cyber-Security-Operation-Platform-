export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'acknowledged' | 'investigating' | 'closed';

export interface Alert {
  id: number;
  alert_id: string;
  alert_title: string;
  alert_type: string;
  severity: Severity;
  priority: string;
  confidence: number | null;
  risk_score: number | null;
  status: string;
  occurrence_count: number;
  source: string | null;
  source_ip: string | null;
  host: string | null;
  username: string | null;
  rule_matches: any[] | null;
  correlation_matches: any[] | null;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
}

export interface Incident {
  id: number;
  incident_id: string;
  alert_id: number | null;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  notes: string | null;
  assigned_to: string | null;
  assigned_role: string | null;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  investigating_at: string | null;
  closed_at: string | null;
  alert?: Alert | null; // For joined details if fetched
}

export interface DashboardSummary {
  total_incidents: number;
  total_logs: number;
  open_incidents: number;
  acknowledged_incidents: number;
  investigating_incidents: number;
  closed_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  medium_incidents: number;
  low_incidents: number;
}
