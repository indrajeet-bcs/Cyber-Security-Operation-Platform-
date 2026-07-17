import type { Severity } from './severity';

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
  alert?: Alert | null;
}

export interface AssignIncidentPayload {
  incidentId: string;
  assigned_to: string;
  assigned_role: string;
}

export interface AddNotePayload {
  incidentId: string;
  note: string;
}
