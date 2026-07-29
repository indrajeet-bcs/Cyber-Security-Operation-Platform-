export interface AlertRecord {
  id: number;
  alert_id: string;
  alert_title: string;
  alert_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  priority: string;
  confidence: number | null;
  risk_score: number | null;
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'closed' | string;
  occurrence_count: number;
  source: string | null;
  source_ip: string | null;
  host: string | null;
  username: string | null;
  event_fingerprint: string | null;
  alert_fingerprint: string;
  rule_matches: string | null;
  correlation_matches: string | null;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
}

export interface AlertsResponse {
  total: number;
  alerts: AlertRecord[];
}
