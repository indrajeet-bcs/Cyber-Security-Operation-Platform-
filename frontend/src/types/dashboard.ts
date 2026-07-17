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
