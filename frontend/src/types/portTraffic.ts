export interface IPTrafficSummary {
  source_ip: string;
  classification: string;
  classification_evidence: string;
  first_seen: string;
  last_seen: string;
  activity_count: number;
  observed_duration_seconds: number;
  exact_lifetime_proven: boolean;
}

export interface TimelineBucket {
  timestamp: string;
  connection_count: number;
  active_ips: string[];
  observed_duration_seconds: number;
}

export interface MonitoringWindowSummary {
  start_time: string;
  end_time: string;
  duration_seconds: number;
}

export interface PortTrafficSummary {
  total_activity_count: number;
  unique_source_ips: number;
  total_observed_duration_seconds: number;
}

export interface PortTrafficReportResponse {
  port: number;
  service_name: string;
  monitoring_window: MonitoringWindowSummary;
  summary: PortTrafficSummary;
  ip_breakdown: IPTrafficSummary[];
  timeline: TimelineBucket[];
}

export interface LiveSourceIpInfo {
  source_ip: string;
  activity_count: number;
  first_seen: string;
  last_seen: string;
  observed_duration_seconds: number;
}

export interface LivePortInfo {
  port: number;
  protocol: string;
  service_name: string;
  current_status: string;
  local_addresses: string[];
  process_name?: string;
  current_active_connections: number;
  first_activity?: string;
  last_activity?: string;
  total_activity_count: number;
  unique_source_ips: number;
  observed_duration_seconds: number;
  source_ips: LiveSourceIpInfo[];
  cpu_percent?: number;
  memory_mb?: number;
  uptime_seconds?: number;
}

export interface LiveWindowSummary {
  start_time: string;
  end_time: string;
  duration_hours: number;
}

export interface SystemMetrics {
  system_cpu_percent: number;
  system_memory_total_gb: number;
  system_memory_used_gb: number;
  system_memory_percent: number;
  system_uptime_seconds: number;
}

export interface LivePortStatusResponse {
  generated_at: string;
  window: LiveWindowSummary;
  system?: SystemMetrics;
  ports: LivePortInfo[];
}

