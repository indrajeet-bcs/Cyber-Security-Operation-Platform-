// Types for the /api/system/metrics endpoint

export interface DiskPartition {
  mount_point: string;
  device: string;
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percent: number;
}

export interface ServiceProcessInfo {
  port: number;
  service_name: string;
  pid?: number | null;
  process_name?: string | null;
  status: 'ONLINE' | 'OFFLINE';
  cpu_percent: number;
  memory_mb: number;
  uptime_seconds: number;
}

export interface SystemMetricsResponse {
  generated_at: string;
  // CPU
  cpu_percent: number;
  cpu_count_logical: number;
  cpu_count_physical: number;
  // Memory
  memory_total_gb: number;
  memory_used_gb: number;
  memory_free_gb: number;
  memory_percent: number;
  // Disk (primary)
  disk_total_gb: number;
  disk_used_gb: number;
  disk_free_gb: number;
  disk_percent: number;
  disks: DiskPartition[];
  // Uptime
  uptime_seconds: number;
  boot_time_iso: string;
  // Network
  total_active_connections: number;
  // Services
  services: ServiceProcessInfo[];
  total_services: number;
  online_services: number;
  offline_services: number;
}
