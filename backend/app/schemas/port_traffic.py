from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class PortTrafficRecordItem(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    protocol: Optional[str] = "TCP"
    first_seen_at: datetime
    last_seen_at: datetime
    activity_count: int = Field(default=1, ge=1)
    observed_duration_seconds: float = Field(default=0.0, ge=0.0)


class PortTrafficIngestRequest(BaseModel):
    monitored_port: int
    window_start: datetime
    window_end: datetime
    records: List[PortTrafficRecordItem]


class IPTrafficSummary(BaseModel):
    source_ip: str
    classification: str
    classification_evidence: str
    first_seen: datetime
    last_seen: datetime
    activity_count: int
    observed_duration_seconds: float
    exact_lifetime_proven: bool = False


class TimelineBucket(BaseModel):
    timestamp: datetime
    connection_count: int
    active_ips: List[str]
    observed_duration_seconds: float


class MonitoringWindowSummary(BaseModel):
    start_time: datetime
    end_time: datetime
    duration_seconds: float


class PortTrafficSummary(BaseModel):
    total_activity_count: int
    unique_source_ips: int
    total_observed_duration_seconds: float


class PortTrafficReportResponse(BaseModel):
    port: int
    service_name: str
    monitoring_window: MonitoringWindowSummary
    summary: PortTrafficSummary
    ip_breakdown: List[IPTrafficSummary]
    timeline: List[TimelineBucket]


class LiveSourceIpInfo(BaseModel):
    source_ip: str
    activity_count: int
    first_seen: str
    last_seen: str
    observed_duration_seconds: float


class LivePortInfo(BaseModel):
    port: int
    protocol: str
    service_name: str
    current_status: str
    local_addresses: List[str]
    process_name: Optional[str] = None
    current_active_connections: int
    first_activity: Optional[str] = None
    last_activity: Optional[str] = None
    total_activity_count: int
    unique_source_ips: int
    observed_duration_seconds: float
    source_ips: List[LiveSourceIpInfo]
    cpu_percent: Optional[float] = 0.0
    memory_mb: Optional[float] = 0.0
    uptime_seconds: Optional[float] = 0.0


class LiveWindowSummary(BaseModel):
    start_time: str
    end_time: str
    duration_hours: float


class SystemMetrics(BaseModel):
    system_cpu_percent: float
    system_memory_total_gb: float
    system_memory_used_gb: float
    system_memory_percent: float
    system_uptime_seconds: float


class LivePortStatusResponse(BaseModel):
    generated_at: str
    window: LiveWindowSummary
    system: Optional[SystemMetrics] = None
    ports: List[LivePortInfo]

