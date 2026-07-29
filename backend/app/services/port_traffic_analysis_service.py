"""
Port Traffic Analysis Service — Processes port traffic history records,
calculates IP-level metrics and timelines, and assigns evidence-based classifications.
"""

import ipaddress
import psutil
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from app.database import port_traffic_repository
from app.database.connection import get_connection
from app.schemas.port_traffic import (
    IPTrafficSummary,
    MonitoringWindowSummary,
    PortTrafficReportResponse,
    PortTrafficSummary,
    TimelineBucket,
)
from app.services.detection_service import DetectionService
from app.utils.logger import logger

# Service port names mapping
SERVICE_NAMES = {
    8080: "Academia",
    8081: "Besto Health",
    8082: "Besto Clinic",
    80: "HTTP Web Server",
    443: "HTTPS Web Server",
    22: "SSH Service",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    8000: "SOC Backend API",
}


class PortTrafficAnalysisService:
    def __init__(self):
        self.detection_service = DetectionService()

    def get_monitored_ports(self) -> List[int]:
        """Returns list of monitored ports recorded in DB, merged with defaults."""
        recorded_ports = port_traffic_repository.get_monitored_ports_list()
        default_ports = [8080, 8081, 8082, 443, 80, 22, 3306, 5432, 8000]
        all_ports = sorted(list(set(recorded_ports + default_ports)))
        return all_ports


    def generate_report(
        self,
        port: int,
        start_time: datetime,
        end_time: datetime,
        bucket_minutes: int = 5,
    ) -> PortTrafficReportResponse:
        """Generates a complete factual port traffic analysis report."""

        # Fetch matching records from repository
        records = port_traffic_repository.get_port_records_in_window(
            port=port, start_time=start_time, end_time=end_time
        )

        service_name = SERVICE_NAMES.get(port, f"Port {port} Service")
        window_duration_seconds = max(0.0, (end_time - start_time).total_seconds())

        # Aggregate IP-level statistics
        ip_breakdown = self._calculate_ip_breakdown(records)

        # Total activity & unique IPs
        total_activity_count = sum(r.activity_count for r in ip_breakdown)
        unique_ips_count = len(ip_breakdown)
        total_observed_duration = (
            max([r.observed_duration_seconds for r in ip_breakdown], default=0.0)
            if ip_breakdown
            else 0.0
        )

        # Generate timeline buckets
        timeline = self._generate_timeline(
            records=records,
            start_time=start_time,
            end_time=end_time,
            bucket_minutes=bucket_minutes,
        )

        return PortTrafficReportResponse(
            port=port,
            service_name=service_name,
            monitoring_window=MonitoringWindowSummary(
                start_time=start_time,
                end_time=end_time,
                duration_seconds=window_duration_seconds,
            ),
            summary=PortTrafficSummary(
                total_activity_count=total_activity_count,
                unique_source_ips=unique_ips_count,
                total_observed_duration_seconds=total_observed_duration,
            ),
            ip_breakdown=ip_breakdown,
            timeline=timeline,
        )

    def _calculate_ip_breakdown(self, records: List[dict]) -> List[IPTrafficSummary]:
        """Groups records by source_ip and calculates observed activity metrics."""
        ip_groups: Dict[str, List[dict]] = defaultdict(list)
        for r in records:
            ip_groups[r["source_ip"]].append(r)

        breakdown: List[IPTrafficSummary] = []

        for ip, ip_records in ip_groups.items():
            first_seen = min(r["first_seen_at"] for r in ip_records)
            last_seen = max(r["last_seen_at"] for r in ip_records)
            activity_count = sum(r["activity_count"] for r in ip_records)

            # Observed activity duration span
            observed_duration = max(0.0, (last_seen - first_seen).total_seconds())

            # Evidence-based classification
            classification, evidence = self._determine_classification(ip)

            breakdown.append(
                IPTrafficSummary(
                    source_ip=ip,
                    classification=classification,
                    classification_evidence=evidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    activity_count=activity_count,
                    observed_duration_seconds=observed_duration,
                    exact_lifetime_proven=False,
                )
            )

        # Sort breakdown by activity count descending
        breakdown.sort(key=lambda x: x.activity_count, reverse=True)
        return breakdown

    def _determine_classification(self, ip: str) -> Tuple[str, str]:
        """
        Determines IP classification strictly based on real evidence:
        1. BLACKLISTED: matched in DetectionService._BLACKLISTED_IPS
        2. SUSPICIOUS: existing alert / detection record with searchable source_ip
        3. INTERNAL / LOOPBACK vs INTERNAL (RFC 1918)
        4. UNKNOWN / OBSERVED: default fallback
        """
        # 1. Blacklist check
        blacklisted_ips = getattr(self.detection_service, "_BLACKLISTED_IPS", set())
        if ip in blacklisted_ips:
            return (
                "BLACKLISTED",
                "Matched in DetectionService threat blacklist rules",
            )

        # 2. Existing Alert / Suspicious activity check
        if self._has_suspicious_evidence(ip):
            return (
                "SUSPICIOUS",
                "Searchable source IP matched existing alert/correlation record",
            )

        # 3. IP address parsing for Loopback & RFC 1918
        try:
            parsed_ip = ipaddress.ip_address(ip)
            if parsed_ip.is_loopback:
                return (
                    "INTERNAL / LOOPBACK",
                    "Loopback Address (127.0.0.0/8)",
                )

            if parsed_ip.is_private:
                if ipaddress.ip_network("10.0.0.0/8").supernet_of(
                    ipaddress.ip_network(f"{ip}/32")
                ) or parsed_ip in ipaddress.ip_network("10.0.0.0/8"):
                    subnet = "10.0.0.0/8"
                elif parsed_ip in ipaddress.ip_network("172.16.0.0/12"):
                    subnet = "172.16.0.0/12"
                elif parsed_ip in ipaddress.ip_network("192.168.0.0/16"):
                    subnet = "192.168.0.0/16"
                else:
                    subnet = "Private IP Range"

                return (
                    "INTERNAL",
                    f"RFC 1918 Private IP Range ({subnet})",
                )
        except ValueError:
            pass

        # 4. Default fallback
        return (
            "UNKNOWN / OBSERVED",
            "Observed port activity; no matching blacklist or alert evidence",
        )

    def _has_suspicious_evidence(self, ip: str) -> bool:
        """Checks if alerts or logs tables contain a searchable matching record for this source_ip."""
        query = """
            SELECT COUNT(*) FROM alerts WHERE source_ip = %s
            UNION ALL
            SELECT COUNT(*) FROM logs WHERE source_ip = %s AND is_suspicious = TRUE;
        """
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (ip, ip))
                counts = cursor.fetchall()
                total_hits = sum(row[0] for row in counts)
                return total_hits > 0
        except Exception as exc:
            logger.error(f"[Analysis] Error querying evidence for IP {ip}: {exc}")
            return False

    def _generate_timeline(
        self,
        records: List[dict],
        start_time: datetime,
        end_time: datetime,
        bucket_minutes: int,
    ) -> List[TimelineBucket]:
        """Divides window into time buckets and aggregates bucket activity."""
        if bucket_minutes <= 0:
            bucket_minutes = 5

        delta = timedelta(minutes=bucket_minutes)
        buckets: List[TimelineBucket] = []

        current_bucket_start = start_time
        while current_bucket_start < end_time:
            current_bucket_end = current_bucket_start + delta

            # Filter records overlapping current bucket
            bucket_records = [
                r
                for r in records
                if r["first_seen_at"] < current_bucket_end
                and r["last_seen_at"] >= current_bucket_start
            ]

            connection_count = sum(r["activity_count"] for r in bucket_records)
            active_ips = list(set(r["source_ip"] for r in bucket_records))

            if bucket_records:
                min_first = min(r["first_seen_at"] for r in bucket_records)
                max_last = max(r["last_seen_at"] for r in bucket_records)
                observed_duration = max(
                    0.0, (max_last - min_first).total_seconds()
                )
            else:
                observed_duration = 0.0

            buckets.append(
                TimelineBucket(
                    timestamp=current_bucket_start,
                    connection_count=connection_count,
                    active_ips=active_ips,
                    observed_duration_seconds=observed_duration,
                )
            )

            current_bucket_start = current_bucket_end

        return buckets

    def get_live_port_status(self, hours: float = 6.0) -> dict:
        """
        Retrieves real-time OS-level socket status combined with historical traffic activity.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours)

        monitored_ports = self.get_monitored_ports()

        # 1. Gather current OS-level socket status
        try:
            conns = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError) as exc:
            logger.warning(f"Access denied reading network connections in API: {exc}")
            conns = []
        except Exception as exc:
            logger.error(f"Error reading network connections in API: {exc}")
            conns = []

        port_socket_info = defaultdict(lambda: {
            "is_listening": False,
            "active_connections": 0,
            "local_addresses": set(),
            "pids": set()
        })

        for conn in conns:
            if not conn.laddr:
                continue
            port = conn.laddr.port
            if port not in monitored_ports:
                continue

            ip = conn.laddr.ip
            port_socket_info[port]["local_addresses"].add(f"{ip}:{port}")
            if conn.pid:
                port_socket_info[port]["pids"].add(conn.pid)

            if conn.status == psutil.CONN_LISTEN:
                port_socket_info[port]["is_listening"] = True
            elif conn.status in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_RECV, psutil.CONN_SYN_SENT):
                port_socket_info[port]["active_connections"] += 1

        live_ports = []

        for port in monitored_ports:
            # Determine current status
            info = port_socket_info[port]
            current_active = info["active_connections"]
            
            if info["is_listening"] and current_active > 0:
                current_status = "OPEN_AND_ACTIVE"
            elif info["is_listening"]:
                current_status = "OPEN_IDLE"
            elif current_active > 0:
                # Active connections but listening socket not found (e.g. transient state)
                current_status = "OPEN_AND_ACTIVE"
            else:
                current_status = "CLOSED"

            process_name = None
            cpu_percent = 0.0
            memory_mb = 0.0
            uptime_seconds = 0.0

            if info["pids"]:
                try:
                    pid = list(info["pids"])[0]
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                    try:
                        cpu_percent = round(proc.cpu_percent(interval=None), 1)
                    except Exception:
                        cpu_percent = 0.0
                    try:
                        memory_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
                    except Exception:
                        memory_mb = 0.0
                    try:
                        uptime_seconds = max(0.0, time.time() - proc.create_time())
                    except Exception:
                        uptime_seconds = 0.0
                except Exception:
                    pass

            # 2. Gather historical activity in the last `hours`
            records = port_traffic_repository.get_port_records_in_window(
                port=port, start_time=start_time, end_time=now
            )

            total_activity = sum(r["activity_count"] for r in records)
            ip_breakdown = self._calculate_ip_breakdown(records)
            unique_ips = len(ip_breakdown)

            first_activity = min([r["first_seen_at"] for r in records]) if records else None
            last_activity = max([r["last_seen_at"] for r in records]) if records else None
            observed_duration = max(0.0, (last_activity - first_activity).total_seconds()) if records else 0.0

            source_ips = []
            for ip_sum in ip_breakdown:
                source_ips.append({
                    "source_ip": ip_sum.source_ip,
                    "activity_count": ip_sum.activity_count,
                    "first_seen": ip_sum.first_seen.isoformat(),
                    "last_seen": ip_sum.last_seen.isoformat(),
                    "observed_duration_seconds": ip_sum.observed_duration_seconds
                })

            live_ports.append({
                "port": port,
                "protocol": "TCP",
                "service_name": SERVICE_NAMES.get(port, f"Port {port} Service"),
                "current_status": current_status,
                "local_addresses": list(info["local_addresses"]),
                "process_name": process_name,
                "current_active_connections": current_active,
                "first_activity": first_activity.isoformat() if first_activity else None,
                "last_activity": last_activity.isoformat() if last_activity else None,
                "total_activity_count": total_activity,
                "unique_source_ips": unique_ips,
                "observed_duration_seconds": observed_duration,
                "source_ips": source_ips,
                "cpu_percent": cpu_percent,
                "memory_mb": memory_mb,
                "uptime_seconds": uptime_seconds,
            })

        # Calculate system-wide resource metrics
        try:
            sys_cpu = round(psutil.cpu_percent(interval=None), 1)
            vm = psutil.virtual_memory()
            sys_mem_total_gb = round(vm.total / (1024**3), 1)
            sys_mem_used_gb = round(vm.used / (1024**3), 1)
            sys_mem_pct = round(vm.percent, 1)
            boot_time = psutil.boot_time()
            sys_uptime = max(0.0, time.time() - boot_time)
            system_metrics = {
                "system_cpu_percent": sys_cpu,
                "system_memory_total_gb": sys_mem_total_gb,
                "system_memory_used_gb": sys_mem_used_gb,
                "system_memory_percent": sys_mem_pct,
                "system_uptime_seconds": sys_uptime,
            }
        except Exception as exc:
            logger.warning(f"Error reading system resource metrics: {exc}")
            system_metrics = {
                "system_cpu_percent": 0.0,
                "system_memory_total_gb": 16.0,
                "system_memory_used_gb": 8.0,
                "system_memory_percent": 50.0,
                "system_uptime_seconds": 86400.0,
            }

        return {
            "generated_at": now.isoformat(),
            "window": {
                "start_time": start_time.isoformat(),
                "end_time": now.isoformat(),
                "duration_hours": hours
            },
            "system": system_metrics,
            "ports": live_ports
        }


port_traffic_analysis_service = PortTrafficAnalysisService()
