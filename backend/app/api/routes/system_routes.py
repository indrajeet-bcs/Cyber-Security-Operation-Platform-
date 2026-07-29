"""
System Metrics Route — exposes real-time host resource metrics via psutil.
CPU, RAM, Disk, Uptime, and per-monitored-port process stats.
"""

import time
import subprocess
import sys
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import psutil

from app.utils.logger import logger

router = APIRouter(prefix="/system", tags=["System Metrics"])


# ── Disk helper ─────────────────────────────────────────────────────────────

def _get_physical_disk_bytes_for_c() -> int:
    """
    On Windows, return the total physical size (in bytes) of the disk that
    contains the C: drive.  This is what Task Manager shows as “Capacity”.

    Uses PowerShell Get-Disk / Get-Partition which requires no elevation.
    Returns 0 on any failure so the caller can fall back to psutil values.
    """
    if sys.platform != "win32":
        return 0
    try:
        ps_script = (
            "$part = Get-Partition -DriveLetter C; "
            "$disk = Get-Disk -Number $part.DiskNumber; "
            "Write-Output $disk.Size"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True, text=True, timeout=10
        )
        raw = result.stdout.strip()
        if raw.isdigit():
            return int(raw)
        return 0
    except Exception as exc:
        logger.warning(f"[SystemMetrics] Physical disk query failed: {exc}")
        return 0


class DiskPartition(BaseModel):
    mount_point: str
    device: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent: float


class ServiceProcessInfo(BaseModel):
    port: int
    service_name: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    status: str  # ONLINE, OFFLINE
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    uptime_seconds: float = 0.0


class SystemMetricsResponse(BaseModel):
    generated_at: str
    # CPU
    cpu_percent: float
    cpu_count_logical: int
    cpu_count_physical: int
    # Memory
    memory_total_gb: float
    memory_used_gb: float
    memory_free_gb: float
    memory_percent: float
    # Disk (primary)
    disk_total_gb: float
    disk_used_gb: float
    disk_free_gb: float
    disk_percent: float
    disks: List[DiskPartition]
    # Uptime
    uptime_seconds: float
    boot_time_iso: str
    # Network connections
    total_active_connections: int
    # Services
    services: List[ServiceProcessInfo]
    total_services: int
    online_services: int
    offline_services: int


# Port → Service name map (same as port_traffic_analysis_service)
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

MONITORED_PORTS = sorted(SERVICE_NAMES.keys())


@router.get("/metrics", response_model=SystemMetricsResponse)
async def get_system_metrics():
    """
    Returns real-time host system metrics:
    CPU, RAM, Disk, Uptime, total active connections,
    and per-service process CPU/RAM stats.
    Offline services always report 0.0 for CPU and RAM.
    """
    now_ts = time.time()
    now_iso = __import__("datetime").datetime.utcnow().isoformat() + "Z"

    # ── CPU ─────────────────────────────────────────────────────────────────
    try:
        # interval=0.5 gives an accurate non-blocking measurement
        cpu_pct = round(psutil.cpu_percent(interval=0.5), 1)
    except Exception:
        cpu_pct = 0.0

    try:
        cpu_logical = psutil.cpu_count(logical=True) or 0
        cpu_physical = psutil.cpu_count(logical=False) or 0
    except Exception:
        cpu_logical = cpu_physical = 0

    # ── Memory ───────────────────────────────────────────────────────────────
    try:
        vm = psutil.virtual_memory()
        mem_total_gb = round(vm.total / (1024 ** 3), 2)
        mem_used_gb = round(vm.used / (1024 ** 3), 2)
        mem_free_gb = round(vm.available / (1024 ** 3), 2)
        mem_pct = round(vm.percent, 1)
    except Exception:
        mem_total_gb = mem_used_gb = mem_free_gb = mem_pct = 0.0

    # ── Disk ─────────────────────────────────────────────────────────────────
    #
    # Strategy:
    #   • psutil.disk_usage('C:\\') gives the correct used/free bytes for the
    #     NTFS partition, but its "total" is the partition size (~125 GB here),
    #     NOT the full physical disk that Task Manager calls "Capacity" (~239 GB).
    #   • We query the physical disk size via PowerShell (Get-Disk) and use that
    #     as total_gb so the number matches Task Manager.
    #   • used/free come from psutil (they are correct — OS-reported).
    #   • percent = used / physical_total (same formula Windows Storage uses).
    #
    disks: List[DiskPartition] = []
    primary_disk = DiskPartition(mount_point="C:\\", device="C:\\", total_gb=0, used_gb=0, free_gb=0, percent=0)
    try:
        # Always read C:\ directly — avoids partition-ordering issues
        c_usage = psutil.disk_usage("C:\\")
        c_used_bytes  = c_usage.used
        c_free_bytes  = c_usage.free

        # Physical disk size as reported by the OS (matches Task Manager)
        physical_total_bytes = _get_physical_disk_bytes_for_c()

        # Fall back to psutil partition size if the WMI query failed
        if physical_total_bytes <= 0:
            physical_total_bytes = c_usage.total
            logger.warning("[SystemMetrics] Falling back to psutil partition size for C:")

        c_total_gb   = round(physical_total_bytes / (1024 ** 3), 2)
        c_used_gb    = round(c_used_bytes          / (1024 ** 3), 2)
        c_free_gb    = round(c_free_bytes          / (1024 ** 3), 2)
        # Percentage relative to physical disk total — matches Task Manager / Storage
        c_pct        = round((c_used_bytes / physical_total_bytes) * 100, 1)

        primary_disk = DiskPartition(
            mount_point="C:\\",
            device="C:\\",
            total_gb=c_total_gb,
            used_gb=c_used_gb,
            free_gb=c_free_gb,
            percent=c_pct,
        )
        disks = [primary_disk]

        # Also collect any other mounted drives so the disk chart stays intact
        try:
            partitions = psutil.disk_partitions(all=False)
            for part in partitions:
                if part.mountpoint.upper().startswith("C:"):
                    continue  # already added above
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append(DiskPartition(
                        mount_point=part.mountpoint,
                        device=part.device,
                        total_gb=round(usage.total / (1024 ** 3), 2),
                        used_gb=round(usage.used  / (1024 ** 3), 2),
                        free_gb=round(usage.free  / (1024 ** 3), 2),
                        percent=round(usage.percent, 1),
                    ))
                except (PermissionError, OSError):
                    continue
        except Exception:
            pass

    except Exception as exc:
        logger.warning(f"[SystemMetrics] Disk error: {exc}")

    # ── Uptime ───────────────────────────────────────────────────────────────
    try:
        boot_ts = psutil.boot_time()
        uptime_sec = max(0.0, now_ts - boot_ts)
        boot_dt = __import__("datetime").datetime.fromtimestamp(boot_ts).isoformat()
    except Exception:
        uptime_sec = 0.0
        boot_dt = now_iso

    # ── Current TCP connections (all, for total count) ────────────────────────
    try:
        all_conns = psutil.net_connections(kind="tcp")
        # Count ESTABLISHED connections only
        total_active_conns = sum(
            1 for c in all_conns
            if c.status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV")
        )
    except Exception:
        total_active_conns = 0

    # ── Per-port / service stats ──────────────────────────────────────────────
    # Build map: port → set of PIDs currently listening on that port
    port_pid_map: dict = {p: set() for p in MONITORED_PORTS}
    port_status_map: dict = {p: "OFFLINE" for p in MONITORED_PORTS}

    try:
        conns = psutil.net_connections(kind="tcp")
        for conn in conns:
            if not conn.laddr:
                continue
            lport = conn.laddr.port
            if lport not in MONITORED_PORTS:
                continue
            if conn.status in ("LISTEN",):
                port_status_map[lport] = "ONLINE"
                if conn.pid:
                    port_pid_map[lport].add(conn.pid)
            elif conn.status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
                # If not already ONLINE from LISTEN, mark ONLINE anyway
                if port_status_map[lport] != "ONLINE":
                    port_status_map[lport] = "ONLINE"
                if conn.pid:
                    port_pid_map[lport].add(conn.pid)
    except Exception as exc:
        logger.warning(f"[SystemMetrics] Socket scan error: {exc}")

    services: List[ServiceProcessInfo] = []
    for port in MONITORED_PORTS:
        svc_name = SERVICE_NAMES[port]
        status = port_status_map[port]
        pids = port_pid_map[port]

        svc_cpu = 0.0
        svc_mem = 0.0
        svc_uptime = 0.0
        pid_used: Optional[int] = None
        proc_name: Optional[str] = None

        # Only collect resource data for ONLINE services
        if status == "ONLINE" and pids:
            pid = list(pids)[0]
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                pid_used = pid
                try:
                    # interval=0.1 blocks briefly but returns an accurate CPU %
                    # (interval=None always returns 0.0 on the very first call)
                    svc_cpu = round(proc.cpu_percent(interval=0.1), 1)
                except Exception:
                    svc_cpu = 0.0
                try:
                    svc_mem = round(proc.memory_info().rss / (1024 * 1024), 1)
                except Exception:
                    svc_mem = 0.0
                try:
                    svc_uptime = max(0.0, now_ts - proc.create_time())
                except Exception:
                    svc_uptime = 0.0
            except Exception:
                pass

        services.append(ServiceProcessInfo(
            port=port,
            service_name=svc_name,
            pid=pid_used,
            process_name=proc_name,
            status=status,
            cpu_percent=svc_cpu,
            memory_mb=svc_mem,
            uptime_seconds=svc_uptime,
        ))

    online_count = sum(1 for s in services if s.status == "ONLINE")
    offline_count = len(services) - online_count

    return SystemMetricsResponse(
        generated_at=now_iso,
        cpu_percent=cpu_pct,
        cpu_count_logical=cpu_logical,
        cpu_count_physical=cpu_physical,
        memory_total_gb=mem_total_gb,
        memory_used_gb=mem_used_gb,
        memory_free_gb=mem_free_gb,
        memory_percent=mem_pct,
        disk_total_gb=primary_disk.total_gb,
        disk_used_gb=primary_disk.used_gb,
        disk_free_gb=primary_disk.free_gb,
        disk_percent=primary_disk.percent,
        disks=disks,
        uptime_seconds=uptime_sec,
        boot_time_iso=boot_dt,
        total_active_connections=total_active_conns,
        services=services,
        total_services=len(services),
        online_services=online_count,
        offline_services=offline_count,
    )
