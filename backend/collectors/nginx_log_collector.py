#!/usr/bin/env python3
"""
NGINX Security Monitoring Agent for the AI-Powered SOC Platform.

Event-driven log collector using OS filesystem notifications (watchdog).
The OS wakes this agent whenever NGINX appends to access.log or error.log.
This agent will NEVER poll the log file on a fixed interval.

Supports dual-mode application filtering:
    • upstream_port  — port-based  (e.g. HR on :8080)
    • server_name    — host-based  (e.g. hr.company.com on :443)
    Either criterion is sufficient for a match (OR logic).

Cross-platform:
    Windows  →  ReadDirectoryChangesW  (via watchdog)
    Linux    →  inotify                (via watchdog)

Connects to the existing SOC pipeline via:
    POST /api/logs  →  RawLogIngest  →  Validation  →  Parsing  →  Detection  →  Alerts

DO NOT modify anything after the collector endpoint.
"""

import json
import logging
import os
import re
import socket
import sys
import threading
import time
from datetime import datetime, timezone

import requests

# ─── watchdog import ─────────────────────────────────────────────────────────
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    print("[FATAL] 'watchdog' package is not installed.")
    print("        Run: pip install watchdog")
    sys.exit(1)

# ─── Logging Configuration ───────────────────────────────────────────────────
# Blends structured logger (matching Docker collector) with print()-prefix style
# (matching Windows and Chrome collectors) for maximum operational clarity.
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("NginxCollector")

# ─── Backend Configuration ───────────────────────────────────────────────────
BACKEND_URL = "http://127.0.0.1:8000/api/logs"
REQUEST_TIMEOUT = 5  # seconds per POST request

# ─── Retry / Backoff Configuration ──────────────────────────────────────────
MAX_RETRIES = 5
RETRY_BASE_DELAY = 1.0   # seconds — doubles on each attempt
RETRY_MAX_DELAY  = 60.0  # seconds — caps the backoff ceiling

# ─── Offset Persistence ──────────────────────────────────────────────────────
# Stored next to this script so it survives collector restarts.
# Records the byte offset + inode of each watched log file.
OFFSET_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "nginx_collector_offsets.json"
)

# ─── Monitored Log Files ─────────────────────────────────────────────────────
# Windows example:  r"C:\nginx\logs\access.log"
# Linux example:    "/var/log/nginx/access.log"
MONITORED_LOGS = [
    r"C:\Bestowal Projects\nginx-1.28.0\nginx-1.28.0\logs\access.log",
    r"C:\Bestowal Projects\nginx-1.28.0\nginx-1.28.0\logs\error.log",
]
# ─── Application Filter Configuration ────────────────────────────────────────
# Each entry defines ONE monitored application.
#
# Matching is OR-based:
#   • upstream_port match  → the parsed upstream port equals app["upstream_port"]
#   • host/server_name match → the parsed Host header or server_name equals app["server_name"]
#   Either criterion alone is sufficient to forward the log line.
#
# Set upstream_port to None to match only by server_name  (virtual-host / SSL deployment).
# Set server_name  to None to match only by upstream_port (port-segregated deployment).
# Set MONITORED_APPLICATIONS = [] to forward ALL traffic   (wildcard / single-app mode).
MONITORED_APPLICATIONS = [
    {
        "name": "LoginApp",
        "upstream_port": "8080",
        "server_name": "localhost"
    }
]


# ─── NGINX Access Log Regex Patterns ─────────────────────────────────────────
# Compiled once at module load — avoids recompilation on every log line.

# Priority 1: Extended Combined Format
# Includes: $http_host  $upstream_addr  $request_time  (and optionally $request_id)
# NGINX config example:
#   log_format extended '$remote_addr - $remote_user [$time_local] '
#                       '"$request" $status $body_bytes_sent '
#                       '"$http_referer" "$http_user_agent" '
#                       '"$http_host" "$upstream_addr" "$request_time" "$request_id"';
ACCESS_LOG_EXTENDED_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+'           # client IP
    r'(?P<remote_user>\S+)\s+'            # ident (always -)
    r'(?P<auth_user>\S+)\s+'              # auth user (- when none)
    r'\[(?P<time_local>[^\]]+)\]\s+'      # [DD/Mon/YYYY:HH:MM:SS ±HHMM]
    r'"(?P<request>[^"]*?)"\s+'           # "METHOD /uri HTTP/1.1"
    r'(?P<status>\d{3})\s+'               # HTTP status code
    r'(?P<body_bytes_sent>\d+|-)\s+'      # response body bytes
    r'"(?P<http_referer>[^"]*?)"\s+'      # Referer header
    r'"(?P<http_user_agent>[^"]*?)"\s+'   # User-Agent header
    r'"(?P<http_host>[^"]*?)"\s+'         # Host header  ($http_host)
    r'"(?P<upstream_addr>[^"]*?)"\s+'     # upstream address  e.g. 127.0.0.1:8080
    r'"(?P<request_time>[^"]*?)"'         # request processing time in seconds
    r'(?:\s+"(?P<request_id>[^"]*?)")?'   # optional $request_id
    r'.*$'
)

# Priority 2: Standard Combined Log Format (default NGINX)
# log_format combined '$remote_addr - $remote_user [$time_local] '
#                     '"$request" $status $body_bytes_sent '
#                     '"$http_referer" "$http_user_agent"';
ACCESS_LOG_COMBINED_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+'
    r'(?P<remote_user>\S+)\s+'
    r'(?P<auth_user>\S+)\s+'
    r'\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*?)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes_sent>\d+|-)\s+'
    r'"(?P<http_referer>[^"]*?)"\s+'
    r'"(?P<http_user_agent>[^"]*?)"'
    r'.*$'
)

# NGINX Error Log Format
# 2026/07/03 11:00:00 [error] 1234#0: *5 message, client: 1.2.3.4, ...
ERROR_LOG_RE = re.compile(
    r'^(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#(?P<tid>\d+):\s+'
    r'(?:\*(?P<cid>\d+)\s+)?'
    r'(?P<message>.+)$'
)

# Context fields appended to NGINX error messages
# e.g. ", client: 1.2.3.4, server: hr.company.com, request: "GET /" HTTP/1.1",
#         upstream: "http://127.0.0.1:8080/", host: "hr.company.com""
ERROR_CONTEXT_RE = re.compile(
    r'(?:,\s*client:\s*(?P<client>[^,]+?))?'
    r'(?:,\s*server:\s*(?P<server>[^,]+?))?'
    r'(?:,\s*request:\s*"(?P<request>[^"]*?)")?'
    r'(?:,\s*upstream:\s*"(?P<upstream>[^"]*?)")?'
    r'(?:,\s*host:\s*"(?P<host>[^"]*?)")?'
    r'\s*$'
)

# Extract port number from upstream address strings:
#   "127.0.0.1:8080"        → "8080"
#   "http://127.0.0.1:8080/" → "8080"
UPSTREAM_PORT_RE = re.compile(r':(\d+)(?:/|$)')

# NGINX Combined Format timestamp
NGINX_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


# ═══════════════════════════════════════════════════════════════════════════════
# Watchdog Event Handler
# ═══════════════════════════════════════════════════════════════════════════════

class NginxFileEventHandler(FileSystemEventHandler):
    """
    Watchdog filesystem event handler.

    The watchdog Observer runs this handler in its own thread whenever the OS
    reports a change event in a watched directory. We filter events down to
    only the specific log files we care about, then wake the collector.

    Design rationale:
        • on_modified  → NGINX appended new log lines
        • on_created   → log rotation: NGINX created a new empty log file
        • All other event types (deleted, moved) are intentionally ignored.
    """

    def __init__(self, collector: "NginxLogCollector", monitored_paths: set):
        super().__init__()
        self.collector = collector
        # Normalise paths once for efficient lookup on every event
        self.monitored_paths = {
            os.path.normcase(os.path.abspath(p)) for p in monitored_paths
        }

    def _is_monitored(self, src_path: str) -> bool:
        """Return True if the event path is one of our configured log files."""
        return os.path.normcase(os.path.abspath(src_path)) in self.monitored_paths

    def on_modified(self, event):
        print(f"[DEBUG] File Modified: {event.src_path}")
        """
        OS reported that a file in the watched directory was modified.
        NGINX appends log lines by writing to the end of the file, which
        triggers this event. We seek to the stored byte offset and read only
        the new content — never re-reading previously processed lines.
        """
        if event.is_directory:
            return
        if not self._is_monitored(event.src_path):
            return

        log_name = os.path.basename(event.src_path)
        logger.info(f"[*] OS Event Received: {log_name} modified")
        self.collector._process_file(event.src_path)

    def on_created(self, event):
        """
        OS reported that a file was created in the watched directory.
        This is the primary signal for log rotation: NGINX renamed the old
        access.log and created a fresh empty one. We reset the stored offset
        to 0 so the new file is read from the beginning.
        """
        if event.is_directory:
            return
        if not self._is_monitored(event.src_path):
            return

        log_name = os.path.basename(event.src_path)
        abs_path = os.path.abspath(event.src_path)
        logger.info(f"[*] OS Event Received: {log_name} created (log rotation signal)")

        with self.collector.offset_lock:
            new_inode = self.collector.get_inode(abs_path)
            self.collector.offsets[abs_path] = {"offset": 0, "inode": new_inode}
            self.collector.save_offsets()

        print(f"[*] Log Rotation Detected for {log_name} (file created). Offset reset to 0.")
        # Read from the new file immediately (may already have content)
        self.collector._process_file(event.src_path)


# ═══════════════════════════════════════════════════════════════════════════════
# NGINX Log Collector
# ═══════════════════════════════════════════════════════════════════════════════

class NginxLogCollector:
    """
    Production-grade, event-driven NGINX Security Monitoring Agent.

    Architecture:
        1. Registers OS filesystem watchers (watchdog) on NGINX log directories.
        2. Sleeps at zero CPU cost until the OS delivers a file-change event.
        3. On each event, reads ONLY the newly appended bytes (byte-offset tracking).
        4. Parses access.log / error.log lines using tri-format regex (auto-detect).
        5. Filters lines through dual-mode application matching (port OR host).
        6. Converts matches to RawLogIngest-compatible payloads.
        7. Sends to POST /api/logs with exponential-backoff retry and buffer.
        8. Persists byte offsets to disk — survives restarts without duplicates.
    """

    def __init__(
        self,
        backend_url: str = BACKEND_URL,
        monitored_logs: list = None,
        monitored_applications: list = None,
        offset_file: str = OFFSET_FILE,
    ):
        self.backend_url = backend_url
        self.monitored_logs = monitored_logs if monitored_logs is not None else MONITORED_LOGS
        self.monitored_applications = (
            monitored_applications if monitored_applications is not None
            else MONITORED_APPLICATIONS
        )
        self.offset_file = offset_file
        self.host_name = socket.gethostname() or "nginx-host"
        self.running = True

        # Per-file offset state: abs_path → {"offset": int, "inode": int}
        self.offsets: dict = {}
        self.offset_lock = threading.Lock()

        # In-memory retry buffer for payloads that could not be delivered
        self.retry_buffer: list = []
        self.retry_lock = threading.Lock()

    # ── Offset Persistence ──────────────────────────────────────────────────

    def load_offsets(self):
        """Load previously persisted byte offsets from the JSON offset file."""
        if not os.path.exists(self.offset_file):
            self.offsets = {}
            return
        try:
            with open(self.offset_file, "r", encoding="utf-8") as f:
                self.offsets = json.load(f)
            logger.info(f"[+] Loaded      from {self.offset_file}")
        except Exception as e:
            logger.warning(f"[!] Could not load offset file ({e}). Starting fresh.")
            self.offsets = {}

    def save_offsets(self):
        """
        Persist current byte offsets to disk.
        IMPORTANT: must be called while holding self.offset_lock (or during init).
        """
        try:
            with open(self.offset_file, "w", encoding="utf-8") as f:
                json.dump(self.offsets, f, indent=2)
        except Exception as e:
            logger.error(f"[-] Failed to save offsets to {self.offset_file}: {e}")

    # ── File Identity ────────────────────────────────────────────────────────

    def get_inode(self, path: str) -> int:
        """
        Return a stable file-identity integer for the given path.

        On NTFS (Windows): st_ino is the file-index number — nonzero and stable
        across log rotation (rename + create). Falls back to ctime_ns when st_ino
        is zero (rare, e.g. FAT32 or network shares).

        On Linux: st_ino is the real inode number.
        """
        try:
            stat = os.stat(path)
            if stat.st_ino != 0:
                return stat.st_ino
            # Fallback: use creation-time nanoseconds as a surrogate identity
            return int(stat.st_ctime_ns)
        except Exception:
            return 0

    # ── Startup ──────────────────────────────────────────────────────────────

    def initialize_tracking(self):
        """
        Print startup banner, load persisted offsets, and initialise per-file
        tracking without replaying previously processed log content.

        For files seen for the first time: jump to end-of-file (offset = current size).
        For files seen before:            resume from the stored offset.
        For files that were rotated:      reset offset to 0.
        """
        print("\n" + "=" * 62)
        print("  NGINX Security Monitoring Agent  —  Collector Started")
        print("=" * 62)
        print(f"  Host      : {self.host_name}")
        print(f"  Backend   : {self.backend_url}")
        print(f"  Offsets   : {self.offset_file}")
        if self.monitored_applications:
            print(f"  Apps      : {len(self.monitored_applications)} configured")
        else:
            print("  Apps      : wildcard — ALL traffic forwarded")
        print("=" * 62)

        self.load_offsets()

        for log_path in self.monitored_logs:
            abs_path = os.path.abspath(log_path)
            log_name = os.path.basename(abs_path)

            if not os.path.exists(abs_path):
                print(f"[!] {log_name} not found at {abs_path}. Will watch for creation.")
                if abs_path not in self.offsets:
                    self.offsets[abs_path] = {"offset": 0, "inode": 0}
                continue

            current_inode  = self.get_inode(abs_path)
            current_size   = os.path.getsize(abs_path)
            stored         = self.offsets.get(abs_path)

            if stored is None:
                # First run — start at end to avoid replaying historical logs
                self.offsets[abs_path] = {"offset": current_size, "inode": current_inode}
                print(f"[+] Watching {log_name} — starting at end (offset {current_size:,} bytes)")

            else:
                stored_inode  = stored.get("inode", 0)
                stored_offset = stored.get("offset", 0)

                if stored_inode != 0 and stored_inode != current_inode:
                    print(
                        f"[*] Log Rotation Detected for {log_name} "
                        f"(inode changed {stored_inode} → {current_inode}). Resetting offset."
                    )
                    self.offsets[abs_path] = {"offset": 0, "inode": current_inode}

                elif stored_offset > current_size:
                    print(
                        f"[*] Log Rotation Detected for {log_name} "
                        f"(size {current_size:,} < offset {stored_offset:,}). Resetting offset."
                    )
                    self.offsets[abs_path] = {"offset": 0, "inode": current_inode}

                else:
                    # Normal resume
                    self.offsets[abs_path]["inode"] = current_inode
                    print(
                        f"[+] Resuming {log_name} "
                        f"from byte offset {stored_offset:,} (inode: {current_inode})"
                    )

        self.save_offsets()

        # Print configured application filter table
        if self.monitored_applications:
            print("\n[+] Monitored Applications:")
            for app in self.monitored_applications:
                port  = app.get("upstream_port") or "—"
                sname = app.get("server_name")   or "—"
                print(f"    • {app['name']:<22}  port={port:<8}  server_name={sname}")
        print()

    # ── Log Rotation Detection ────────────────────────────────────────────────

    def _detect_rotation(self, abs_path: str) -> bool:
        """
        Detect log rotation by comparing the stored inode / offset against the
        current file state. Called inside _process_file while holding offset_lock.

        Returns True if rotation was detected and offsets were reset.
        """
        try:
            stat = os.stat(abs_path)
            current_inode = stat.st_ino if stat.st_ino != 0 else int(stat.st_ctime_ns)
            current_size  = stat.st_size
        except FileNotFoundError:
            return False

        stored        = self.offsets.get(abs_path, {})
        stored_inode  = stored.get("inode", 0)
        stored_offset = stored.get("offset", 0)
        log_name      = os.path.basename(abs_path)
        rotated       = False

        if stored_inode != 0 and stored_inode != current_inode:
            print(
                f"[*] Log Rotation Detected for {log_name} "
                f"(inode changed {stored_inode} → {current_inode}). Resetting offset."
            )
            rotated = True

        elif stored_offset > current_size:
            print(
                f"[*] Log Rotation Detected for {log_name} "
                f"(size {current_size:,} < offset {stored_offset:,}). Resetting offset."
            )
            rotated = True

        if rotated:
            self.offsets[abs_path] = {"offset": 0, "inode": current_inode}
            self.save_offsets()

        return rotated

    # ── Core File Processing ─────────────────────────────────────────────────

    def _process_file(self, path: str):
        """
        Core method: reads all newly appended lines since the last stored byte
        offset, parses each line, applies dual-mode application filtering, and
        sends matched payloads to the SOC backend.

        Called from the watchdog Observer thread on every OS file-change event.
        This method is the only place that advances the stored byte offset.

        Error isolation:
            • PermissionError / FileNotFoundError → logged, returns early
            • Per-line parse errors → logged, line skipped, loop continues
            • Backend failures → exponential backoff retry + buffer
            • Nothing here can crash the outer watchdog loop
        """
        abs_path = os.path.abspath(path)
        log_name = os.path.basename(abs_path)
        log_type = "error" if "error" in log_name.lower() else "access"

        # ── Acquire offset and detect rotation ──────────────────────────────
        with self.offset_lock:
            if abs_path not in self.offsets:
                self.offsets[abs_path] = {"offset": 0, "inode": self.get_inode(abs_path)}
            self._detect_rotation(abs_path)
            stored_offset = self.offsets[abs_path]["offset"]

        logger.info(f"[*] Reading New Lines from {log_name} (from byte {stored_offset:,})")

        # ── Read only newly appended bytes ───────────────────────────────────
        new_lines = []
        new_offset = stored_offset
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(stored_offset)
                new_lines = f.readlines()
                new_offset = f.tell()
        except PermissionError as e:
            print(f"[!] Permission denied reading {log_name}: {e}")
            return
        except FileNotFoundError:
            print(f"[!] File disappeared: {log_name}. Waiting for OS creation event.")
            return
        except Exception as e:
            logger.error(f"[-] Unexpected error reading {log_name}: {e}")
            return

        if not new_lines:
            return

        print(f"[*] Reading New Lines — {len(new_lines)} line(s) from {log_name}")

        # ── Advance stored offset before parsing ────────────────────────────
        # We advance the offset immediately after reading to prevent re-reading
        # the same bytes if the backend is temporarily offline.
        with self.offset_lock:
            self.offsets[abs_path]["offset"] = new_offset
            self.save_offsets()
        print(f"[+] Offset Updated: {log_name} → {new_offset:,} bytes")

        # ── Parse, filter, and send each new line ───────────────────────────
        for raw_line in new_lines:
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue

            try:
                parsed = (
                    self._parse_access_line(line)
                    if log_type == "access"
                    else self._parse_error_line(line)
                )

                if parsed is None:
                    logger.debug(f"    [?] Unparseable line in {log_name}: {line[:120]}")
                    continue

                method = parsed.get("http_method") or ""
                uri    = parsed.get("request_uri") or ""
                status = parsed.get("status_code") or ""
                logger.info(f"[+] New Log Parsed: {method} {uri[:60]} {status}".rstrip())

                # ── Dual-mode application filter (port OR host/server_name) ─
                matched_app = self._match_application(parsed)

                if matched_app is None:
                    # Non-empty filter list with no match — discard silently
                    print(
                        f"[~] Filtered Application: "
                        f"host={parsed.get('host') or '—'}  "
                        f"port={parsed.get('upstream_port') or '—'}  "
                        f"— not in monitored applications"
                    )
                    continue

                payload = self._to_payload(parsed, log_type, matched_app)
                self._send_with_retry(payload)

            except Exception as e:
                # Never let a single bad line crash the collector loop
                logger.error(f"[-] Error processing line in {log_name}: {e}")

        # ── Flush any previously buffered payloads ──────────────────────────
        self._flush_retry_buffer()

    # ── Parsing ──────────────────────────────────────────────────────────────

    def _parse_access_line(self, line: str) -> dict | None:
        """
        Parse a single NGINX access log line using tri-format auto-detection.

        Priority order:
            1. JSON format          — if line starts with '{'
            2. Extended Combined    — with $http_host, $upstream_addr, $request_time
            3. Standard Combined    — default NGINX format (no upstream fields)

        Returns a normalised field dict or None if the line cannot be parsed.
        """
        stripped = line.lstrip()

        # Priority 1: JSON format (NGINX json log_format)
        if stripped.startswith("{"):
            return self._parse_json_access_line(line)

        # Priority 2: Extended format (upstream fields present)
        m = ACCESS_LOG_EXTENDED_RE.match(line)
        if m:
            return self._extract_access_fields(m, extended=True)

        # Priority 3: Standard Combined Log Format
        m = ACCESS_LOG_COMBINED_RE.match(line)
        if m:
            return self._extract_access_fields(m, extended=False)

        return None

    def _extract_access_fields(self, match: re.Match, extended: bool) -> dict:
        """
        Extract and normalise fields from a successful Combined/Extended regex match.
        Splits the request line into method, URI, and query string.
        Extracts upstream port from the upstream_addr field.
        """
        d = match.groupdict()

        # Parse "METHOD /uri?qs HTTP/1.1" request line
        http_method  = ""
        request_uri  = ""
        query_string = ""
        request_line = d.get("request") or ""
        parts = request_line.split(" ", 2)
        if len(parts) >= 2:
            http_method = parts[0]
            full_uri    = parts[1]
            if "?" in full_uri:
                request_uri, query_string = full_uri.split("?", 1)
            else:
                request_uri = full_uri

        # Extract upstream port from "127.0.0.1:8080" or "http://127.0.0.1:8080/"
        raw_upstream  = d.get("upstream_addr") or ""
        upstream_addr = raw_upstream if raw_upstream and raw_upstream != "-" else None
        upstream_port = None
        if upstream_addr:
            pm = UPSTREAM_PORT_RE.search(upstream_addr)
            if pm:
                upstream_port = pm.group(1)

        # Host header — only available in Extended format
        host = None
        if extended:
            raw_host = d.get("http_host") or ""
            host = raw_host if raw_host and raw_host != "-" else None

        timestamp = self._parse_nginx_time(d.get("time_local") or "")

        return {
            "client_ip":    d.get("remote_addr") or "",
            "http_method":  http_method,
            "request_uri":  request_uri,
            "query_string": query_string,
            "status_code":  d.get("status") or "",
            "bytes_sent":   d.get("body_bytes_sent") or "0",
            "http_referer": d.get("http_referer") or "",
            "user_agent":   d.get("http_user_agent") or "",
            "host":         host,
            "server_name":  None,           # not available in log line format
            "upstream_addr": upstream_addr,
            "upstream_port": upstream_port,
            "response_time": d.get("request_time") or None,
            "request_id":    d.get("request_id") or None,
            "timestamp":     timestamp,
        }

    def _parse_json_access_line(self, line: str) -> dict | None:
        """
        Parse a JSON-format NGINX access log line.
        Handles common field-name variations across different NGINX JSON configs.
        Returns a normalised field dict or None on JSON decode failure.
        """
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Upstream address — try multiple common field names
        raw_upstream = (
            d.get("upstream_addr") or d.get("upstream") or ""
        )
        upstream_addr = raw_upstream if raw_upstream and raw_upstream != "-" else None
        upstream_port = None
        if upstream_addr:
            pm = UPSTREAM_PORT_RE.search(upstream_addr)
            if pm:
                upstream_port = pm.group(1)

        # Parse request line
        http_method  = ""
        request_uri  = ""
        query_string = ""
        request_line = d.get("request") or ""
        parts = request_line.split(" ", 2)
        if len(parts) >= 2:
            http_method = parts[0]
            full_uri    = parts[1]
            if "?" in full_uri:
                request_uri, query_string = full_uri.split("?", 1)
            else:
                request_uri = full_uri

        # Timestamp — try multiple common field names
        raw_time = (
            d.get("time") or d.get("time_local") or d.get("timestamp") or ""
        )
        timestamp = self._parse_nginx_time(raw_time) if raw_time else datetime.now(timezone.utc).isoformat()

        return {
            "client_ip":    d.get("remote_addr") or d.get("client") or "",
            "http_method":  http_method,
            "request_uri":  request_uri,
            "query_string": query_string,
            "status_code":  str(d.get("status") or d.get("status_code") or ""),
            "bytes_sent":   str(d.get("body_bytes_sent") or d.get("bytes_sent") or "0"),
            "http_referer": d.get("http_referer") or d.get("referer") or "",
            "user_agent":   d.get("http_user_agent") or d.get("user_agent") or "",
            "host":         d.get("http_host") or d.get("host") or None,
            "server_name":  d.get("server_name") or None,
            "upstream_addr": upstream_addr,
            "upstream_port": upstream_port,
            "response_time": str(d.get("request_time") or d.get("response_time") or ""),
            "request_id":    d.get("request_id") or None,
            "timestamp":     timestamp,
        }

    def _parse_error_line(self, line: str) -> dict | None:
        """
        Parse a single NGINX error log line.

        Format:
            YYYY/MM/DD HH:MM:SS [level] pid#tid: *cid core_message[, context_fields]

        Context fields (optional, comma-separated tail):
            client: <ip>
            server: <server_name>
            request: "METHOD URI HTTP/V"
            upstream: "http://ip:port/path"
            host: "hostname"

        Returns a normalised field dict or None if the line does not match.
        """
        m = ERROR_LOG_RE.match(line)
        if not m:
            return None

        d       = m.groupdict()
        message = d.get("message") or ""
        level   = d.get("level") or "error"

        # Timestamp — NGINX error log uses local time "YYYY/MM/DD HH:MM:SS"
        try:
            dt        = datetime.strptime(d.get("time") or "", "%Y/%m/%d %H:%M:%S")
            timestamp = dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            timestamp = datetime.now(timezone.utc).isoformat()

        # Extract structured context fields from the message tail
        ctx        = ERROR_CONTEXT_RE.search(message)
        client_ip  = ""
        server     = None
        request    = ""
        upstream_r = None
        host       = None
        if ctx:
            client_ip  = (ctx.group("client")   or "").strip()
            server     = (ctx.group("server")   or "").strip() or None
            request    = (ctx.group("request")  or "").strip()
            upstream_r = (ctx.group("upstream") or "").strip() or None
            host       = (ctx.group("host")     or "").strip() or None

        # Split request into method + URI
        http_method  = ""
        request_uri  = ""
        if request:
            rparts = request.split(" ", 2)
            if len(rparts) >= 2:
                http_method = rparts[0]
                request_uri = rparts[1]

        # Extract upstream port from the upstream URL
        upstream_port = None
        if upstream_r:
            pm = UPSTREAM_PORT_RE.search(upstream_r)
            if pm:
                upstream_port = pm.group(1)

        # Strip the context tail from the core message
        core_message = re.split(r",\s*client:", message, maxsplit=1)[0].strip()

        return {
            "client_ip":     client_ip,
            "http_method":   http_method,
            "request_uri":   request_uri,
            "query_string":  "",
            "status_code":   "",          # Error logs do not carry HTTP status codes
            "bytes_sent":    "0",
            "http_referer":  "",
            "user_agent":    "",
            "host":          host or server,
            "server_name":   server,
            "upstream_addr": upstream_r,
            "upstream_port": upstream_port,
            "response_time": None,
            "request_id":    None,
            "timestamp":     timestamp,
            "error_level":   level,
            "message":       core_message,
            "pid":           d.get("pid") or "",
            "connection_id": d.get("cid") or "",
        }

    def _parse_nginx_time(self, time_str: str) -> str:
        """
        Convert an NGINX timestamp string to an ISO-8601 UTC string.

        Handles two common formats:
            • Combined log format: "03/Jul/2026:11:00:00 +0530"
            • ISO-8601 (JSON logs): "2026-07-03T11:00:00+05:30"  or  "2026-07-03T11:00:00Z"
        """
        if not time_str:
            return datetime.now(timezone.utc).isoformat()

        # Try NGINX Combined timestamp
        try:
            dt = datetime.strptime(time_str.strip(), NGINX_TIME_FORMAT)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass

        # Try ISO-8601 (JSON log_format)
        try:
            dt = datetime.fromisoformat(time_str.strip().replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass

        return datetime.now(timezone.utc).isoformat()

    # ── Severity Mapping ─────────────────────────────────────────────────────

    def _determine_severity(self, parsed: dict, log_type: str) -> str:
        """
        Map NGINX log fields to SOC severity strings.

        Access logs — severity by HTTP status code:
            5xx → high     (server errors)
            401 / 403 → medium  (auth failures — security relevant)
            4xx → low      (client errors)
            2xx / 3xx → info

        Error logs — severity by NGINX log level:
            emerg / alert / crit / error → high
            warn                         → medium
            notice / info / debug        → info
        """
        if log_type == "error":
            level = (parsed.get("error_level") or "").lower()
            if level in ("emerg", "alert", "crit", "error"):
                return "high"
            elif level == "warn":
                return "medium"
            return "info"

        # Access log — HTTP status code based
        try:
            code = int(parsed.get("status_code") or 0)
        except (ValueError, TypeError):
            return "info"

        if code >= 500:
            return "high"
        elif code in (401, 403):
            return "medium"
        elif code >= 400:
            return "low"
        return "info"

    # ── Dual-Mode Application Filter ─────────────────────────────────────────

    def _match_application(self, parsed: dict):
        """
        OR-based dual-mode application filter.

        For each configured application entry, the following two criteria are
        evaluated. A match on EITHER criterion is sufficient:

            port_match:
                app["upstream_port"] is configured  AND
                parsed["upstream_port"] == app["upstream_port"]

            host_match:
                app["server_name"] is configured  AND
                (parsed["host"] == app["server_name"]  OR
                 parsed["server_name"] == app["server_name"])

        Returns:
            The matched application dict  (line is forwarded, metadata annotated).
            None                          (line is discarded — no match found).

        Special cases:
            MONITORED_APPLICATIONS = []   → wildcard mode; returns a synthetic
            "all" entry so every line is forwarded.
        """
        if not self.monitored_applications:
            # Wildcard / single-app mode — forward everything
            return {"name": "all", "upstream_port": None, "server_name": None}

        parsed_port  = parsed.get("upstream_port")                    # e.g. "8080"
        parsed_host  = (parsed.get("host")        or "").lower()      # e.g. "hr.company.com"
        parsed_sname = (parsed.get("server_name") or "").lower()

        for app in self.monitored_applications:
            app_port  = app.get("upstream_port")
            app_sname = (app.get("server_name") or "").lower()

            port_match = bool(
                app_port and parsed_port and parsed_port == app_port
            )
            host_match = bool(
                app_sname and (
                    (parsed_host  and parsed_host  == app_sname) or
                    (parsed_sname and parsed_sname == app_sname)
                )
            )

            if port_match or host_match:
                return app   # First-match wins

        return None   # No application matched — line will be discarded

    # ── Payload Construction ─────────────────────────────────────────────────

    def _to_payload(self, parsed: dict, log_type: str, matched_app: dict | None) -> dict:
        """
        Convert a parsed NGINX log dict into a RawLogIngest-compatible payload dict.

        Matches the exact schema and field conventions used by the existing
        Windows Event, Chrome Browser, and Docker collectors.
        """
        severity = self._determine_severity(parsed, log_type)

        # Human-readable message line
        if log_type == "error":
            event_type = "nginx.error"
            message    = parsed.get("message") or "NGINX error log event"
        else:
            method     = parsed.get("http_method") or "?"
            uri        = parsed.get("request_uri") or "/"
            status     = parsed.get("status_code") or "?"
            host_label = parsed.get("host")        or self.host_name
            message    = f"NGINX {method} {uri} → {status} [{host_label}]"
            event_type = "nginx.access"

        metadata = {
            "log_type":      log_type,
            "http_method":   parsed.get("http_method")   or "",
            "request_uri":   parsed.get("request_uri")   or "",
            "query_string":  parsed.get("query_string")  or "",
            "status_code":   parsed.get("status_code")   or "",
            "bytes_sent":    parsed.get("bytes_sent")    or "0",
            "http_referer":  parsed.get("http_referer")  or "",
            "user_agent":    parsed.get("user_agent")    or "",
            "host":          parsed.get("host")          or "",
            "server_name":   parsed.get("server_name")   or "",
            "upstream_addr": parsed.get("upstream_addr") or "",
            "upstream_port": parsed.get("upstream_port") or "",
            "response_time": parsed.get("response_time") or "",
            "request_id":    parsed.get("request_id")    or "",
        }

        # Annotate with matched application name (enables SOC-side app grouping)
        if matched_app and matched_app.get("name") != "all":
            metadata["application"] = matched_app["name"]

        # Error-log-specific metadata fields
        if log_type == "error":
            metadata["error_level"]   = parsed.get("error_level")   or ""
            metadata["pid"]           = parsed.get("pid")           or ""
            metadata["connection_id"] = parsed.get("connection_id") or ""

        return {
            "source":     "nginx",
            "event_type": event_type,
            "message":    message,
            "severity":   severity,
            "timestamp":  parsed.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "host":       self.host_name,
            "source_ip":  parsed.get("client_ip") or None,
            "metadata":   metadata,
        }

    # ── Backend Communication ─────────────────────────────────────────────────

    def send_to_backend(self, payload: dict) -> bool:
        """
        Send a single log payload to the FastAPI backend via POST /api/logs.
        Handles HTTP 409 (duplicate) as a success to advance the read pointer.
        Returns True on success or duplicate, False on any failure.
        """
        try:
            response = requests.post(self.backend_url, json=payload, timeout=REQUEST_TIMEOUT)

            if response.status_code in (200, 201):
                print(
                    f"  [SUCCESS] Backend Success: "
                    f"{payload['event_type']} — {payload['message'][:80]}"
                )
                return True

            elif response.status_code == 409:
                data = response.json()
                print(
                    f"  [SKIP] Duplicate event already stored as "
                    f"log id={data.get('existing_log_id')}. Skipping."
                )
                return True

            else:
                print(
                    f"  [X] Backend rejected payload. "
                    f"Status: {response.status_code}, Response: {response.text[:200]}"
                )
                return False

        except requests.exceptions.RequestException as e:
            print(f"  [X] Backend connection error: {e}. Will retry.")
            return False

    def _send_with_retry(self, payload: dict):
        """
        Attempt to deliver a payload with exponential backoff retry.

        Retry schedule (RETRY_BASE_DELAY = 1s, MAX_RETRIES = 5):
            Attempt 1 → immediate
            Attempt 2 → wait  1s
            Attempt 3 → wait  2s
            Attempt 4 → wait  4s
            Attempt 5 → wait  8s
            → all retries exhausted → payload added to retry_buffer

        The retry buffer is flushed at the end of every file-processing batch
        so buffered payloads are delivered as soon as the backend comes back online.
        """
        delay = RETRY_BASE_DELAY

        for attempt in range(1, MAX_RETRIES + 1):
            if self.send_to_backend(payload):
                return   # Delivered successfully

            if attempt < MAX_RETRIES:
                print(f"  [*] Retrying in {delay:.0f}s (attempt {attempt}/{MAX_RETRIES})...")
                time.sleep(delay)
                delay = min(delay * 2, RETRY_MAX_DELAY)

        # All retries exhausted — buffer for later delivery
        with self.retry_lock:
            self.retry_buffer.append(payload)
            buf_size = len(self.retry_buffer)
        print(f"  [!] All retries exhausted. Buffered for retry ({buf_size} in buffer).")

    def _flush_retry_buffer(self):
        """
        Attempt to drain the in-memory retry buffer.

        Called at the end of every _process_file batch. Stops on the first
        failed delivery to preserve payload ordering and avoid hammering a
        downed backend. On partial success, removes only the delivered entries.
        """
        with self.retry_lock:
            if not self.retry_buffer:
                return
            print(f"[*] Flushing retry buffer ({len(self.retry_buffer)} buffered payload(s))...")
            remaining = []
            for payload in self.retry_buffer:
                if not self.send_to_backend(payload):
                    # Backend still down — keep this and all subsequent entries
                    remaining.append(payload)
                    remaining.extend(self.retry_buffer[self.retry_buffer.index(payload) + 1:])
                    break
            sent = len(self.retry_buffer) - len(remaining)
            if sent:
                print(f"[+] Flushed {sent} buffered payload(s). {len(remaining)} remaining.")
            self.retry_buffer = remaining

    # ── Main Entry Point ─────────────────────────────────────────────────────

    def run(self):
        """
        Start the collector.

        1. Calls initialize_tracking() to load offsets and print the startup banner.
        2. Registers watchdog filesystem watchers on each NGINX log directory.
        3. Starts the watchdog Observer thread (runs in background, zero CPU when idle).
        4. Blocks the main thread in an idle loop until KeyboardInterrupt.

        The main thread consumes effectively zero CPU between file-change events.
        All active work happens in the watchdog Observer thread via _process_file.
        """
        self.initialize_tracking()

        # Group log paths by their parent directory
        # (watchdog schedules watchers per-directory, not per-file)
        monitored_dirs: dict = {}
        for log_path in self.monitored_logs:
            abs_path = os.path.abspath(log_path)
            log_dir  = os.path.dirname(abs_path)

            if not os.path.exists(log_dir):
                print(f"[!] Directory does not exist: {log_dir}. Skipping {os.path.basename(abs_path)}.")
                continue

            monitored_dirs.setdefault(log_dir, []).append(abs_path)

        if not monitored_dirs:
            print("[CRITICAL] No valid NGINX log directories found. Check MONITORED_LOGS config. Exiting.")
            sys.exit(1)

        # Collect the full set of monitored paths for the event handler filter
        all_paths = {p for paths in monitored_dirs.values() for p in paths}
        handler   = NginxFileEventHandler(collector=self, monitored_paths=all_paths)

        # Start the watchdog Observer
        observer = Observer()
        for log_dir, paths in monitored_dirs.items():
            observer.schedule(handler, path=log_dir, recursive=False)
            for lp in paths:
                print(f"[+] Watching {os.path.basename(lp)} in {log_dir}")

        observer.start()
        print(f"\n[*] Collector Waiting — OS will notify this agent on file change events.")
        print("[*] Press Ctrl+C to stop.\n")

        try:
            while self.running:
                # The Observer thread does all the real work.
                # This loop just keeps the main thread alive.
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Agent stopped by user.")
        finally:
            self.running = False
            observer.stop()
            observer.join()
            logger.info("[*] NGINX Collector shut down cleanly.")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        collector = NginxLogCollector()
        collector.run()
    except Exception as exc:
        print(f"[CRITICAL] NGINX Collector agent failed to start: {exc}")
        sys.exit(1)
