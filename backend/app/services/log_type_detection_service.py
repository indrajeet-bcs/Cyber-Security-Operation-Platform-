import re
from typing import Any
from app.schemas.log import RawLogIngest
from app.utils.logger import logger

class LogTypeDetectionService:
    """
    Service to automatically identify log types and subtypes after parsing.
    Assigns confidence score and classification reason.
    """

    _AUTH_KEYWORDS = (
        "failed login", "login failed", "authentication failed", "password mismatch",
        "successful login", "login successful", "session opened", "session closed",
        "su attempt", "bad su", "access denied", "access granted", "unauthorized"
    )

    _DB_KEYWORDS = (
        "postgres", "postgresql", "mysql", "sqlite", "oracle", "mongodb",
        "mssql", "sqlserver", "db2", "redis", "cassandra"
    )

    _SQL_COMMANDS = (
        "select ", "insert ", "update ", "delete ", "create table", "drop table",
        "alter table", "create index", "grant ", "revoke "
    )

    def detect_log_type(self, raw: RawLogIngest, parse_result: dict[str, Any]) -> dict[str, Any]:
        """
        Classifies the log and returns classification results matching the required format.
        """
        logger.info("[INFO] Log type detection started")

        # 1. Gather all inputs safely
        source = (raw.source or "").strip()
        event_type = (raw.event_type or "").strip()
        message = (raw.message or "").strip()
        detected_format = parse_result.get("detected_format") or "text"

        metadata = raw.metadata or {}
        event_data = metadata.get("event_data") or {}
        
        source_lower = source.lower()
        event_type_lower = event_type.lower()
        message_lower = message.lower()

        # Check for event_id in metadata/event_data (common in Windows XML)
        payload = parse_result.get("payload") or {}
        event_id = (
            metadata.get("event_id")
            or event_data.get("EventID")
            or metadata.get("EventID")
            or (payload.get("metadata") or {}).get("event_id")
            or (payload.get("event_data") or {}).get("EventID")
        )

        # 2. Apply Classification Rules (Specific Platforms/Formats first)

        # Rule 1: windows_event
        if (
            detected_format == "windows_xml"
            or "windows" in source_lower
            or "windows" in event_type_lower
            or event_type_lower.startswith("windows_event")
            or event_type_lower.startswith("windows_raw")
            or (event_id is not None and (metadata.get("provider") or metadata.get("Provider") or event_data.get("Provider")))
        ):
            # Extract subtype based on EventID
            log_subtype = "system"
            if event_id:
                try:
                    eid = int(event_id)
                    if eid in (4624, 4625):
                        log_subtype = "authentication"
                    elif eid == 4688:
                        log_subtype = "process_creation"
                    elif eid in (4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740):
                        log_subtype = "account_management"
                    elif eid in (7045, 4697):
                        log_subtype = "service_installation"
                    elif eid in (4663, 4656):
                        log_subtype = "object_access"
                    elif eid in (1102, 4719):
                        log_subtype = "audit_log"
                except (ValueError, TypeError):
                    pass

            reason = "Detected EventID and Provider fields" if event_id else "Detected Windows Event signature"
            return self._build_result("windows_event", log_subtype, 95, reason)

        # Rule 2: chrome_browser
        if source_lower == "chrome-browser" or "chrome" in source_lower or event_type_lower.startswith("browser."):
            log_subtype = None
            if event_type_lower == "browser.url_visit":
                log_subtype = "url_visit"
            elif event_type_lower == "browser.search":
                log_subtype = "search"
            elif event_type_lower == "browser.download":
                log_subtype = "download"
            return self._build_result("chrome_browser", log_subtype, 95, "Source or event type matches Chrome browser log collector")

        # Rule 3: docker_event (lifecycle events)
        if source_lower == "docker" and event_type_lower.startswith("docker.") and event_type_lower not in ("docker.stdout", "docker.stderr", "docker_log"):
            return self._build_result("docker_event", "container_lifecycle", 95, "Docker event lifecycle format detected")

        # Rule 4: docker_container_log (stdout/stderr streams)
        if source_lower == "docker" and (event_type_lower in ("docker.stdout", "docker.stderr", "docker_log") or "stdout" in event_type_lower or "stderr" in event_type_lower):
            log_subtype = "stdout" if "stdout" in event_type_lower else ("stderr" if "stderr" in event_type_lower else "container_log")
            return self._build_result("docker_container_log", log_subtype, 95, "Docker container stdout/stderr log stream")

        # Rule 5: syslog
        if detected_format == "syslog" or source_lower == "syslog-collector" or "syslog" in event_type_lower or "syslog" in source_lower:
            log_subtype = "system"
            if any(kw in message_lower for kw in self._AUTH_KEYWORDS):
                log_subtype = "authentication"
            return self._build_result("syslog", log_subtype, 95, "Detected standard syslog format")

        # Rule 6: nginx_access  
        if (detected_format == "web" and "nginx" in source_lower) or (source_lower == "nginx-access" or "nginx" in source_lower and "access" in event_type_lower):
            return self._build_result("nginx_access", "access", 95, "Web access log with Nginx source")

        # Rule 7: apache_access
        if (detected_format == "web" and "apache" in source_lower) or (source_lower == "apache-access" or "apache" in source_lower and "access" in event_type_lower):
            return self._build_result("apache_access", "access", 95, "Web access log with Apache source")

        # Rule 8: firewall_log
        if (
            "firewall" in source_lower or "firewall" in event_type_lower or "fw" in source_lower
            or "paloalto" in source_lower or "cisco-asa" in source_lower or "fortigate" in source_lower or "iptables" in source_lower
            or (detected_format == "key_value" and any(k in metadata for k in ("srcip", "dstip", "action", "proto", "sport", "dport", "dst", "src")))
        ):
            log_subtype = "traffic"
            if "deny" in message_lower or "block" in message_lower or "drop" in message_lower:
                log_subtype = "deny"
            elif "allow" in message_lower or "accept" in message_lower or "permit" in message_lower:
                log_subtype = "allow"
            return self._build_result("firewall_log", log_subtype, 90, "Firewall source or event pattern detected")

        # Rule 9: dns_log
        if "dns" in source_lower or "dns" in event_type_lower or "query" in event_type_lower or "query:" in message_lower:
            log_subtype = "query"
            if "response" in message_lower or "reply" in message_lower:
                log_subtype = "response"
            return self._build_result("dns_log", log_subtype, 90, "DNS service or query pattern detected")

        # Rule 10: database_log
        if (
            any(kw in source_lower or kw in event_type_lower for kw in self._DB_KEYWORDS)
            or any(cmd in message_lower for cmd in self._SQL_COMMANDS)
        ):
            log_subtype = "query"
            if "error" in message_lower or "fail" in message_lower:
                log_subtype = "error"
            elif "connect" in message_lower or "login" in message_lower:
                log_subtype = "connection"
            return self._build_result("database_log", log_subtype, 85, "Database log pattern or SQL keywords detected")

        # Rule 11: authentication_log
        if (
            any(kw in event_type_lower for kw in ("auth", "login", "signin", "signup", "logout"))
            or any(kw in message_lower for kw in self._AUTH_KEYWORDS)
        ):
            log_subtype = "failure" if any(f in message_lower for f in ("fail", "deny", "bad", "mismatch", "unauthorized")) else "success"
            return self._build_result("authentication_log", log_subtype, 90, "Authentication keywords or event category detected")

        # Rule 12: application_log
        if any(kw in source_lower or kw in event_type_lower for kw in ("app", "application", "service", "web-app", "api", "backend", "frontend")):
            log_subtype = "info"
            if "error" in message_lower or "exception" in message_lower:
                log_subtype = "error"
            elif "warn" in message_lower:
                log_subtype = "warning"
            return self._build_result("application_log", log_subtype, 85, "Application source or service tag detected")

        # Fallback: unknown
        logger.warning("[WARNING] Unknown log type detected")
        return self._build_result("unknown", None, 20, "No matching classifier")

    def _build_result(self, log_type: str, subtype: str | None, confidence: int, reason: str) -> dict[str, Any]:
        """Helper to format classification output."""
        result = {
            "log_type": log_type,
            "confidence": confidence,
            "classification_reason": reason
        }
        if subtype:
            result["log_subtype"] = subtype
        
        if log_type != "unknown":
            logger.info(f"[INFO] Classified as {log_type}")
            
        return result

log_type_detection_service = LogTypeDetectionService()
