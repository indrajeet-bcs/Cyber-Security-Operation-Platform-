from app.schemas.log import NormalizedSOCLog, DetectionResult, Severity
import re

# ---------------------------------------------------------------------------
# NGINX Detection Constants (centralized — configurable in one place)
# ---------------------------------------------------------------------------

# SQL injection regex patterns (case-insensitive matching against request_uri / query_string)
_SQL_INJECTION_PATTERNS: tuple[str, ...] = (
    r"union[\s\+]+select",
    r"select[\s\+]+.+\bfrom\b",
    r"insert[\s\+]+into",
    r"drop[\s\+]+table",
    r"or[\s\+]+'?1'?[\s]*=[\s]*'?1'?",
    r"'[\s]*or[\s]*'",
    r"--[\s]",
    r";[\s]*drop",
    r"xp_cmdshell",
    r"waitfor[\s]+delay",
    r"benchmark\(",
    r"sleep\(",
    r"char\(",
    r"exec\(",
)

# Path traversal regex patterns (case-insensitive matching against request_uri)
_PATH_TRAVERSAL_PATTERNS: tuple[str, ...] = (
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e",
    r"etc/passwd",
    r"etc/shadow",
    r"windows/system32",
    r"win\.ini",
    r"boot\.ini",
)

# Sensitive/reconnaissance path prefixes (case-insensitive startswith)
_RECON_PATH_PREFIXES: tuple[str, ...] = (
    "/.git",
    "/.env",
    "/.htaccess",
    "/admin",
    "/config",
    "/backup",
    "/phpinfo",
    "/wp-admin",
    "/wp-config",
    "/server-status",
    "/actuator",
    "/debug",
    "/.ds_store",
    "/web.config",
    "/credentials",
    "/phpmyadmin",
    "/manager",
    "/console",
    "/api/v1/admin",
)

# Substrings identifying known scanning/attack tool user-agents (case-insensitive)
_SUSPICIOUS_USER_AGENTS: tuple[str, ...] = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "hydra",
    "metasploit",
    "burpsuite",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "acunetix",
    "nessus",
    "openvas",
    " zap/",
    "w3af",
)

# HTTP status codes that indicate a server-side error for NGINX 5xx detection
_HTTP_5XX_PREFIX = "5"


class DetectionService:
    """Analyzes normalized logs to identify suspicious activity based on rules."""

    # Temporary in-code blacklist of suspicious/malicious source IPs
    _BLACKLISTED_IPS = {
        "192.168.1.10",
        "10.0.0.99",
        "203.0.113.50",
    }

    def analyze(self, log: NormalizedSOCLog) -> DetectionResult:
        """Evaluates a normalized log against detection rules.

        Existing rules (unchanged — preserved exactly):
        - If log severity is critical: suspicious = True, severity = critical.
        - If event_type contains 'malware': suspicious = True, severity = high (or critical).
        - If event_type contains 'unauthorized': suspicious = True, severity = high.
        - If event_type is 'login_failed' AND source_ip is blacklisted: suspicious = True.

        New NGINX metadata-aware rules (additive — do not affect existing checks):
        - HTTP 401 from nginx source → suspicious (auth failure)
        - SQL injection patterns in request_uri / query_string → suspicious (critical)
        - Path traversal patterns in request_uri → suspicious (high)
        - Sensitive path probing → suspicious (medium)
        - Known attack tool user-agent → suspicious (high)
        - HTTP 5xx from nginx source → suspicious (medium)
        """
        event_type = (log.event_type or "").lower().strip()
        source_ip = log.source_ip
        log_severity = log.severity

        # ── Existing checks — preserved exactly, order unchanged ──────────────

        # 1. Critical severity events
        if log_severity == Severity.critical:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.critical,
                reason="Critical severity log event",
            )

        # 2. Malware-related events
        if "malware" in event_type:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.critical if log_severity == Severity.critical else Severity.high,
                reason="Malware activity detected",
            )

        # 3. Unauthorized access events
        if "unauthorized" in event_type:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.high,
                reason="Unauthorized access attempt",
            )

        # 4. Blacklisted IP login failures
        if event_type == "login_failed" and source_ip in self._BLACKLISTED_IPS:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.high,
                reason="Login failure from blacklisted IP",
            )

        # ── New NGINX metadata-aware detection — additive only ────────────────
        # Only executed when none of the existing checks triggered.
        # Reads log.metadata which is already populated by the NGINX collector.

        nginx_result = self._analyze_nginx_metadata(log)
        if nginx_result is not None:
            return nginx_result

        # Default fallback: Event is not suspicious (unchanged)
        return DetectionResult(
            is_suspicious=False,
            severity=Severity.low,
            reason=None,
        )

    # ------------------------------------------------------------------
    # NGINX Metadata Analysis (new — additive only)
    # ------------------------------------------------------------------

    def _analyze_nginx_metadata(self, log: NormalizedSOCLog) -> DetectionResult | None:
        """
        Inspects NGINX HTTP metadata fields for attack indicators.

        This method is only called AFTER all existing detection checks have
        passed without triggering. It returns None if no NGINX indicators are
        found, allowing the default fallback to proceed unchanged.

        Checks (in severity order — most severe first):
          1. SQL Injection in request_uri / query_string → critical
          2. Path Traversal in request_uri → high
          3. Suspicious user-agent (known scanner tool) → high
          4. HTTP 401 authentication failure (nginx source) → high
          5. Sensitive path reconnaissance → medium
          6. HTTP 5xx server error (nginx source) → medium
        """
        metadata = log.metadata if isinstance(log.metadata, dict) else {}
        source = (log.source or "").lower()

        # Only inspect metadata when we have NGINX-relevant fields
        request_uri = str(metadata.get("request_uri") or "")
        query_string = str(metadata.get("query_string") or "")
        status_code = str(metadata.get("status_code") or "")
        user_agent = str(metadata.get("user_agent") or "")

        # Combine uri and query for injection checks (attacker may embed payload in either)
        full_request = f"{request_uri}?{query_string}" if query_string else request_uri

        # 1. SQL Injection
        if self._is_sql_injection_request(full_request):
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.critical,
                reason=f"SQL injection pattern detected in request: {request_uri[:120]}",
            )

        # 2. Path Traversal
        if self._is_directory_traversal_request(request_uri):
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.high,
                reason=f"Directory traversal pattern detected in request: {request_uri[:120]}",
            )

        # 3. Suspicious User-Agent
        if self._is_suspicious_user_agent(user_agent):
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.high,
                reason=f"Suspicious scanning tool user-agent detected: {user_agent[:80]}",
            )

        # 4. NGINX HTTP 401 authentication failure
        if "nginx" in source and status_code == "401":
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.high,
                reason=f"HTTP 401 authentication failure on {request_uri or 'unknown path'}",
            )

        # 5. Sensitive path reconnaissance
        if "nginx" in source and self._is_recon_request(request_uri):
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.medium,
                reason=f"Sensitive path probing detected: {request_uri[:120]}",
            )

        # 6. HTTP 5xx server error
        if "nginx" in source and status_code.startswith(_HTTP_5XX_PREFIX) and status_code:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.medium,
                reason=f"HTTP {status_code} server error on {request_uri or 'unknown path'}",
            )

        return None

    # ------------------------------------------------------------------
    # NGINX Helper Methods (prefer helper methods over duplicated logic)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_sql_injection_request(text: str) -> bool:
        """
        Returns True if the given text (URI or query string) contains a SQL
        injection pattern from the centralized _SQL_INJECTION_PATTERNS constant.
        Case-insensitive matching via re.IGNORECASE.
        """
        if not text:
            return False
        for pattern in _SQL_INJECTION_PATTERNS:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    @staticmethod
    def _is_directory_traversal_request(request_uri: str) -> bool:
        """
        Returns True if the request URI contains a path traversal pattern from
        the centralized _PATH_TRAVERSAL_PATTERNS constant.
        Case-insensitive matching via re.IGNORECASE.
        """
        if not request_uri:
            return False
        for pattern in _PATH_TRAVERSAL_PATTERNS:
            try:
                if re.search(pattern, request_uri, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    @staticmethod
    def _is_recon_request(request_uri: str) -> bool:
        """
        Returns True if the request URI starts with a sensitive/recon path prefix
        from the centralized _RECON_PATH_PREFIXES constant.
        Case-insensitive matching.
        """
        if not request_uri:
            return False
        uri_lower = request_uri.lower()
        return any(uri_lower.startswith(prefix) for prefix in _RECON_PATH_PREFIXES)

    @staticmethod
    def _is_suspicious_user_agent(user_agent: str) -> bool:
        """
        Returns True if the user-agent string contains a known scanning/attack
        tool identifier from the centralized _SUSPICIOUS_USER_AGENTS constant.
        Case-insensitive matching.
        """
        if not user_agent:
            return False
        ua_lower = user_agent.lower()
        return any(tool in ua_lower for tool in _SUSPICIOUS_USER_AGENTS)


detection_service = DetectionService()
