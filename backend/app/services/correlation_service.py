"""
Correlation Service — Advanced Real-Time Correlation Engine.

Production-grade multi-event correlation engine similar in concept to
Splunk ES, IBM QRadar, Microsoft Sentinel, Elastic Security, and Chronicle.

Architecture:
  - Runs AFTER the Rule Engine and BEFORE the Detection Service
  - All correlation operates from in-memory sliding-window caches (collections.deque)
  - PostgreSQL only stores correlation results (never queried for correlation logic)
  - Fully thread-safe via threading.Lock
  - All failures are caught and logged — never crashes the ingestion pipeline

Supported Correlation Detections:
  1. Failed Login Burst         — same user + same IP, >5 failures in 5 min
  2. Brute Force Success        — multiple failed logins → successful login in 10 min
  3. Multi-Host Attack          — same IP → ≥3 distinct hosts in 15 min
  4. Reconnaissance Activity    — same IP → ≥3 event categories (DNS/HTTP/Auth/Docker) in 10 min
  5. High-Risk Rule Chain       — ≥2 distinct high-risk rule matches in 15 min
  6. Browser→Download→Exec      — search → download → process for same user in 30 min
  7. Docker Attack Pattern      — restart + stop + create/recreate on same host in 10 min
  8. Risk Score Escalation      — cumulative risk_score ≥ 100 for user/IP in 1 hour

Cache Design:
  - user_cache:        user → deque[event_snapshot]
  - source_ip_cache:   source_ip → deque[event_snapshot]
  - host_cache:        host → deque[event_snapshot]
  - event_type_cache:  event_type → deque[event_snapshot]
  - fingerprint_cache: fingerprint → deque[event_snapshot]
"""

import hashlib
import threading
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from app.database import correlation_repository
from app.schemas.log import NormalizedSOCLog
from app.utils.logger import logger


# ---------------------------------------------------------------------------
# Constants — Sliding Window Durations
# ---------------------------------------------------------------------------

WINDOW_1_MIN = timedelta(minutes=1)
WINDOW_5_MIN = timedelta(minutes=5)
WINDOW_10_MIN = timedelta(minutes=10)
WINDOW_15_MIN = timedelta(minutes=15)
WINDOW_30_MIN = timedelta(minutes=30)
WINDOW_1_HOUR = timedelta(hours=1)
WINDOW_24_HOUR = timedelta(hours=24)

# Maximum events per cache key — prevents unbounded memory growth
_MAX_DEQUE_LEN = 10000

# Suppression windows for each correlation detector
SUPPRESSION_WINDOWS = {
    "failed_login_burst": WINDOW_5_MIN,
    "brute_force_success": WINDOW_10_MIN,
    "multi_host_attack": WINDOW_15_MIN,
    "reconnaissance_activity": WINDOW_10_MIN,
    "high_risk_rule_chain": WINDOW_15_MIN,
    "browser_download_execution_chain": WINDOW_30_MIN,
    "docker_attack_pattern": WINDOW_10_MIN,
    "risk_score_escalation": WINDOW_1_HOUR,
    # NGINX detectors (new — additive)
    "nginx_brute_force": WINDOW_5_MIN,
    "nginx_recon_scanning": WINDOW_10_MIN,
}


# ---------------------------------------------------------------------------
# NGINX Correlation Constants (centralized — configurable in one place)
# ---------------------------------------------------------------------------

# Number of failed HTTP auth attempts from same IP to trigger brute-force alert
NGINX_BRUTE_FORCE_THRESHOLD: int = 5
# Sliding window duration for NGINX brute-force detection
NGINX_BRUTE_FORCE_WINDOW: timedelta = WINDOW_5_MIN

# Number of distinct sensitive paths probed from same IP to trigger recon alert
NGINX_RECON_PATH_THRESHOLD: int = 5
# Sliding window duration for NGINX recon scanning detection
NGINX_RECON_WINDOW: timedelta = WINDOW_10_MIN

# Sensitive/reconnaissance path prefixes (case-insensitive startswith)
_NGINX_RECON_PATHS: frozenset[str] = frozenset({
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
})

# HTTP status codes that are relevant for NGINX recon/scanning detection
_NGINX_SUSPICIOUS_STATUS_CODES: frozenset[str] = frozenset({"401", "403", "404", "500"})

# URI path substrings that identify login endpoints for auth failure detection
_NGINX_LOGIN_URI_PATTERNS: tuple[str, ...] = (
    "/login",
    "/signin",
    "/auth",
    "/session",
    "/token",
    "/api/auth",
    "/api/login",
)


class CorrelationService:
    """
    Production-style in-memory correlation engine.

    Lifecycle:
      1. correlate() is called for every normalized log after rule evaluation.
      2. Event is indexed into all relevant caches.
      3. Stale entries (>24h) are purged from accessed caches.
      4. All 8 detectors run against the current cache state.
      5. Matches are persisted to PostgreSQL on a daemon background thread.
      6. Matches are returned to attach into normalized.metadata.

    Thread safety: All cache mutations are protected by self._lock.
    Failure isolation: correlate() NEVER raises — all exceptions caught and logged.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Primary caches: field_value → deque[event_snapshot dict]
        self._user_cache: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_DEQUE_LEN)
        )
        self._source_ip_cache: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_DEQUE_LEN)
        )
        self._host_cache: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_DEQUE_LEN)
        )
        self._event_type_cache: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_DEQUE_LEN)
        )
        self._fingerprint_cache: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_DEQUE_LEN)
        )

        # In-memory suppression tracking: correlation_key -> active dict
        self._active_correlations: dict[str, dict] = {}
        # Historical correlation keys to distinguish first-time from reactivation
        self._historical_correlations: set[str] = set()

    @staticmethod
    def _generate_correlation_key(match: dict) -> str:
        """
        Generates a deterministic correlation key for in-memory suppression tracking.
        Format: correlation_type:entity_identifier(s)
        """
        corr_type = match.get("correlation_type")
        user = match.get("related_user") or ""
        source_ip = match.get("related_source_ip") or ""
        host = match.get("related_host") or ""

        if corr_type == "failed_login_burst":
            return f"failed_login_burst:{user}:{source_ip}"
        elif corr_type == "brute_force_success":
            return f"brute_force_success:{user}"
        elif corr_type == "multi_host_attack":
            return f"multi_host_attack:{source_ip}"
        elif corr_type == "reconnaissance_activity":
            return f"reconnaissance_activity:{source_ip}"
        elif corr_type == "high_risk_rule_chain":
            entity = source_ip or user or "unknown"
            return f"high_risk_rule_chain:{entity}"
        elif corr_type == "browser_download_execution_chain":
            return f"browser_download_execution_chain:{user}"
        elif corr_type == "docker_attack_pattern":
            return f"docker_attack_pattern:{host}"
        elif corr_type == "risk_score_escalation":
            entity = source_ip or user or "unknown"
            return f"risk_score_escalation:{entity}"
        elif corr_type == "nginx_brute_force":
            return f"nginx_brute_force:{source_ip}"
        elif corr_type == "nginx_recon_scanning":
            return f"nginx_recon_scanning:{source_ip}"
        else:
            entity = source_ip or user or host or "unknown"
            return f"{corr_type}:{entity}"

    def reset_correlation(self, key: str) -> None:
        """Thread-safe public method to reset/clear an active correlation by key."""
        with self._lock:
            if key in self._active_correlations:
                del self._active_correlations[key]
                logger.info(f"[INFO] Correlation reset for key: {key}")

    def close_correlation(self, key: str) -> None:
        """Thread-safe public method to mark an active correlation as closed/reset status."""
        with self._lock:
            if key in self._active_correlations:
                self._active_correlations[key]["correlation_status"] = "closed"
                logger.info(f"[INFO] Correlation closed for key: {key}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, log: NormalizedSOCLog) -> list[dict]:
        """
        Main entry point — called by log_service AFTER Rule Engine, BEFORE Detection.

        1. Generate event fingerprint (deterministic SHA256)
        2. Build event snapshot from normalized log + rule_matches
        3. Index into all caches
        4. Purge expired entries (> 24h)
        5. Run all 8 correlation detectors
        6. For each match: persist to DB on background thread
        7. Return list of correlation_match dicts

        NEVER raises — all exceptions caught and logged.
        Returns [] on any failure.
        """
        try:
            return self._correlate_internal(log)
        except Exception as exc:
            logger.error(
                f"[CorrelationEngine] Unexpected top-level error — "
                f"continuing pipeline without correlation: {exc}"
            )
            return []

    # ------------------------------------------------------------------
    # Internal Correlation Pipeline
    # ------------------------------------------------------------------

    def _correlate_internal(self, log: NormalizedSOCLog) -> list[dict]:
        """Core correlation logic — separated for clean error boundaries."""
        logger.info("[INFO] Correlation Engine Started")

        now = datetime.now(timezone.utc)

        # 1. Generate deterministic fingerprint
        fingerprint = self._generate_fingerprint(log)

        # 2. Extract rule_matches and risk_score from metadata
        metadata = log.metadata if isinstance(log.metadata, dict) else {}
        rule_matches = metadata.get("rule_matches", [])
        risk_score = max(
            (int(rm.get("risk_score", 0)) for rm in rule_matches),
            default=0,
        )

        # Extract log_type from classification metadata
        log_classification = metadata.get("log_classification", {})
        log_type = None
        if isinstance(log_classification, dict):
            log_type = log_classification.get("log_type")

        # Extract NGINX HTTP context fields from metadata.
        # These are populated by the NGINX collector for nginx.access logs.
        # For all other log sources they resolve to empty strings, which means
        # the NGINX-specific detectors will not trigger for non-NGINX events.
        http_method = str(metadata.get("http_method") or "")
        request_uri = str(metadata.get("request_uri") or "")
        status_code = str(metadata.get("status_code") or "")
        user_agent = str(metadata.get("user_agent") or "")

        # 3. Build event snapshot
        event_snapshot = {
            "timestamp": now,
            "event_type": log.event_type or "",
            "host": log.host,
            "source": log.source,
            "user": log.user,
            "source_ip": log.source_ip,
            "severity": log.severity.value if log.severity else "low",
            "rule_matches": rule_matches,
            "risk_score": risk_score,
            "event_fingerprint": fingerprint,
            "log_type": log_type,
            # NGINX HTTP context (empty strings for non-NGINX sources — safe)
            "http_method": http_method,
            "request_uri": request_uri,
            "status_code": status_code,
            "user_agent": user_agent,
        }

        # 4. Index into caches and purge stale entries
        with self._lock:
            self._index_event(event_snapshot)
            self._purge_stale_entries(now)

        # 5. Run all 8 detectors
        matches: list[dict] = []

        detectors = [
            # Existing detectors — preserved exactly, order unchanged
            self._detect_failed_login_burst,
            self._detect_brute_force_success,
            self._detect_multi_host_attack,
            self._detect_reconnaissance,
            self._detect_high_risk_rule_chain,
            self._detect_browser_download_exec,
            self._detect_docker_attack_pattern,
            self._detect_risk_score_escalation,
            # New NGINX detectors — additive only
            self._detect_nginx_brute_force,
            self._detect_nginx_recon_scanning,
        ]

        for detector in detectors:
            try:
                result = detector(event_snapshot, now)
                if result:
                    matches.append(result)
            except Exception as exc:
                logger.error(
                    f"[CorrelationEngine] Detector {detector.__name__} failed: {exc} "
                    "— skipping this detector, continuing with others."
                )

        # 6. Apply suppression logic to matches
        non_suppressed_matches: list[dict] = []
        with self._lock:
            for match in matches:
                try:
                    key = self._generate_correlation_key(match)
                    window = SUPPRESSION_WINDOWS.get(match["correlation_type"], WINDOW_5_MIN)
                    
                    active = self._active_correlations.get(key)
                    if active:
                        # Check if expired
                        if now - active["first_seen"] > window:
                            logger.info(f"[INFO] Correlation window expired for key: {key}")
                            del self._active_correlations[key]
                            active = None
                        # Check if closed/reset
                        elif active.get("correlation_status") in ("closed", "reset"):
                            logger.info(f"[INFO] Correlation status was closed/reset for key: {key}")
                            del self._active_correlations[key]
                            active = None

                    if active:
                        # Suppress match: update last_seen and event_count internally
                        active["last_seen"] = match.get("last_seen", now)
                        active["event_count"] = match.get("event_count", active["event_count"])
                        logger.info(f"[INFO] Correlation suppressed for key: {key}")
                    else:
                        # Generate new correlation: track active
                        self._active_correlations[key] = {
                            "first_seen": match.get("first_seen", now),
                            "last_seen": match.get("last_seen", now),
                            "correlation_type": match["correlation_type"],
                            "event_count": match.get("event_count", 1),
                            "correlation_status": match.get("correlation_status", "active")
                        }
                        
                        if key in self._historical_correlations:
                            logger.info(f"[INFO] Correlation reactivated for key: {key}")
                        else:
                            logger.info(f"[INFO] Correlation generated for key: {key}")
                            self._historical_correlations.add(key)
                            
                        # Persist to PostgreSQL on background daemon thread
                        self._persist_async(match)
                        non_suppressed_matches.append(match)
                except Exception as exc:
                    logger.error(
                        f"[CorrelationEngine] Suppression check failed for match {match.get('correlation_type')}: {exc}. "
                        "Continuing without suppression for this match."
                    )
                    # Fail-open: write to DB and allow match if suppression logic fails
                    self._persist_async(match)
                    non_suppressed_matches.append(match)

        logger.info(
            f"[INFO] Correlation Engine Complete — "
            f"{len(non_suppressed_matches)} correlation(s) detected "
            f"for source={log.source} user={log.user} source_ip={log.source_ip}"
        )

        return non_suppressed_matches

    # ------------------------------------------------------------------
    # Event Fingerprint
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_fingerprint(log: NormalizedSOCLog) -> str:
        """
        Generates a deterministic SHA256 fingerprint from:
            source + host + event_type + user + source_ip

        Used for deduplication, grouping, attack tracking, and future investigations.
        """
        raw = (
            f"{log.source or ''}"
            f"|{log.host or ''}"
            f"|{log.event_type or ''}"
            f"|{log.user or ''}"
            f"|{log.source_ip or ''}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Cache Operations
    # ------------------------------------------------------------------

    def _index_event(self, snapshot: dict) -> None:
        """
        Pushes the event snapshot into all relevant caches.
        Must be called under self._lock.
        """
        user = snapshot.get("user")
        source_ip = snapshot.get("source_ip")
        host = snapshot.get("host")
        event_type = snapshot.get("event_type")
        fingerprint = snapshot.get("event_fingerprint")

        if user:
            self._user_cache[user].append(snapshot)
        if source_ip:
            self._source_ip_cache[source_ip].append(snapshot)
        if host:
            self._host_cache[host].append(snapshot)
        if event_type:
            self._event_type_cache[event_type].append(snapshot)
        if fingerprint:
            self._fingerprint_cache[fingerprint].append(snapshot)

    def _purge_stale_entries(self, now: datetime) -> None:
        """
        Removes events older than 24 hours from all caches.
        Uses popleft() on deque — matching the pattern in rule_engine_service.py.
        Must be called under self._lock.
        """
        cutoff = now - WINDOW_24_HOUR
        for cache in (
            self._user_cache,
            self._source_ip_cache,
            self._host_cache,
            self._event_type_cache,
            self._fingerprint_cache,
        ):
            for key in list(cache.keys()):
                dq = cache[key]
                while dq and dq[0].get("timestamp", now) < cutoff:
                    dq.popleft()
                # Remove empty deques to prevent memory leak from stale keys
                if not dq:
                    del cache[key]

    @staticmethod
    def _filter_window(events: deque, now: datetime, window: timedelta) -> list[dict]:
        """Returns events within the specified time window from the deque."""
        cutoff = now - window
        return [e for e in events if e.get("timestamp", now) >= cutoff]

    # ------------------------------------------------------------------
    # Background Persistence
    # ------------------------------------------------------------------

    def _persist_async(self, match: dict) -> None:
        """
        Persists a correlation match to PostgreSQL on a daemon background thread.
        DB write failure is logged but never re-raised — ingestion is never blocked.
        """
        def _write():
            try:
                correlation_repository.insert_correlation_event(match)
            except Exception as exc:
                logger.error(
                    f"[CorrelationEngine] Background DB write failed for "
                    f"correlation_id={match.get('correlation_id')}: {exc}"
                )

        thread = threading.Thread(target=_write, daemon=True)
        thread.start()

    # ------------------------------------------------------------------
    # Helper: Build a correlation match result
    # ------------------------------------------------------------------

    @staticmethod
    def _build_match(
        correlation_type: str,
        severity: str,
        confidence: int,
        risk_score: int,
        reason: str,
        related_user: str | None = None,
        related_source_ip: str | None = None,
        related_host: str | None = None,
        event_count: int = 0,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        event_fingerprint: str | None = None,
    ) -> dict:
        """Constructs a standardized correlation match result dict."""
        now = datetime.now(timezone.utc)
        return {
            "correlation_id": uuid.uuid4().hex,
            "correlation_type": correlation_type,
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "reason": reason,
            "related_user": related_user,
            "related_source_ip": related_source_ip,
            "related_host": related_host,
            "event_count": event_count,
            "first_seen": first_seen or now,
            "last_seen": last_seen or now,
            "correlation_reason": reason,
            "correlation_status": "active",
            "event_fingerprint": event_fingerprint,
            "created_at": now,
        }

    # ------------------------------------------------------------------
    # NGINX Helper Methods
    # ------------------------------------------------------------------

    @staticmethod
    def _is_nginx_auth_failure(snapshot: dict) -> bool:
        """
        Returns True if the snapshot represents a failed HTTP authentication event.

        Evaluates HTTP metadata fields (method, uri, status_code) — does NOT
        depend on the event_type string, so it correctly identifies NGINX
        authentication failures regardless of how the log is classified.

        Criteria:
          - status_code == "401"   (HTTP Unauthorized)
          - http_method == "POST"  (credential submission)
          - request_uri contains a recognized login endpoint pattern
        """
        method = (snapshot.get("http_method") or "").upper()
        uri = (snapshot.get("request_uri") or "").lower()
        status = str(snapshot.get("status_code") or "")
        return (
            status == "401"
            and method == "POST"
            and any(pattern in uri for pattern in _NGINX_LOGIN_URI_PATTERNS)
        )

    @staticmethod
    def _is_nginx_suspicious_request(snapshot: dict) -> bool:
        """
        Returns True if the snapshot represents a suspicious NGINX request
        suitable for recon scanning detection.

        Criteria:
          - source contains "nginx" (ensures only NGINX events are considered)
          - status_code is in _NGINX_SUSPICIOUS_STATUS_CODES (4xx/5xx)
          - request_uri starts with a path from _NGINX_RECON_PATHS
        """
        source = (snapshot.get("source") or "").lower()
        if "nginx" not in source:
            return False

        status = str(snapshot.get("status_code") or "")
        if status not in _NGINX_SUSPICIOUS_STATUS_CODES:
            return False

        uri = (snapshot.get("request_uri") or "").lower()
        return any(uri.startswith(path) for path in _NGINX_RECON_PATHS)

    # ------------------------------------------------------------------
    # Detector 1: Failed Login Burst
    # ------------------------------------------------------------------

    def _detect_failed_login_burst(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: Same user + same source_ip + >5 failed login events within 5 minutes.

        Trigger:  event_type contains "login" AND contains "fail"
        Cache:    source_ip_cache[source_ip] (cross-checked with user)
        Window:   5 minutes
        Severity: High
        """
        event_type = (snapshot.get("event_type") or "").lower()
        if "login" not in event_type or "fail" not in event_type:
            return None

        source_ip = snapshot.get("source_ip")
        user = snapshot.get("user")
        if not source_ip or not user:
            return None

        with self._lock:
            ip_events = self._source_ip_cache.get(source_ip)
            if not ip_events:
                return None
            window_events = self._filter_window(ip_events, now, WINDOW_5_MIN)

        # Filter: same user + failed login events
        failed_logins = [
            e for e in window_events
            if e.get("user") == user
            and "login" in (e.get("event_type") or "").lower()
            and "fail" in (e.get("event_type") or "").lower()
        ]

        if len(failed_logins) > 5:
            timestamps = [e["timestamp"] for e in failed_logins]
            return self._build_match(
                correlation_type="failed_login_burst",
                severity="high",
                confidence=90,
                risk_score=75,
                reason=(
                    f"{len(failed_logins)} failed login attempts from {source_ip} "
                    f"for user '{user}' within 5 minutes"
                ),
                related_user=user,
                related_source_ip=source_ip,
                related_host=snapshot.get("host"),
                event_count=len(failed_logins),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 2: Brute Force Success
    # ------------------------------------------------------------------

    def _detect_brute_force_success(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: Multiple failed logins → successful login within 10 minutes.

        Trigger:  a successful login event (event_type contains "login" but NOT "fail")
        Cache:    user_cache[user] — look back for prior failed logins
        Window:   10 minutes
        Threshold: ≥3 failed logins before the success
        Severity: Critical
        """
        event_type = (snapshot.get("event_type") or "").lower()

        # Only trigger on successful login (contains "login" but NOT "fail")
        if "login" not in event_type or "fail" in event_type:
            return None

        user = snapshot.get("user")
        if not user:
            return None

        with self._lock:
            user_events = self._user_cache.get(user)
            if not user_events:
                return None
            window_events = self._filter_window(user_events, now, WINDOW_10_MIN)

        # Count failed logins in the window (excluding the current success event)
        failed_logins = [
            e for e in window_events
            if "login" in (e.get("event_type") or "").lower()
            and "fail" in (e.get("event_type") or "").lower()
        ]

        if len(failed_logins) >= 3:
            timestamps = [e["timestamp"] for e in failed_logins]
            timestamps.append(snapshot.get("timestamp", now))
            return self._build_match(
                correlation_type="brute_force_success",
                severity="critical",
                confidence=95,
                risk_score=95,
                reason=(
                    f"Brute force detected: {len(failed_logins)} failed login attempts "
                    f"followed by successful login for user '{user}' within 10 minutes"
                ),
                related_user=user,
                related_source_ip=snapshot.get("source_ip"),
                related_host=snapshot.get("host"),
                event_count=len(failed_logins) + 1,
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 3: Multi-Host Attack
    # ------------------------------------------------------------------

    def _detect_multi_host_attack(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: Same source_ip contacting ≥3 distinct hosts within 15 minutes.

        Trigger:  any event with a source_ip
        Cache:    source_ip_cache[source_ip]
        Window:   15 minutes
        Severity: High
        """
        source_ip = snapshot.get("source_ip")
        if not source_ip:
            return None

        with self._lock:
            ip_events = self._source_ip_cache.get(source_ip)
            if not ip_events:
                return None
            window_events = self._filter_window(ip_events, now, WINDOW_15_MIN)

        # Collect distinct hosts
        distinct_hosts = set()
        for e in window_events:
            host = e.get("host")
            if host:
                distinct_hosts.add(host)

        if len(distinct_hosts) >= 3:
            timestamps = [e["timestamp"] for e in window_events]
            return self._build_match(
                correlation_type="multi_host_attack",
                severity="high",
                confidence=85,
                risk_score=80,
                reason=(
                    f"Source IP {source_ip} contacted {len(distinct_hosts)} distinct hosts "
                    f"({', '.join(sorted(distinct_hosts))}) within 15 minutes — "
                    f"possible lateral movement"
                ),
                related_user=snapshot.get("user"),
                related_source_ip=source_ip,
                related_host=", ".join(sorted(distinct_hosts)),
                event_count=len(window_events),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 4: Reconnaissance Activity
    # ------------------------------------------------------------------

    def _detect_reconnaissance(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: Same source_ip generating ≥3 distinct event categories within 10 min.

        Categories:
          - dns:    event_type contains "dns"
          - http:   event_type contains "http" or "web" or "browser"
          - auth:   event_type contains "login" or "auth" or "access"
          - docker: source contains "docker" or event_type contains "container"

        Severity: Medium (3 categories), High (4 categories)
        """
        source_ip = snapshot.get("source_ip")
        if not source_ip:
            return None

        with self._lock:
            ip_events = self._source_ip_cache.get(source_ip)
            if not ip_events:
                return None
            window_events = self._filter_window(ip_events, now, WINDOW_10_MIN)

        # Classify events into categories
        categories_found: set[str] = set()
        for e in window_events:
            et = (e.get("event_type") or "").lower()
            src = (e.get("source") or "").lower()

            if "dns" in et:
                categories_found.add("dns")
            if "http" in et or "web" in et or "browser" in et:
                categories_found.add("http")
            if "login" in et or "auth" in et or "access" in et:
                categories_found.add("auth")
            if "docker" in src or "container" in et:
                categories_found.add("docker")

        if len(categories_found) >= 3:
            severity = "high" if len(categories_found) >= 4 else "medium"
            timestamps = [e["timestamp"] for e in window_events]
            return self._build_match(
                correlation_type="reconnaissance_activity",
                severity=severity,
                confidence=80,
                risk_score=70 if severity == "medium" else 85,
                reason=(
                    f"Reconnaissance detected from {source_ip}: "
                    f"{len(categories_found)} distinct event categories "
                    f"({', '.join(sorted(categories_found))}) observed within 10 minutes"
                ),
                related_user=snapshot.get("user"),
                related_source_ip=source_ip,
                related_host=snapshot.get("host"),
                event_count=len(window_events),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 5: High-Risk Rule Chain
    # ------------------------------------------------------------------

    def _detect_high_risk_rule_chain(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: ≥2 distinct high-risk rule_code matches (risk_score ≥ 50) within 15 min.

        Trigger:  event has rule_matches with risk_score >= 50
        Cache:    source_ip_cache[source_ip] (fallback: user_cache[user])
        Window:   15 minutes
        Severity: Critical
        """
        # Only trigger if current event has high-risk rule matches
        current_rules = snapshot.get("rule_matches") or []
        high_risk_current = [
            rm for rm in current_rules if int(rm.get("risk_score", 0)) >= 50
        ]
        if not high_risk_current:
            return None

        # Determine which cache to search
        source_ip = snapshot.get("source_ip")
        user = snapshot.get("user")

        with self._lock:
            if source_ip:
                events = self._source_ip_cache.get(source_ip)
            elif user:
                events = self._user_cache.get(user)
            else:
                return None
            if not events:
                return None
            window_events = self._filter_window(events, now, WINDOW_15_MIN)

        # Collect all distinct rule_codes with risk_score >= 50 in the window
        distinct_rule_codes: set[str] = set()
        for e in window_events:
            for rm in (e.get("rule_matches") or []):
                if int(rm.get("risk_score", 0)) >= 50:
                    distinct_rule_codes.add(rm.get("rule_code", ""))

        if len(distinct_rule_codes) >= 2:
            timestamps = [e["timestamp"] for e in window_events]
            return self._build_match(
                correlation_type="high_risk_rule_chain",
                severity="critical",
                confidence=92,
                risk_score=95,
                reason=(
                    f"High-risk rule chain detected: {len(distinct_rule_codes)} distinct "
                    f"high-risk rules triggered ({', '.join(sorted(distinct_rule_codes))}) "
                    f"within 15 minutes"
                ),
                related_user=user,
                related_source_ip=source_ip,
                related_host=snapshot.get("host"),
                event_count=len(window_events),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 6: Browser → Download → Execution Chain
    # ------------------------------------------------------------------

    def _detect_browser_download_exec(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: Same user performs browser.search → browser.download → process execution
        within 30 minutes.

        Categories checked:
          1. browser search: event_type contains "browser" AND "search"
          2. browser download: event_type contains "browser" AND "download"
          3. process execution: event_type starts with "process" or "exec"

        Severity: Critical
        """
        user = snapshot.get("user")
        if not user:
            return None

        with self._lock:
            user_events = self._user_cache.get(user)
            if not user_events:
                return None
            window_events = self._filter_window(user_events, now, WINDOW_30_MIN)

        has_search = False
        has_download = False
        has_execution = False

        for e in window_events:
            et = (e.get("event_type") or "").lower()

            if "browser" in et and "search" in et:
                has_search = True
            if "browser" in et and "download" in et:
                has_download = True
            if et.startswith("process") or et.startswith("exec"):
                has_execution = True

        if has_search and has_download and has_execution:
            timestamps = [e["timestamp"] for e in window_events]
            return self._build_match(
                correlation_type="browser_download_execution_chain",
                severity="critical",
                confidence=88,
                risk_score=90,
                reason=(
                    f"Attack chain detected for user '{user}': "
                    f"browser search → browser download → process execution "
                    f"within 30 minutes"
                ),
                related_user=user,
                related_source_ip=snapshot.get("source_ip"),
                related_host=snapshot.get("host"),
                event_count=len(window_events),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 7: Docker Attack Pattern
    # ------------------------------------------------------------------

    def _detect_docker_attack_pattern(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: container restart + container stop + container create/recreate
        on the same host within 10 minutes.

        Trigger:  source contains "docker" OR event_type contains "container"
        Cache:    host_cache[host]
        Severity: High
        """
        event_type = (snapshot.get("event_type") or "").lower()
        source = (snapshot.get("source") or "").lower()

        # Only trigger on Docker-related events
        if "docker" not in source and "container" not in event_type:
            return None

        host = snapshot.get("host")
        if not host:
            return None

        with self._lock:
            host_events = self._host_cache.get(host)
            if not host_events:
                return None
            window_events = self._filter_window(host_events, now, WINDOW_10_MIN)

        has_restart = False
        has_stop = False
        has_create = False

        for e in window_events:
            et = (e.get("event_type") or "").lower()
            src = (e.get("source") or "").lower()

            # Only consider Docker events for this host
            if "docker" not in src and "container" not in et:
                continue

            if "restart" in et:
                has_restart = True
            if "stop" in et:
                has_stop = True
            if "create" in et or "recreate" in et:
                has_create = True

        if has_restart and has_stop and has_create:
            timestamps = [e["timestamp"] for e in window_events]
            return self._build_match(
                correlation_type="docker_attack_pattern",
                severity="high",
                confidence=85,
                risk_score=80,
                reason=(
                    f"Docker attack pattern detected on host '{host}': "
                    f"container restart + stop + create/recreate within 10 minutes"
                ),
                related_user=snapshot.get("user"),
                related_source_ip=snapshot.get("source_ip"),
                related_host=host,
                event_count=len(window_events),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 8: Risk Score Escalation
    # ------------------------------------------------------------------

    def _detect_risk_score_escalation(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: Accumulated risk_score ≥ 100 for a user or source_ip within 1 hour.

        Trigger:  any event with rule_matches
        Cache:    source_ip_cache[source_ip] (primary), user_cache[user] (fallback)
        Window:   1 hour
        Severity: Critical
        """
        # Only trigger if current event has rule matches
        current_rules = snapshot.get("rule_matches") or []
        if not current_rules:
            return None

        source_ip = snapshot.get("source_ip")
        user = snapshot.get("user")

        # Try source_ip first, fallback to user
        with self._lock:
            if source_ip:
                events = self._source_ip_cache.get(source_ip)
            elif user:
                events = self._user_cache.get(user)
            else:
                return None
            if not events:
                return None
            window_events = self._filter_window(events, now, WINDOW_1_HOUR)

        # Sum all risk_scores in the window
        total_risk = sum(int(e.get("risk_score", 0)) for e in window_events)

        if total_risk >= 100:
            timestamps = [e["timestamp"] for e in window_events]
            entity = source_ip or user
            entity_type = "source_ip" if source_ip else "user"
            return self._build_match(
                correlation_type="risk_score_escalation",
                severity="critical",
                confidence=90,
                risk_score=total_risk,
                reason=(
                    f"Risk score escalation: cumulative risk score {total_risk} "
                    f"(threshold: 100) for {entity_type} '{entity}' "
                    f"across {len(window_events)} events within 1 hour"
                ),
                related_user=user,
                related_source_ip=source_ip,
                related_host=snapshot.get("host"),
                event_count=len(window_events),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 9: NGINX Brute Force
    # ------------------------------------------------------------------

    def _detect_nginx_brute_force(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: >= NGINX_BRUTE_FORCE_THRESHOLD POST /login 401 responses from
        the same source IP within NGINX_BRUTE_FORCE_WINDOW.

        Trigger:  _is_nginx_auth_failure(snapshot) returns True
        Cache:    source_ip_cache[source_ip]
        Window:   NGINX_BRUTE_FORCE_WINDOW  (default: 5 minutes)
        Threshold: NGINX_BRUTE_FORCE_THRESHOLD (default: 5 events)
        Severity: High

        NOTE: This detector operates entirely on HTTP metadata fields
        (http_method, request_uri, status_code). It does NOT depend on
        event_type content and therefore correctly detects NGINX brute force
        attacks that arrive as 'nginx.access' log events.

        Backward compatibility: The existing _detect_failed_login_burst detector
        (Detector 1) remains completely unchanged. This is a separate detector
        for a separate signal. There is no overlap because Detector 1 requires
        'login' AND 'fail' in event_type, which NGINX logs never satisfy.
        """
        if not self._is_nginx_auth_failure(snapshot):
            return None

        source_ip = snapshot.get("source_ip")
        if not source_ip:
            return None

        with self._lock:
            ip_events = self._source_ip_cache.get(source_ip)
            if not ip_events:
                return None
            window_events = self._filter_window(ip_events, now, NGINX_BRUTE_FORCE_WINDOW)

        # Count auth failures from same IP within the window
        auth_failures = [e for e in window_events if self._is_nginx_auth_failure(e)]

        if len(auth_failures) >= NGINX_BRUTE_FORCE_THRESHOLD:
            timestamps = [e["timestamp"] for e in auth_failures]
            return self._build_match(
                correlation_type="nginx_brute_force",
                severity="high",
                confidence=90,
                risk_score=80,
                reason=(
                    f"{len(auth_failures)} HTTP 401 authentication failures from "
                    f"{source_ip} within "
                    f"{int(NGINX_BRUTE_FORCE_WINDOW.total_seconds() // 60)} minute(s) "
                    f"(threshold: {NGINX_BRUTE_FORCE_THRESHOLD})"
                ),
                related_user=snapshot.get("user"),
                related_source_ip=source_ip,
                related_host=snapshot.get("host"),
                event_count=len(auth_failures),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None

    # ------------------------------------------------------------------
    # Detector 10: NGINX Recon Scanning
    # ------------------------------------------------------------------

    def _detect_nginx_recon_scanning(
        self, snapshot: dict, now: datetime
    ) -> dict | None:
        """
        Detects: Same source IP requesting >= NGINX_RECON_PATH_THRESHOLD distinct
        sensitive/administrative paths within NGINX_RECON_WINDOW — a strong
        indicator of automated reconnaissance or vulnerability scanning.

        Trigger:  _is_nginx_suspicious_request(snapshot) returns True
        Cache:    source_ip_cache[source_ip]
        Window:   NGINX_RECON_WINDOW  (default: 10 minutes)
        Threshold: NGINX_RECON_PATH_THRESHOLD distinct paths (default: 5)
        Severity: Medium (<10 distinct paths), High (>=10 distinct paths)

        NOTE: This detector operates on HTTP metadata fields and is independent
        of event_type content. It will not interfere with the existing
        _detect_reconnaissance detector (Detector 4), which categorizes events
        by DNS/HTTP/auth/docker categories and fires on >=3 categories.
        """
        if not self._is_nginx_suspicious_request(snapshot):
            return None

        source_ip = snapshot.get("source_ip")
        if not source_ip:
            return None

        with self._lock:
            ip_events = self._source_ip_cache.get(source_ip)
            if not ip_events:
                return None
            window_events = self._filter_window(ip_events, now, NGINX_RECON_WINDOW)

        # Collect distinct sensitive paths probed by this IP within the window
        distinct_paths: set[str] = set()
        for e in window_events:
            uri = (e.get("request_uri") or "").lower()
            status = str(e.get("status_code") or "")
            src = (e.get("source") or "").lower()
            if (
                "nginx" in src
                and status in _NGINX_SUSPICIOUS_STATUS_CODES
                and any(uri.startswith(path) for path in _NGINX_RECON_PATHS)
            ):
                distinct_paths.add(uri)

        if len(distinct_paths) >= NGINX_RECON_PATH_THRESHOLD:
            severity = "high" if len(distinct_paths) >= 10 else "medium"
            timestamps = [e["timestamp"] for e in window_events]
            return self._build_match(
                correlation_type="nginx_recon_scanning",
                severity=severity,
                confidence=85,
                risk_score=85 if severity == "high" else 70,
                reason=(
                    f"Reconnaissance scanning detected from {source_ip}: "
                    f"{len(distinct_paths)} distinct sensitive path(s) probed "
                    f"within {int(NGINX_RECON_WINDOW.total_seconds() // 60)} minute(s) "
                    f"(threshold: {NGINX_RECON_PATH_THRESHOLD})"
                ),
                related_user=snapshot.get("user"),
                related_source_ip=source_ip,
                related_host=snapshot.get("host"),
                event_count=len(window_events),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                event_fingerprint=snapshot.get("event_fingerprint"),
            )

        return None


# Module-level singleton (same pattern as all other services)
correlation_service = CorrelationService()
