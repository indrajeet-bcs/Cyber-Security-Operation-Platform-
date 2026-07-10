"""
Rule Engine Service — Advanced detection layer between Normalization and Detection.

Evaluates enabled rules loaded from the `detection_rules` PostgreSQL table.
Supports two rule types:

  - pattern   : match based on source_type, event_type_pattern, message_pattern,
                and optionally metadata_conditions (NEW — NGINX-aware matching)
  - threshold : sliding-window counter — fires when N events seen in M minutes

Rules are cached in-memory on first use and can be refreshed via reload_rules().
The engine is fully thread-safe and will never crash the ingestion pipeline:
DB failures fall back to an empty rule set.

Output per matched rule:
    {
        "rule_code": str,
        "rule_name": str,
        "severity": str,
        "risk_score": int,
        "reason": str
    }
"""

import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from app.database import rule_repository
from app.schemas.log import NormalizedSOCLog
from app.utils.logger import logger


# ---------------------------------------------------------------------------
# NGINX Detection Pattern Constants
# Centralized here for easy configuration — do NOT hardcode inside methods.
# ---------------------------------------------------------------------------

# SQL Injection patterns (case-insensitive regex fragments)
_NGINX_SQL_INJECTION_PATTERNS: tuple[str, ...] = (
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

# Path traversal patterns (case-insensitive regex fragments)
_NGINX_PATH_TRAVERSAL_PATTERNS: tuple[str, ...] = (
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
_NGINX_RECON_PATHS: tuple[str, ...] = (
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

# Suspicious scanning tool user-agent substrings (case-insensitive contains)
_NGINX_SUSPICIOUS_USER_AGENTS: tuple[str, ...] = (
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
    "zap",
    "w3af",
)


# ---------------------------------------------------------------------------
# Built-in NGINX Detection Rules
#
# These rules are always active — they do not depend on the detection_rules
# DB table being populated. They evaluate metadata fields (http_method,
# request_uri, status_code, user_agent) extracted by the NGINX collector.
#
# Each rule follows the same dict schema as DB-loaded rules so that the
# same _evaluate_pattern_rules() method evaluates them identically.
# ---------------------------------------------------------------------------

_BUILTIN_NGINX_RULES: list[dict] = [
    {
        "rule_code": "NGINX_AUTH_FAILURE",
        "rule_name": "NGINX Authentication Failure",
        "rule_type": "pattern",
        "severity": "high",
        "risk_score": 60,
        "source_type": "nginx",
        "event_type_pattern": None,
        "message_pattern": None,
        "metadata_conditions": {
            "status_code": {"op": "eq", "value": "401"},
        },
    },
    {
        "rule_code": "NGINX_SQL_INJECTION",
        "rule_name": "NGINX SQL Injection Attempt",
        "rule_type": "pattern",
        "severity": "critical",
        "risk_score": 90,
        "source_type": "nginx",
        "event_type_pattern": None,
        "message_pattern": None,
        "metadata_conditions": {
            "request_uri": {
                "op": "regex_any",
                "patterns": list(_NGINX_SQL_INJECTION_PATTERNS),
            },
        },
    },
    {
        "rule_code": "NGINX_PATH_TRAVERSAL",
        "rule_name": "NGINX Path Traversal Attempt",
        "rule_type": "pattern",
        "severity": "high",
        "risk_score": 80,
        "source_type": "nginx",
        "event_type_pattern": None,
        "message_pattern": None,
        "metadata_conditions": {
            "request_uri": {
                "op": "regex_any",
                "patterns": list(_NGINX_PATH_TRAVERSAL_PATTERNS),
            },
        },
    },
    {
        "rule_code": "NGINX_RECON_SCAN",
        "rule_name": "NGINX Reconnaissance Path Scan",
        "rule_type": "pattern",
        "severity": "medium",
        "risk_score": 50,
        "source_type": "nginx",
        "event_type_pattern": None,
        "message_pattern": None,
        "metadata_conditions": {
            "request_uri": {
                "op": "startswith_any",
                "paths": list(_NGINX_RECON_PATHS),
            },
        },
    },
    {
        "rule_code": "NGINX_SUSPICIOUS_UA",
        "rule_name": "NGINX Suspicious User-Agent (Scanner/Attack Tool)",
        "rule_type": "pattern",
        "severity": "high",
        "risk_score": 70,
        "source_type": "nginx",
        "event_type_pattern": None,
        "message_pattern": None,
        "metadata_conditions": {
            "user_agent": {
                "op": "contains_any",
                "values": list(_NGINX_SUSPICIOUS_USER_AGENTS),
            },
        },
    },
]


class RuleEngineService:
    """
    Production-style rule engine similar to Splunk, Wazuh, QRadar, and Elastic SIEM.

    Lifecycle:
      1. Rules are loaded from DB once on first `evaluate_rules()` call.
      2. `reload_rules()` can be called to force a refresh.
      3. Threshold sliding windows are kept in-memory per (rule_code, group_key).
      4. Built-in NGINX rules are always evaluated alongside DB rules (additive).
    """

    def __init__(self) -> None:
        self._rules: list[dict] = []
        self._rules_loaded: bool = False
        self._lock = threading.Lock()

        # Sliding window store: (rule_code, group_key) -> deque of UTC datetimes
        self._threshold_windows: dict[tuple, deque] = defaultdict(deque)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reload_rules(self) -> None:
        """Forces a fresh load of rules from the database."""
        with self._lock:
            try:
                self._rules = rule_repository.reload_rules()
                self._rules_loaded = True
                logger.info(
                    f"[RuleEngine] Rules reloaded — {len(self._rules)} enabled rules active."
                )
            except Exception as exc:
                logger.error(
                    f"[RuleEngine] Rule reload failed: {exc}. "
                    "Keeping previous rule set."
                )

    def evaluate_rules(self, log: NormalizedSOCLog) -> list[dict]:
        """
        Evaluates all enabled rules against a normalized log.

        Evaluation order:
          1. DB-loaded pattern rules (existing behaviour — unchanged)
          2. DB-loaded threshold rules (existing behaviour — unchanged)
          3. Built-in NGINX rules (new — additive only, always active)

        Returns a list of match dicts (one per matched rule).
        Returns [] if no rules match or if rule loading fails.
        Never raises — all exceptions are caught and logged.
        """
        logger.info("[INFO] Rule Engine Started")

        # Lazy-load rules on first call
        with self._lock:
            if not self._rules_loaded:
                try:
                    self._rules = rule_repository.get_enabled_rules()
                    self._rules_loaded = True
                    logger.info(
                        f"[RuleEngine] Loaded {len(self._rules)} enabled rules."
                    )
                except Exception as exc:
                    logger.error(
                        f"[RuleEngine] Could not load rules from DB: {exc}. "
                        "Processing with empty rule set — backend remains stable."
                    )
                    self._rules_loaded = True  # don't retry every log

        pattern_rules = [r for r in self._rules if r.get("rule_type") == "pattern"]
        threshold_rules = [r for r in self._rules if r.get("rule_type") == "threshold"]

        matches: list[dict] = []

        # 1 & 2. DB rules — existing behaviour, unchanged
        try:
            matches.extend(self._evaluate_pattern_rules(log, pattern_rules))
            matches.extend(self._evaluate_threshold_rules(log, threshold_rules))
        except Exception as exc:
            logger.error(f"[RuleEngine] Unexpected error during rule evaluation: {exc}")

        # 3. Built-in NGINX rules — additive, always active, no DB dependency
        try:
            matches.extend(self._evaluate_pattern_rules(log, _BUILTIN_NGINX_RULES))
        except Exception as exc:
            logger.error(
                f"[RuleEngine] Unexpected error during built-in NGINX rule evaluation: {exc}"
            )

        logger.info(
            f"[INFO] Rule Evaluation Complete — "
            f"{len(matches)} rule(s) matched for source={log.source}"
        )
        return matches

    # ------------------------------------------------------------------
    # Pattern Rules
    # ------------------------------------------------------------------

    def _evaluate_pattern_rules(
        self, log: NormalizedSOCLog, rules: list[dict]
    ) -> list[dict]:
        """
        Evaluates pattern rules.

        A rule matches if ALL non-null conditions match:
          - source_type         → log.source contains the value (case-insensitive)
          - event_type_pattern  → log.event_type contains/matches the pattern
          - message_pattern     → log.message contains/matches the pattern
          - metadata_conditions → all metadata field conditions match (NEW, additive)

        Patterns starting with '/' are treated as regex: /pattern/
        Otherwise substring contains match (case-insensitive).
        """
        matches = []
        for rule in rules:
            try:
                if self._pattern_rule_matches(log, rule):
                    match = self._build_match(
                        rule,
                        reason=f"Log matched pattern rule: {rule['rule_name']}",
                    )
                    matches.append(match)
                    self._emit_match_logs(match)
            except Exception as exc:
                logger.warning(
                    f"[RuleEngine] Error evaluating pattern rule "
                    f"'{rule.get('rule_code')}': {exc}"
                )
        return matches

    def _pattern_rule_matches(self, log: NormalizedSOCLog, rule: dict) -> bool:
        """
        Returns True only if every non-null condition in the rule matches.

        Existing conditions (source_type, event_type_pattern, message_pattern)
        are evaluated exactly as before. The new metadata_conditions check is
        purely additive — if absent from a rule, behaviour is identical to the
        original implementation.
        """
        source_type: str | None = rule.get("source_type")
        event_type_pattern: str | None = rule.get("event_type_pattern")
        message_pattern: str | None = rule.get("message_pattern")
        metadata_conditions: dict | None = rule.get("metadata_conditions")

        # Must have at least one condition defined
        if not any([source_type, event_type_pattern, message_pattern, metadata_conditions]):
            return False

        # Existing checks — unchanged
        if source_type:
            if not self._field_matches(log.source or "", source_type):
                return False

        if event_type_pattern:
            if not self._field_matches(log.event_type or "", event_type_pattern):
                return False

        if message_pattern:
            if not self._field_matches(log.message or "", message_pattern):
                return False

        # New metadata check — additive only; skipped when metadata_conditions is None
        if metadata_conditions:
            if not self._metadata_conditions_match(log, metadata_conditions):
                return False

        return True

    @staticmethod
    def _metadata_conditions_match(
        log: NormalizedSOCLog, conditions: dict[str, Any]
    ) -> bool:
        """
        Evaluates a set of metadata field conditions against the log's metadata dict.

        Supported operators:
          - eq            : str(field_value).lower() == str(value).lower()
          - contains      : str(value).lower() is a substring of field_value
          - contains_any  : any of the listed values is a substring of field_value
          - startswith_any: field_value starts with any of the listed path prefixes
          - regex         : re.search(value, field_value, IGNORECASE)
          - regex_any     : any pattern in the patterns list matches field_value

        ALL conditions in the dict must match (AND semantics), consistent with the
        existing _pattern_rule_matches() AND-gate design.

        Returns False if log.metadata is absent or a required field is missing.
        """
        metadata = log.metadata if isinstance(log.metadata, dict) else {}

        for field, condition in conditions.items():
            raw_value = metadata.get(field)
            if raw_value is None:
                return False

            field_value = str(raw_value)
            field_lower = field_value.lower()
            op = condition.get("op", "eq")

            if op == "eq":
                expected = str(condition.get("value", "")).lower()
                if field_lower != expected:
                    return False

            elif op == "contains":
                needle = str(condition.get("value", "")).lower()
                if needle not in field_lower:
                    return False

            elif op == "contains_any":
                needles = [str(v).lower() for v in condition.get("values", [])]
                if not any(n in field_lower for n in needles):
                    return False

            elif op == "startswith_any":
                prefixes = [str(p).lower() for p in condition.get("paths", [])]
                if not any(field_lower.startswith(p) for p in prefixes):
                    return False

            elif op == "regex":
                pattern = condition.get("value", "")
                try:
                    if not re.search(pattern, field_value, re.IGNORECASE):
                        return False
                except re.error:
                    return False

            elif op == "regex_any":
                patterns = condition.get("patterns", [])
                try:
                    if not any(
                        re.search(p, field_value, re.IGNORECASE) for p in patterns
                    ):
                        return False
                except re.error:
                    return False

            else:
                # Unknown operator — fail safe (treat as no match)
                return False

        return True

    @staticmethod
    def _field_matches(field_value: str, pattern: str) -> bool:
        """
        Matches a field value against a pattern.

        - Patterns wrapped in '/' are treated as regex:  /failed.*login/i
        - All other patterns: case-insensitive substring contains match.
        """
        field_lower = field_value.lower()
        pattern_stripped = pattern.strip()

        # Regex pattern: /pattern/ or /pattern/i
        if pattern_stripped.startswith("/") and pattern_stripped.rfind("/") > 0:
            last_slash = pattern_stripped.rfind("/")
            regex_body = pattern_stripped[1:last_slash]
            flags_str = pattern_stripped[last_slash + 1:]
            flags = re.IGNORECASE if "i" in flags_str else 0
            try:
                return bool(re.search(regex_body, field_value, flags))
            except re.error:
                return False

        # Plain substring match (case-insensitive)
        return pattern_stripped.lower() in field_lower

    # ------------------------------------------------------------------
    # Threshold Rules
    # ------------------------------------------------------------------

    def _evaluate_threshold_rules(
        self, log: NormalizedSOCLog, rules: list[dict]
    ) -> list[dict]:
        """
        Evaluates threshold (sliding window) rules.

        Each matching event is timestamped and counted within the window.
        A rule fires when count >= threshold_count within threshold_minutes.

        Group key = (rule_code, source, event_type) — ensures thresholds
        are tracked per-source per-event-type independently.
        """
        matches = []
        now = datetime.now(timezone.utc)

        for rule in rules:
            try:
                count = rule.get("threshold_count")
                minutes = rule.get("threshold_minutes")
                if not count or not minutes:
                    continue

                # A threshold rule must also match the pattern conditions
                # (source_type, event_type_pattern, message_pattern) before counting.
                if not self._pattern_rule_matches(log, rule):
                    continue

                rule_code = rule["rule_code"]
                group_key = (rule_code, log.source or "", log.event_type or "")
                window_duration = timedelta(minutes=minutes)
                cutoff = now - window_duration

                with self._lock:
                    window = self._threshold_windows[group_key]
                    # Append current event
                    window.append(now)
                    # Purge events outside the sliding window
                    while window and window[0] < cutoff:
                        window.popleft()
                    current_count = len(window)

                if current_count >= count:
                    reason = (
                        f"{current_count} matching events detected "
                        f"within {minutes} minute(s) "
                        f"(threshold: {count})"
                    )
                    match = self._build_match(rule, reason=reason)
                    matches.append(match)
                    self._emit_match_logs(match)

            except Exception as exc:
                logger.warning(
                    f"[RuleEngine] Error evaluating threshold rule "
                    f"'{rule.get('rule_code')}': {exc}"
                )

        return matches

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_match(rule: dict, reason: str) -> dict:
        """Constructs a standardized rule match result dict."""
        return {
            "rule_code": rule.get("rule_code", "UNKNOWN"),
            "rule_name": rule.get("rule_name", "Unknown Rule"),
            "severity": rule.get("severity", "low"),
            "risk_score": int(rule.get("risk_score") or 0),
            "reason": reason,
        }

    @staticmethod
    def _emit_match_logs(match: dict) -> None:
        """Emits required structured log entries for a matched rule."""
        logger.info(
            f"[INFO] Rule Matched — code={match['rule_code']} "
            f"severity={match['severity']} risk_score={match['risk_score']}"
        )
        if match["severity"] in ("high", "critical"):
            logger.warning(
                f"[WARNING] High Severity Rule Triggered — "
                f"rule={match['rule_code']} severity={match['severity']} "
                f"risk_score={match['risk_score']} reason={match['reason']}"
            )


# Module-level singleton (same pattern as all other services)
rule_engine_service = RuleEngineService()
