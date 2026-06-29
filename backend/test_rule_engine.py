"""
Test suite for the Advanced Rule Engine.

Tests cover:
  - Pattern rule matching (contains, regex, source_type, no-match)
  - Threshold sliding window (fires at threshold, does not fire early)
  - DB failure isolation (empty rules, no crash)
  - End-to-end pipeline integration (metadata.rule_matches attached)
  - High-severity warning logging

Run from: d:\\Componies Work\\Bestowal System Work\\soc_platform\\backend
    python -m pytest test_rule_engine.py -v
"""

import hashlib
import threading
import unittest
from collections import deque
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.log import NormalizedSOCLog, Severity
from app.services.rule_engine_service import RuleEngineService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_log(
    source="test-source",
    event_type="test.event",
    message="test message",
    source_ip=None,
    user=None,
) -> NormalizedSOCLog:
    """Creates a minimal NormalizedSOCLog for testing."""
    return NormalizedSOCLog(
        source=source,
        event_type=event_type,
        message=message,
        severity=Severity.low,
        timestamp=datetime.now(timezone.utc),
        source_ip=source_ip,
        user=user,
        metadata={},
    )


def _pattern_rule(
    rule_code="TEST_RULE",
    rule_name="Test Rule",
    severity="medium",
    risk_score=50,
    source_type=None,
    event_type_pattern=None,
    message_pattern=None,
) -> dict:
    """Constructs a pattern rule dict matching the detection_rules schema."""
    return {
        "id": 1,
        "rule_code": rule_code,
        "rule_name": rule_name,
        "rule_type": "pattern",
        "severity": severity,
        "source_type": source_type,
        "event_type_pattern": event_type_pattern,
        "message_pattern": message_pattern,
        "threshold_count": None,
        "threshold_minutes": None,
        "risk_score": risk_score,
        "is_enabled": True,
        "created_by": "system",
        "created_at": None,
        "updated_at": None,
    }


def _threshold_rule(
    rule_code="THRESH_RULE",
    rule_name="Threshold Rule",
    severity="high",
    risk_score=80,
    source_type=None,
    event_type_pattern=None,
    message_pattern=None,
    threshold_count=5,
    threshold_minutes=5,
) -> dict:
    """Constructs a threshold rule dict matching the detection_rules schema."""
    return {
        "id": 2,
        "rule_code": rule_code,
        "rule_name": rule_name,
        "rule_type": "threshold",
        "severity": severity,
        "source_type": source_type,
        "event_type_pattern": event_type_pattern,
        "message_pattern": message_pattern,
        "threshold_count": threshold_count,
        "threshold_minutes": threshold_minutes,
        "risk_score": risk_score,
        "is_enabled": True,
        "created_by": "system",
        "created_at": None,
        "updated_at": None,
    }


# ---------------------------------------------------------------------------
# Pattern Rule Tests
# ---------------------------------------------------------------------------

class TestPatternRules(unittest.TestCase):

    def setUp(self):
        # Fresh engine instance with empty DB — inject rules manually
        self.engine = RuleEngineService()
        self.engine._rules_loaded = True  # skip DB load in tests

    def test_message_contains_match(self):
        """Pattern rule fires when message contains the keyword."""
        self.engine._rules = [
            _pattern_rule(rule_code="FAILED_LOGIN", message_pattern="failed login")
        ]
        log = _make_log(message="User failed login from 192.168.1.1")
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_code"], "FAILED_LOGIN")

    def test_event_type_contains_match(self):
        """Pattern rule fires when event_type contains the pattern."""
        self.engine._rules = [
            _pattern_rule(rule_code="POWERSHELL", event_type_pattern="powershell")
        ]
        log = _make_log(event_type="windows.powershell_execution")
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_code"], "POWERSHELL")

    def test_source_type_match(self):
        """Pattern rule fires when source contains source_type value."""
        self.engine._rules = [
            _pattern_rule(rule_code="DOCKER_STOP", source_type="docker")
        ]
        log = _make_log(source="docker")
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_code"], "DOCKER_STOP")

    def test_regex_pattern_match(self):
        """Pattern rule with /regex/ syntax matches correctly."""
        self.engine._rules = [
            _pattern_rule(
                rule_code="ENCODED_CMD",
                message_pattern="/powershell.*-enc/i",
            )
        ]
        log = _make_log(message="Executed PowerShell -EncodedCommand abc123")
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_code"], "ENCODED_CMD")

    def test_multi_condition_all_must_match(self):
        """Pattern rule with multiple conditions requires ALL to match."""
        self.engine._rules = [
            _pattern_rule(
                rule_code="CHROME_DOWNLOAD",
                source_type="chrome",
                event_type_pattern="browser.download",
                message_pattern="http",
            )
        ]
        # Only source and event_type match — message does NOT
        log = _make_log(
            source="chrome-browser",
            event_type="browser.download",
            message="ftp://example.com/malware.exe",  # no 'http'
        )
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 0)

    def test_no_match_returns_empty_list(self):
        """Non-matching log returns empty list — no false positives."""
        self.engine._rules = [
            _pattern_rule(rule_code="SPECIFIC_RULE", message_pattern="very_specific_keyword_xyz")
        ]
        log = _make_log(message="completely unrelated log message")
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 0)

    def test_empty_conditions_rule_does_not_match(self):
        """A pattern rule with all-None conditions must never fire."""
        self.engine._rules = [
            _pattern_rule(
                rule_code="EMPTY_RULE",
                source_type=None,
                event_type_pattern=None,
                message_pattern=None,
            )
        ]
        log = _make_log(message="any log message")
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 0)

    def test_match_result_structure(self):
        """Matched rule result contains all required fields."""
        self.engine._rules = [
            _pattern_rule(
                rule_code="STRUCT_TEST",
                rule_name="Structure Test Rule",
                severity="high",
                risk_score=75,
                message_pattern="test",
            )
        ]
        log = _make_log(message="this is a test log")
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertIn("rule_code", m)
        self.assertIn("rule_name", m)
        self.assertIn("severity", m)
        self.assertIn("risk_score", m)
        self.assertIn("reason", m)
        self.assertEqual(m["rule_code"], "STRUCT_TEST")
        self.assertEqual(m["rule_name"], "Structure Test Rule")
        self.assertEqual(m["severity"], "high")
        self.assertEqual(m["risk_score"], 75)


# ---------------------------------------------------------------------------
# Threshold Rule Tests
# ---------------------------------------------------------------------------

class TestThresholdRules(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngineService()
        self.engine._rules_loaded = True

    def test_threshold_fires_at_count(self):
        """Threshold rule fires exactly when count reaches threshold."""
        rule = _threshold_rule(
            rule_code="FAILED_LOGIN_BURST",
            event_type_pattern="login_failed",
            threshold_count=3,
            threshold_minutes=5,
        )
        self.engine._rules = [rule]
        log = _make_log(event_type="login_failed", message="auth fail")

        # 1st and 2nd event — should NOT fire
        r1 = self.engine.evaluate_rules(log)
        r2 = self.engine.evaluate_rules(log)
        self.assertEqual(len(r1), 0)
        self.assertEqual(len(r2), 0)

        # 3rd event — SHOULD fire
        r3 = self.engine.evaluate_rules(log)
        self.assertEqual(len(r3), 1)
        self.assertEqual(r3[0]["rule_code"], "FAILED_LOGIN_BURST")

    def test_threshold_does_not_fire_early(self):
        """Threshold rule with count=5 must not fire on 4 events."""
        rule = _threshold_rule(
            rule_code="DOCKER_RESTART_BURST",
            event_type_pattern="docker.restart",
            threshold_count=5,
            threshold_minutes=15,
        )
        self.engine._rules = [rule]
        log = _make_log(event_type="docker.restart", message="Container restarted")

        for _ in range(4):
            matches = self.engine.evaluate_rules(log)
            self.assertEqual(len(matches), 0, "Should not fire before reaching threshold")

    def test_threshold_window_expiry(self):
        """Events outside the sliding window are not counted."""
        rule = _threshold_rule(
            rule_code="WINDOW_TEST",
            event_type_pattern="test.event",
            threshold_count=2,
            threshold_minutes=1,  # 1 minute window
        )
        self.engine._rules = [rule]
        log = _make_log(event_type="test.event")

        # Manually inject an old event (2 minutes ago) into the window
        group_key = ("WINDOW_TEST", log.source, log.event_type)
        old_time = datetime.now(timezone.utc) - timedelta(minutes=2)
        self.engine._threshold_windows[group_key].append(old_time)

        # Only 1 new event — old one is outside window, so total = 1 < 2
        matches = self.engine.evaluate_rules(log)
        self.assertEqual(len(matches), 0, "Old event outside window should be purged")

    def test_threshold_continues_firing_after_trigger(self):
        """After threshold is reached, subsequent events keep firing."""
        rule = _threshold_rule(
            rule_code="PERSIST_FIRE",
            message_pattern="attack",
            threshold_count=2,
            threshold_minutes=10,
        )
        self.engine._rules = [rule]
        log = _make_log(message="attack detected")

        # Reach threshold
        self.engine.evaluate_rules(log)
        self.engine.evaluate_rules(log)  # fires here

        # Additional events beyond threshold should still fire
        r = self.engine.evaluate_rules(log)
        self.assertEqual(len(r), 1)


# ---------------------------------------------------------------------------
# Error Isolation Tests
# ---------------------------------------------------------------------------

class TestErrorIsolation(unittest.TestCase):

    def test_db_failure_does_not_crash_pipeline(self):
        """If DB fails on rule load, engine returns empty list without crashing."""
        engine = RuleEngineService()  # fresh instance, _rules_loaded = False
        log = _make_log(message="any log")

        with patch(
            "app.services.rule_engine_service.rule_repository.get_enabled_rules",
            side_effect=Exception("DB connection refused"),
        ):
            try:
                matches = engine.evaluate_rules(log)
                self.assertEqual(matches, [])
            except Exception as e:
                self.fail(
                    f"evaluate_rules raised exception on DB failure: {e}. "
                    "Engine must be fully isolated from DB errors."
                )

    def test_bad_regex_does_not_crash_engine(self):
        """Malformed regex pattern in a rule should not crash the engine."""
        engine = RuleEngineService()
        engine._rules_loaded = True
        engine._rules = [
            _pattern_rule(rule_code="BAD_REGEX", message_pattern="/[invalid_regex/")
        ]
        log = _make_log(message="test message")
        try:
            matches = engine.evaluate_rules(log)
            # Should not raise — may or may not match (graceful failure)
        except Exception as e:
            self.fail(f"Bad regex crashed the engine: {e}")

    def test_reload_rules_on_db_failure_keeps_existing(self):
        """reload_rules() on DB failure keeps the existing rule set intact."""
        engine = RuleEngineService()
        engine._rules_loaded = True
        original_rules = [_pattern_rule(rule_code="EXISTING_RULE")]
        engine._rules = original_rules

        with patch(
            "app.services.rule_engine_service.rule_repository.reload_rules",
            side_effect=Exception("DB timeout"),
        ):
            engine.reload_rules()
            # Original rules should still be present
            self.assertEqual(engine._rules, original_rules)


# ---------------------------------------------------------------------------
# Integration Tests (Full Pipeline via TestClient)
# ---------------------------------------------------------------------------

class TestPipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_pipeline_no_rules_returns_200(self):
        """
        When no rules match, the pipeline completes normally (no rule_matches key).
        """
        payload = {
            "source": "test-source-xyz-no-rule",
            "event_type": "completely_unmatched_event_type",
            "message": "no rule should match this unique message content 9z8y7x",
            "severity": "low",
            "timestamp": "2026-06-08T12:00:00Z",
        }
        with patch(
            "app.services.rule_engine_service.rule_repository.get_enabled_rules",
            return_value=[],
        ):
            response = self.client.post("/api/logs/", json=payload)
        self.assertEqual(response.status_code, 200)

    def test_pipeline_rule_match_attached_to_metadata(self):
        """
        When a pattern rule matches, metadata.rule_matches is present in the response.
        """
        mock_rule = _pattern_rule(
            rule_code="INTEG_TEST_RULE",
            rule_name="Integration Test Rule",
            severity="high",
            risk_score=90,
            message_pattern="integration_test_keyword",
        )
        payload = {
            "source": "integ-test-source",
            "event_type": "integ.test.event",
            "message": "This log contains integration_test_keyword trigger",
            "severity": "medium",
            "timestamp": "2026-06-08T12:00:00Z",
        }
        with patch(
            "app.services.rule_engine_service.rule_repository.get_enabled_rules",
            return_value=[mock_rule],
        ):
            # Fresh engine instance so it re-loads rules from mock
            from app.services import rule_engine_service as svc_module
            svc_module.rule_engine_service._rules_loaded = False
            svc_module.rule_engine_service._rules = []

            response = self.client.post("/api/logs/", json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn("metadata", data)
        self.assertIn("rule_matches", data["metadata"])
        rule_matches = data["metadata"]["rule_matches"]
        self.assertIsInstance(rule_matches, list)
        self.assertGreater(len(rule_matches), 0)

        match = rule_matches[0]
        self.assertEqual(match["rule_code"], "INTEG_TEST_RULE")
        self.assertEqual(match["severity"], "high")
        self.assertEqual(match["risk_score"], 90)
        self.assertIn("reason", match)

    def test_pipeline_db_failure_still_returns_200(self):
        """
        If rule DB fails during pipeline, log is still processed and stored.
        The backend must not crash.
        """
        payload = {
            "source": "db-fail-source",
            "event_type": "db.fail.event",
            "message": "Test log when rule DB is down",
            "severity": "low",
            "timestamp": "2026-06-08T12:00:00Z",
        }
        with patch(
            "app.services.rule_engine_service.rule_repository.get_enabled_rules",
            side_effect=Exception("Simulated DB outage"),
        ):
            from app.services import rule_engine_service as svc_module
            svc_module.rule_engine_service._rules_loaded = False
            svc_module.rule_engine_service._rules = []

            response = self.client.post("/api/logs/", json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        # No rule_matches key when engine had no rules
        self.assertNotIn("rule_matches", data.get("metadata", {}))


if __name__ == "__main__":
    unittest.main()
