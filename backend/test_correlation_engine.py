"""
Test suite for the Advanced Real-Time Correlation Engine.

Tests cover:
  - Event fingerprint generation (deterministic SHA256)
  - Cache operations (insertion, expiry, purge)
  - Failed Login Burst detection
  - Brute Force Success detection
  - Multi-Host Attack detection
  - Reconnaissance Activity detection
  - High-Risk Rule Chain detection
  - Browser → Download → Execution chain detection
  - Docker Attack Pattern detection
  - Risk Score Escalation detection
  - Failure isolation (detector crash, DB failure)
  - Output format validation
  - End-to-end pipeline integration

Run from: d:\\Componies Work\\Bestowal System Work\\soc_platform\\backend
    python -m pytest test_correlation_engine.py -v
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
from app.services.correlation_service import CorrelationService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_log(
    source="test-source",
    event_type="test.event",
    message="test message",
    severity=Severity.low,
    source_ip=None,
    user=None,
    host=None,
    metadata=None,
) -> NormalizedSOCLog:
    """Creates a minimal NormalizedSOCLog for testing."""
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


def _inject_event(engine: CorrelationService, snapshot: dict) -> None:
    """Directly injects an event snapshot into all caches (bypasses correlate)."""
    with engine._lock:
        engine._index_event(snapshot)


def _make_snapshot(
    event_type="test.event",
    user=None,
    source_ip=None,
    host=None,
    source="test-source",
    severity="low",
    rule_matches=None,
    risk_score=0,
    timestamp=None,
    fingerprint="abc123",
    log_type=None,
) -> dict:
    """Creates a cache event snapshot dict for testing."""
    return {
        "timestamp": timestamp or datetime.now(timezone.utc),
        "event_type": event_type,
        "host": host,
        "source": source,
        "user": user,
        "source_ip": source_ip,
        "severity": severity,
        "rule_matches": rule_matches or [],
        "risk_score": risk_score,
        "event_fingerprint": fingerprint,
        "log_type": log_type,
    }


# ---------------------------------------------------------------------------
# Fingerprint Tests
# ---------------------------------------------------------------------------

class TestEventFingerprint(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fingerprint_deterministic(self):
        """Same fields always produce the same SHA256 fingerprint."""
        log = _make_log(
            source="windows", host="server-01", event_type="login_failed",
            user="admin", source_ip="10.0.0.1"
        )
        fp1 = self.engine._generate_fingerprint(log)
        fp2 = self.engine._generate_fingerprint(log)
        self.assertEqual(fp1, fp2)

    def test_fingerprint_different_inputs(self):
        """Different fields produce different fingerprints."""
        log1 = _make_log(source="windows", host="server-01", event_type="login_failed",
                         user="admin", source_ip="10.0.0.1")
        log2 = _make_log(source="linux", host="server-02", event_type="login_success",
                         user="root", source_ip="192.168.1.1")
        fp1 = self.engine._generate_fingerprint(log1)
        fp2 = self.engine._generate_fingerprint(log2)
        self.assertNotEqual(fp1, fp2)

    def test_fingerprint_is_sha256(self):
        """Fingerprint is a valid 64-char hex SHA256 hash."""
        log = _make_log(source="test", event_type="test")
        fp = self.engine._generate_fingerprint(log)
        self.assertEqual(len(fp), 64)
        # Verify it's valid hex
        int(fp, 16)

    def test_fingerprint_handles_none_fields(self):
        """Fingerprint works gracefully when fields are None."""
        log = _make_log(source="test", event_type="test",
                        user=None, source_ip=None, host=None)
        fp = self.engine._generate_fingerprint(log)
        self.assertEqual(len(fp), 64)


# ---------------------------------------------------------------------------
# Cache Tests
# ---------------------------------------------------------------------------

class TestCacheOperations(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_event_indexed_into_user_cache(self):
        """Events with a user field are indexed into user_cache."""
        snapshot = _make_snapshot(user="admin")
        _inject_event(self.engine, snapshot)
        self.assertEqual(len(self.engine._user_cache["admin"]), 1)

    def test_event_indexed_into_ip_cache(self):
        """Events with a source_ip field are indexed into source_ip_cache."""
        snapshot = _make_snapshot(source_ip="10.0.0.1")
        _inject_event(self.engine, snapshot)
        self.assertEqual(len(self.engine._source_ip_cache["10.0.0.1"]), 1)

    def test_event_indexed_into_host_cache(self):
        """Events with a host field are indexed into host_cache."""
        snapshot = _make_snapshot(host="server-01")
        _inject_event(self.engine, snapshot)
        self.assertEqual(len(self.engine._host_cache["server-01"]), 1)

    def test_stale_events_purged(self):
        """Events older than 24 hours are purged from caches."""
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)
        old_snapshot = _make_snapshot(user="admin", timestamp=old_time)
        _inject_event(self.engine, old_snapshot)

        self.assertEqual(len(self.engine._user_cache["admin"]), 1)

        # Purge
        now = datetime.now(timezone.utc)
        with self.engine._lock:
            self.engine._purge_stale_entries(now)

        self.assertEqual(len(self.engine._user_cache.get("admin", deque())), 0)

    def test_recent_events_not_purged(self):
        """Events within 24 hours are NOT purged."""
        recent_time = datetime.now(timezone.utc) - timedelta(hours=1)
        snapshot = _make_snapshot(user="admin", timestamp=recent_time)
        _inject_event(self.engine, snapshot)

        now = datetime.now(timezone.utc)
        with self.engine._lock:
            self.engine._purge_stale_entries(now)

        self.assertEqual(len(self.engine._user_cache["admin"]), 1)

    def test_filter_window(self):
        """_filter_window correctly filters events within a time window."""
        now = datetime.now(timezone.utc)
        events = deque()
        events.append(_make_snapshot(timestamp=now - timedelta(minutes=10)))  # outside 5m
        events.append(_make_snapshot(timestamp=now - timedelta(minutes=3)))   # inside 5m
        events.append(_make_snapshot(timestamp=now - timedelta(minutes=1)))   # inside 5m

        result = self.engine._filter_window(events, now, timedelta(minutes=5))
        self.assertEqual(len(result), 2)


# ---------------------------------------------------------------------------
# Detector 1: Failed Login Burst
# ---------------------------------------------------------------------------

class TestFailedLoginBurst(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_on_more_than_5_failures(self):
        """Fires when >5 failed login events from same user+IP within 5 min."""
        now = datetime.now(timezone.utc)
        for i in range(6):
            snapshot = _make_snapshot(
                event_type="login_failed",
                user="admin",
                source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=30 * i),
            )
            _inject_event(self.engine, snapshot)

        # Trigger with the 7th event
        trigger = _make_snapshot(
            event_type="login_failed",
            user="admin",
            source_ip="10.0.0.1",
            timestamp=now,
        )
        _inject_event(self.engine, trigger)
        result = self.engine._detect_failed_login_burst(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "failed_login_burst")
        self.assertEqual(result["severity"], "high")

    def test_does_not_fire_at_5_or_fewer(self):
        """Does NOT fire when exactly 5 failed login events."""
        now = datetime.now(timezone.utc)
        for i in range(5):
            snapshot = _make_snapshot(
                event_type="login_failed",
                user="admin",
                source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=30 * i),
            )
            _inject_event(self.engine, snapshot)

        trigger = _make_snapshot(
            event_type="login_failed",
            user="admin",
            source_ip="10.0.0.1",
            timestamp=now,
        )
        result = self.engine._detect_failed_login_burst(trigger, now)
        self.assertIsNone(result)

    def test_does_not_fire_on_non_login_event(self):
        """Does NOT fire for non-login events."""
        now = datetime.now(timezone.utc)
        trigger = _make_snapshot(event_type="file_access", user="admin", source_ip="10.0.0.1")
        result = self.engine._detect_failed_login_burst(trigger, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Detector 2: Brute Force Success
# ---------------------------------------------------------------------------

class TestBruteForceSuccess(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_on_failed_then_success(self):
        """Fires when >=3 failed logins followed by a successful login within 10 min."""
        now = datetime.now(timezone.utc)
        # Inject 3 failed logins
        for i in range(3):
            snapshot = _make_snapshot(
                event_type="login_failed",
                user="victim",
                source_ip="10.0.0.5",
                timestamp=now - timedelta(minutes=5 - i),
            )
            _inject_event(self.engine, snapshot)

        # Trigger with successful login
        trigger = _make_snapshot(
            event_type="login_success",
            user="victim",
            source_ip="10.0.0.5",
            timestamp=now,
        )
        _inject_event(self.engine, trigger)
        result = self.engine._detect_brute_force_success(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "brute_force_success")
        self.assertEqual(result["severity"], "critical")

    def test_does_not_fire_without_prior_failures(self):
        """Does NOT fire on successful login without prior failures."""
        now = datetime.now(timezone.utc)
        trigger = _make_snapshot(
            event_type="login_success",
            user="clean_user",
            source_ip="10.0.0.5",
            timestamp=now,
        )
        _inject_event(self.engine, trigger)
        result = self.engine._detect_brute_force_success(trigger, now)
        self.assertIsNone(result)

    def test_does_not_fire_on_failed_login(self):
        """Does NOT fire on a failed login event (only triggers on success)."""
        now = datetime.now(timezone.utc)
        trigger = _make_snapshot(
            event_type="login_failed",
            user="victim",
            source_ip="10.0.0.5",
            timestamp=now,
        )
        result = self.engine._detect_brute_force_success(trigger, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Detector 3: Multi-Host Attack
# ---------------------------------------------------------------------------

class TestMultiHostAttack(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_on_3_distinct_hosts(self):
        """Fires when same IP contacts ≥3 distinct hosts within 15 min."""
        now = datetime.now(timezone.utc)
        for host in ["host-1", "host-2", "host-3"]:
            snapshot = _make_snapshot(
                source_ip="192.168.1.100",
                host=host,
                timestamp=now - timedelta(minutes=5),
            )
            _inject_event(self.engine, snapshot)

        trigger = _make_snapshot(
            source_ip="192.168.1.100",
            host="host-3",
            timestamp=now,
        )
        result = self.engine._detect_multi_host_attack(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "multi_host_attack")
        self.assertEqual(result["severity"], "high")

    def test_does_not_fire_on_2_hosts(self):
        """Does NOT fire when same IP contacts only 2 distinct hosts."""
        now = datetime.now(timezone.utc)
        for host in ["host-1", "host-2"]:
            snapshot = _make_snapshot(
                source_ip="192.168.1.100",
                host=host,
                timestamp=now - timedelta(minutes=5),
            )
            _inject_event(self.engine, snapshot)

        trigger = _make_snapshot(
            source_ip="192.168.1.100",
            host="host-2",
            timestamp=now,
        )
        result = self.engine._detect_multi_host_attack(trigger, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Detector 4: Reconnaissance Activity
# ---------------------------------------------------------------------------

class TestReconnaissance(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_on_3_categories(self):
        """Fires when same IP generates ≥3 distinct event categories in 10 min."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(event_type="dns_query", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=5)),
            _make_snapshot(event_type="http_request", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=4)),
            _make_snapshot(event_type="login_attempt", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=3)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(
            event_type="login_attempt", source_ip="10.0.0.99", timestamp=now
        )
        result = self.engine._detect_reconnaissance(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "reconnaissance_activity")

    def test_fires_high_on_4_categories(self):
        """Fires with severity=high when all 4 categories present."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(event_type="dns_query", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=5)),
            _make_snapshot(event_type="http_request", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=4)),
            _make_snapshot(event_type="login_attempt", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=3)),
            _make_snapshot(event_type="container.start", source="docker",
                           source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=2)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(
            event_type="container.start", source="docker",
            source_ip="10.0.0.99", timestamp=now
        )
        result = self.engine._detect_reconnaissance(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "high")

    def test_does_not_fire_on_2_categories(self):
        """Does NOT fire when only 2 categories present."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(event_type="dns_query", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=5)),
            _make_snapshot(event_type="http_request", source_ip="10.0.0.99",
                           timestamp=now - timedelta(minutes=4)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(
            event_type="http_request", source_ip="10.0.0.99", timestamp=now
        )
        result = self.engine._detect_reconnaissance(trigger, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Detector 5: High-Risk Rule Chain
# ---------------------------------------------------------------------------

class TestHighRiskRuleChain(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_on_2_distinct_high_risk_rules(self):
        """Fires when ≥2 distinct high-risk rule_codes (risk>=50) in 15 min."""
        now = datetime.now(timezone.utc)
        # First event with rule match
        snap1 = _make_snapshot(
            source_ip="10.0.0.1",
            rule_matches=[{"rule_code": "SUSPICIOUS_PS", "risk_score": 80}],
            risk_score=80,
            timestamp=now - timedelta(minutes=10),
        )
        _inject_event(self.engine, snap1)

        # Second event with different rule match
        snap2 = _make_snapshot(
            source_ip="10.0.0.1",
            rule_matches=[{"rule_code": "ENCODED_PAYLOAD", "risk_score": 70}],
            risk_score=70,
            timestamp=now,
        )
        _inject_event(self.engine, snap2)

        result = self.engine._detect_high_risk_rule_chain(snap2, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "high_risk_rule_chain")
        self.assertEqual(result["severity"], "critical")

    def test_does_not_fire_on_single_rule(self):
        """Does NOT fire when only 1 distinct high-risk rule_code."""
        now = datetime.now(timezone.utc)
        snap = _make_snapshot(
            source_ip="10.0.0.1",
            rule_matches=[{"rule_code": "SUSPICIOUS_PS", "risk_score": 80}],
            risk_score=80,
            timestamp=now,
        )
        _inject_event(self.engine, snap)

        result = self.engine._detect_high_risk_rule_chain(snap, now)
        self.assertIsNone(result)

    def test_does_not_fire_on_low_risk_rules(self):
        """Does NOT fire when rules have risk_score < 50."""
        now = datetime.now(timezone.utc)
        snap1 = _make_snapshot(
            source_ip="10.0.0.1",
            rule_matches=[{"rule_code": "LOW_RULE_1", "risk_score": 30}],
            risk_score=30,
            timestamp=now - timedelta(minutes=5),
        )
        snap2 = _make_snapshot(
            source_ip="10.0.0.1",
            rule_matches=[{"rule_code": "LOW_RULE_2", "risk_score": 20}],
            risk_score=20,
            timestamp=now,
        )
        _inject_event(self.engine, snap1)
        _inject_event(self.engine, snap2)

        result = self.engine._detect_high_risk_rule_chain(snap2, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Detector 6: Browser → Download → Execution Chain
# ---------------------------------------------------------------------------

class TestBrowserDownloadExecChain(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_on_complete_chain(self):
        """Fires when search → download → process execution for same user in 30 min."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(event_type="browser.search", user="victim",
                           timestamp=now - timedelta(minutes=20)),
            _make_snapshot(event_type="browser.download", user="victim",
                           timestamp=now - timedelta(minutes=10)),
            _make_snapshot(event_type="process.start", user="victim",
                           timestamp=now - timedelta(minutes=2)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(event_type="process.start", user="victim", timestamp=now)
        _inject_event(self.engine, trigger)
        result = self.engine._detect_browser_download_exec(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "browser_download_execution_chain")
        self.assertEqual(result["severity"], "critical")

    def test_does_not_fire_on_partial_chain(self):
        """Does NOT fire when chain is incomplete (search + download, no execution)."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(event_type="browser.search", user="victim",
                           timestamp=now - timedelta(minutes=20)),
            _make_snapshot(event_type="browser.download", user="victim",
                           timestamp=now - timedelta(minutes=10)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(event_type="browser.download", user="victim", timestamp=now)
        result = self.engine._detect_browser_download_exec(trigger, now)
        self.assertIsNone(result)

    def test_does_not_fire_without_user(self):
        """Does NOT fire when user is None."""
        now = datetime.now(timezone.utc)
        trigger = _make_snapshot(event_type="browser.search", user=None, timestamp=now)
        result = self.engine._detect_browser_download_exec(trigger, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Detector 7: Docker Attack Pattern
# ---------------------------------------------------------------------------

class TestDockerAttackPattern(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_on_restart_stop_create(self):
        """Fires on container restart + stop + create on same host within 10 min."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(event_type="container.restart", source="docker",
                           host="docker-host-01",
                           timestamp=now - timedelta(minutes=8)),
            _make_snapshot(event_type="container.stop", source="docker",
                           host="docker-host-01",
                           timestamp=now - timedelta(minutes=5)),
            _make_snapshot(event_type="container.create", source="docker",
                           host="docker-host-01",
                           timestamp=now - timedelta(minutes=2)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(
            event_type="container.create", source="docker",
            host="docker-host-01", timestamp=now,
        )
        _inject_event(self.engine, trigger)
        result = self.engine._detect_docker_attack_pattern(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "docker_attack_pattern")
        self.assertEqual(result["severity"], "high")

    def test_does_not_fire_on_partial_pattern(self):
        """Does NOT fire when only restart + stop (missing create)."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(event_type="container.restart", source="docker",
                           host="docker-host-01",
                           timestamp=now - timedelta(minutes=8)),
            _make_snapshot(event_type="container.stop", source="docker",
                           host="docker-host-01",
                           timestamp=now - timedelta(minutes=5)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(
            event_type="container.stop", source="docker",
            host="docker-host-01", timestamp=now,
        )
        result = self.engine._detect_docker_attack_pattern(trigger, now)
        self.assertIsNone(result)

    def test_does_not_fire_on_non_docker_event(self):
        """Does NOT fire on non-Docker events."""
        now = datetime.now(timezone.utc)
        trigger = _make_snapshot(
            event_type="file.access", source="windows",
            host="server-01", timestamp=now,
        )
        result = self.engine._detect_docker_attack_pattern(trigger, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Detector 8: Risk Score Escalation
# ---------------------------------------------------------------------------

class TestRiskScoreEscalation(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationService()

    def test_fires_at_cumulative_100(self):
        """Fires when cumulative risk_score >= 100 within 1 hour."""
        now = datetime.now(timezone.utc)
        # Inject events with risk scores summing to 110
        events = [
            _make_snapshot(source_ip="10.0.0.1", risk_score=40,
                           rule_matches=[{"rule_code": "R1", "risk_score": 40}],
                           timestamp=now - timedelta(minutes=30)),
            _make_snapshot(source_ip="10.0.0.1", risk_score=35,
                           rule_matches=[{"rule_code": "R2", "risk_score": 35}],
                           timestamp=now - timedelta(minutes=20)),
            _make_snapshot(source_ip="10.0.0.1", risk_score=35,
                           rule_matches=[{"rule_code": "R3", "risk_score": 35}],
                           timestamp=now - timedelta(minutes=10)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(
            source_ip="10.0.0.1", risk_score=35,
            rule_matches=[{"rule_code": "R3", "risk_score": 35}],
            timestamp=now,
        )
        _inject_event(self.engine, trigger)
        result = self.engine._detect_risk_score_escalation(trigger, now)
        self.assertIsNotNone(result)
        self.assertEqual(result["correlation_type"], "risk_score_escalation")
        self.assertEqual(result["severity"], "critical")

    def test_does_not_fire_below_100(self):
        """Does NOT fire when cumulative risk_score < 100."""
        now = datetime.now(timezone.utc)
        events = [
            _make_snapshot(source_ip="10.0.0.1", risk_score=30,
                           rule_matches=[{"rule_code": "R1", "risk_score": 30}],
                           timestamp=now - timedelta(minutes=30)),
            _make_snapshot(source_ip="10.0.0.1", risk_score=20,
                           rule_matches=[{"rule_code": "R2", "risk_score": 20}],
                           timestamp=now - timedelta(minutes=20)),
        ]
        for e in events:
            _inject_event(self.engine, e)

        trigger = _make_snapshot(
            source_ip="10.0.0.1", risk_score=20,
            rule_matches=[{"rule_code": "R2", "risk_score": 20}],
            timestamp=now,
        )
        result = self.engine._detect_risk_score_escalation(trigger, now)
        self.assertIsNone(result)

    def test_does_not_fire_without_rule_matches(self):
        """Does NOT fire when no rule_matches present."""
        now = datetime.now(timezone.utc)
        trigger = _make_snapshot(source_ip="10.0.0.1", risk_score=0, rule_matches=[])
        result = self.engine._detect_risk_score_escalation(trigger, now)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Failure Isolation Tests
# ---------------------------------------------------------------------------

class TestFailureIsolation(unittest.TestCase):

    def test_correlate_never_raises(self):
        """correlate() must NEVER raise — even if a detector crashes."""
        engine = CorrelationService()
        log = _make_log(source="test", event_type="test.event", message="test")

        # Patch a detector to throw
        with patch.object(
            engine, "_detect_failed_login_burst",
            side_effect=RuntimeError("Simulated detector crash"),
        ):
            try:
                result = engine.correlate(log)
                self.assertIsInstance(result, list)
            except Exception as e:
                self.fail(
                    f"correlate() raised exception: {e}. "
                    "Correlation must be fully isolated from pipeline."
                )

    def test_db_write_failure_does_not_crash(self):
        """Database write failure on background thread does not crash correlate()."""
        engine = CorrelationService()

        with patch(
            "app.services.correlation_service.correlation_repository.insert_correlation_event",
            side_effect=Exception("DB connection refused"),
        ):
            # Inject enough events to trigger a correlation
            now = datetime.now(timezone.utc)
            for i in range(7):
                snapshot = _make_snapshot(
                    event_type="login_failed",
                    user="admin",
                    source_ip="10.0.0.1",
                    timestamp=now - timedelta(seconds=30 * i),
                )
                _inject_event(engine, snapshot)

            log = _make_log(
                source="test",
                event_type="login_failed",
                message="failed login",
                user="admin",
                source_ip="10.0.0.1",
            )
            try:
                result = engine.correlate(log)
                self.assertIsInstance(result, list)
            except Exception as e:
                self.fail(
                    f"correlate() raised on DB failure: {e}. "
                    "DB errors must be isolated to background thread."
                )

    def test_all_detectors_fail_still_returns_empty(self):
        """If ALL detectors fail, correlate() returns [] without crashing."""
        engine = CorrelationService()

        for method_name in [
            "_detect_failed_login_burst",
            "_detect_brute_force_success",
            "_detect_multi_host_attack",
            "_detect_reconnaissance",
            "_detect_high_risk_rule_chain",
            "_detect_browser_download_exec",
            "_detect_docker_attack_pattern",
            "_detect_risk_score_escalation",
        ]:
            setattr(engine, method_name, MagicMock(side_effect=RuntimeError("boom")))

        log = _make_log(source="test", event_type="test.event", message="test")
        result = engine.correlate(log)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)


# ---------------------------------------------------------------------------
# Output Format Tests
# ---------------------------------------------------------------------------

class TestOutputFormat(unittest.TestCase):

    def test_match_contains_required_fields(self):
        """Correlation match dict contains all required output fields."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)

        # Trigger a failed login burst
        for i in range(7):
            snapshot = _make_snapshot(
                event_type="login_failed",
                user="admin",
                source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=30 * i),
            )
            _inject_event(engine, snapshot)

        trigger = _make_snapshot(
            event_type="login_failed", user="admin",
            source_ip="10.0.0.1", timestamp=now,
        )
        _inject_event(engine, trigger)
        result = engine._detect_failed_login_burst(trigger, now)

        self.assertIsNotNone(result)
        # Verify all required fields from the spec
        required_fields = [
            "correlation_id", "correlation_type", "severity",
            "confidence", "risk_score", "reason",
        ]
        for field in required_fields:
            self.assertIn(field, result, f"Missing field: {field}")

        # Verify types
        self.assertIsInstance(result["correlation_id"], str)
        self.assertIsInstance(result["correlation_type"], str)
        self.assertIsInstance(result["confidence"], int)
        self.assertIsInstance(result["risk_score"], int)


# ---------------------------------------------------------------------------
# Integration Tests (Full Pipeline via TestClient)
# ---------------------------------------------------------------------------

class TestPipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_pipeline_correlation_no_match_returns_200(self):
        """
        When no correlations fire, the pipeline completes normally.
        """
        payload = {
            "source": "integration-test-no-corr",
            "event_type": "completely_unique_event_type_xyz123",
            "message": "no correlation should match this",
            "severity": "low",
            "timestamp": "2026-06-08T12:00:00Z",
        }
        with patch(
            "app.services.rule_engine_service.rule_repository.get_enabled_rules",
            return_value=[],
        ):
            response = self.client.post("/api/logs/", json=payload)
        self.assertEqual(response.status_code, 200)

    def test_pipeline_correlation_failure_still_returns_200(self):
        """
        If the correlation engine crashes, the pipeline still processes
        the log and returns 200.
        """
        payload = {
            "source": "corr-fail-source",
            "event_type": "corr.fail.event",
            "message": "Test log when correlation engine crashes",
            "severity": "low",
            "timestamp": "2026-06-08T12:00:00Z",
        }
        with patch(
            "app.services.rule_engine_service.rule_repository.get_enabled_rules",
            return_value=[],
        ):
            with patch(
                "app.services.correlation_service.correlation_service.correlate",
                side_effect=RuntimeError("Simulated correlation crash"),
            ):
                response = self.client.post("/api/logs/", json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Correlation crash should NOT prevent log from being returned
        self.assertIn("id", data)

    def test_pipeline_preserves_rule_matches(self):
        """
        Rule Engine matches must still be present in metadata even when
        correlation engine runs.
        """
        mock_rule = {
            "id": 1,
            "rule_code": "CORR_INTEG_RULE",
            "rule_name": "Correlation Integration Rule",
            "rule_type": "pattern",
            "severity": "high",
            "source_type": None,
            "event_type_pattern": None,
            "message_pattern": "corr_integ_keyword",
            "threshold_count": None,
            "threshold_minutes": None,
            "risk_score": 90,
            "is_enabled": True,
            "created_by": "system",
            "created_at": None,
            "updated_at": None,
        }
        payload = {
            "source": "corr-integ-source",
            "event_type": "corr.integ.event",
            "message": "This log contains corr_integ_keyword trigger",
            "severity": "medium",
            "timestamp": "2026-06-08T12:00:00Z",
        }
        with patch(
            "app.services.rule_engine_service.rule_repository.get_enabled_rules",
            return_value=[mock_rule],
        ):
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
        self.assertEqual(rule_matches[0]["rule_code"], "CORR_INTEG_RULE")


# ---------------------------------------------------------------------------
# Suppression Tests
# ---------------------------------------------------------------------------

class TestCorrelationSuppression(unittest.TestCase):

    def test_first_detection_generates_event(self):
        """First detection inserts to DB and logs 'Correlation generated'."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)
        
        # Inject 6 failed logins for user 'admin' and IP '10.0.0.1' to meet threshold (>5)
        for i in range(6):
            snapshot = _make_snapshot(
                event_type="login_failed",
                user="admin",
                source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10),
            )
            _inject_event(engine, snapshot)
            
        trigger = _make_log(
            event_type="login_failed",
            user="admin",
            source_ip="10.0.0.1",
        )
        
        with patch.object(engine, "_persist_async") as mock_persist:
            matches = engine.correlate(trigger)
            self.assertEqual(len(matches), 1)
            mock_persist.assert_called_once()
            self.assertEqual(matches[0]["correlation_type"], "failed_login_burst")
            key = "failed_login_burst:admin:10.0.0.1"
            self.assertIn(key, engine._active_correlations)

    def test_duplicate_event_inside_window_is_suppressed(self):
        """Subsequent events inside window are suppressed (no DB insert)."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)
        
        # Inject failed logins
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin", source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10)
            ))
            
        # First correlation should generate
        trigger1 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches1 = engine.correlate(trigger1)
            self.assertEqual(len(matches1), 1)
            self.assertEqual(mock_persist.call_count, 1)
            
        # Second correlation immediately after should be suppressed
        trigger2 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches2 = engine.correlate(trigger2)
            self.assertEqual(len(matches2), 0)
            mock_persist.assert_not_called()

    def test_expired_window_allows_new_event(self):
        """Once window expires, active entry is removed, new event generated and logged as reactivated."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)
        
        # Inject failed logins
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin", source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10)
            ))
            
        trigger1 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches1 = engine.correlate(trigger1)
            self.assertEqual(len(matches1), 1)
            
        key = "failed_login_burst:admin:10.0.0.1"
        self.assertIn(key, engine._active_correlations)
        
        # Fast-forward active correlation key to be expired (e.g., 6 minutes ago)
        engine._active_correlations[key]["first_seen"] = now - timedelta(minutes=6)
        
        # Inject another failure to meet threshold in the new check
        _inject_event(engine, _make_snapshot(
            event_type="login_failed", user="admin", source_ip="10.0.0.1",
            timestamp=now
        ))
        
        trigger2 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches2 = engine.correlate(trigger2)
            self.assertEqual(len(matches2), 1)
            self.assertEqual(matches2[0]["correlation_type"], "failed_login_burst")
            mock_persist.assert_called_once()

    def test_different_user_creates_new_event(self):
        """A different user bypasses existing active correlation (new key allowed)."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)
        
        # Inject failed logins for user 'admin'
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin", source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10)
            ))
        trigger1 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async"):
            matches1 = engine.correlate(trigger1)
            self.assertEqual(len(matches1), 1)
            
        # Inject failed logins for user 'admin2'
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin2", source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10)
            ))
        trigger2 = _make_log(event_type="login_failed", user="admin2", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches2 = engine.correlate(trigger2)
            self.assertEqual(len(matches2), 1)
            self.assertEqual(matches2[0]["related_user"], "admin2")
            mock_persist.assert_called_once()

    def test_different_source_ip_creates_new_event(self):
        """A different source IP bypasses existing active correlation (new key allowed)."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)
        
        # Inject failed logins for user 'admin' on IP '10.0.0.1'
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin", source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10)
            ))
        trigger1 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async"):
            matches1 = engine.correlate(trigger1)
            self.assertEqual(len(matches1), 1)
            
        # Inject failed logins for user 'admin' on IP '10.0.0.2'
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin", source_ip="10.0.0.2",
                timestamp=now - timedelta(seconds=10)
            ))
        trigger2 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.2")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches2 = engine.correlate(trigger2)
            self.assertEqual(len(matches2), 1)
            self.assertEqual(matches2[0]["related_source_ip"], "10.0.0.2")
            mock_persist.assert_called_once()

    def test_suppression_survives_high_event_volume(self):
        """High event volume (100 events) does not cause leak/flooding, updating event counts inside window."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)
        
        # Inject initial failed logins
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin", source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10)
            ))
            
        # First correlation should generate
        trigger1 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches1 = engine.correlate(trigger1)
            self.assertEqual(len(matches1), 1)
            
        # Send 100 duplicate events
        with patch.object(engine, "_persist_async") as mock_persist:
            for _ in range(100):
                log = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
                _inject_event(engine, _make_snapshot(
                    event_type="login_failed", user="admin", source_ip="10.0.0.1",
                    timestamp=now
                ))
                matches = engine.correlate(log)
                self.assertEqual(len(matches), 0)
            
            mock_persist.assert_not_called()
            
        key = "failed_login_burst:admin:10.0.0.1"
        self.assertGreater(engine._active_correlations[key]["event_count"], 6)

    def test_closed_status_allows_new_event(self):
        """Closing status in-memory allows a new correlation event to fire immediately."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)
        
        # Inject failed logins
        for i in range(6):
            _inject_event(engine, _make_snapshot(
                event_type="login_failed", user="admin", source_ip="10.0.0.1",
                timestamp=now - timedelta(seconds=10)
            ))
            
        trigger1 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches1 = engine.correlate(trigger1)
            self.assertEqual(len(matches1), 1)
            
        key = "failed_login_burst:admin:10.0.0.1"
        self.assertIn(key, engine._active_correlations)
        
        # Mark status as closed/reset
        engine._active_correlations[key]["correlation_status"] = "closed"
        
        # Inject another failure
        _inject_event(engine, _make_snapshot(
            event_type="login_failed", user="admin", source_ip="10.0.0.1",
            timestamp=now
        ))
        
        # Now trigger again, it should allow new event
        trigger2 = _make_log(event_type="login_failed", user="admin", source_ip="10.0.0.1")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches2 = engine.correlate(trigger2)
            self.assertEqual(len(matches2), 1)
            self.assertEqual(matches2[0]["correlation_type"], "failed_login_burst")
            mock_persist.assert_called_once()

    def test_existing_detectors_continue_working(self):
        """Verify other correlation detectors trigger normally when distinct activities occur."""
        engine = CorrelationService()
        now = datetime.now(timezone.utc)

        # Let's test Docker Attack Pattern detection through correlate pipeline
        # Needs stop + restart + create on host within 10 min
        events = [
            _make_log(source="docker", event_type="container.restart", host="docker-01"),
            _make_log(source="docker", event_type="container.stop", host="docker-01"),
        ]
        for e in events:
            with patch.object(engine, "_persist_async"):
                engine.correlate(e)

        trigger = _make_log(source="docker", event_type="container.create", host="docker-01")
        with patch.object(engine, "_persist_async") as mock_persist:
            matches = engine.correlate(trigger)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["correlation_type"], "docker_attack_pattern")
            mock_persist.assert_called_once()


if __name__ == "__main__":
    unittest.main()
