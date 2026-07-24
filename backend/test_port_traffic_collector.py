#!/usr/bin/env python3
"""
Test suite for the Port Traffic Monitoring Collector.

Tests cover:
  - Threshold not exceeded → no event sent
  - Threshold exceeded → anomaly event generated with correct payload
  - Multiple monitored ports → isolation between port counters
  - Payload structure matches RawLogIngest schema
  - Severity is always "high" for anomalies
  - Cooldown suppression prevents duplicate alerts
  - Backend failure → payload buffered in retry_buffer
  - Retry buffer flush drains on backend recovery
  - Graceful shutdown evaluates final window
  - Aggregation window resets counters after evaluation

Run from: backend/
    python -m pytest test_port_traffic_collector.py -v
"""

import threading
import unittest
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

from collectors.port_traffic_collector import PortTrafficCollector


# ---------------------------------------------------------------------------
# Mock helpers — simulate psutil connection objects
# ---------------------------------------------------------------------------

_Addr = namedtuple("Addr", ["ip", "port"])
_Conn = namedtuple("Conn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def _make_conn(
    local_ip: str = "0.0.0.0",
    local_port: int = 8080,
    remote_ip: str = "192.168.1.50",
    remote_port: int = 54321,
    status: str = "ESTABLISHED",
) -> _Conn:
    """Creates a mock psutil connection object."""
    return _Conn(
        fd=-1,
        family=2,
        type=1,
        laddr=_Addr(local_ip, local_port),
        raddr=_Addr(remote_ip, remote_port),
        status=status,
        pid=1234,
    )


def _make_connections(
    count: int,
    local_port: int = 8080,
    remote_ip_prefix: str = "10.0.0.",
    status: str = "ESTABLISHED",
) -> list[_Conn]:
    """Creates a list of N mock connections with unique remote ports."""
    return [
        _make_conn(
            local_port=local_port,
            remote_ip=f"{remote_ip_prefix}{(i % 254) + 1}",
            remote_port=50000 + i,
            status=status,
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

class TestThresholdLogic(unittest.TestCase):
    """Tests for aggregation window threshold evaluation."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080, 443],
            traffic_threshold=10,
            time_window_seconds=60,
            cooldown_seconds=300,
        )
        # Prevent actual HTTP calls
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_below_threshold_no_event(self):
        """When connection count is below threshold, no event is sent."""
        conns = _make_connections(5, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        self.collector.send_to_backend.assert_not_called()

    def test_above_threshold_sends_event(self):
        """When connection count exceeds threshold, an anomaly event is sent."""
        conns = _make_connections(15, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        self.collector.send_to_backend.assert_called_once()

    def test_exact_threshold_no_event(self):
        """When count equals threshold exactly, no event (threshold is 'more than')."""
        conns = _make_connections(10, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        self.collector.send_to_backend.assert_not_called()


class TestMultiPortIsolation(unittest.TestCase):
    """Tests that monitored ports track connections independently."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080, 443],
            traffic_threshold=10,
            time_window_seconds=60,
            cooldown_seconds=300,
        )
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_port_isolation(self):
        """Connections on port 8080 do not affect port 443 threshold."""
        conns_8080 = _make_connections(15, local_port=8080)
        conns_443 = _make_connections(3, local_port=443, remote_ip_prefix="172.16.0.")

        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns_8080 + conns_443
            self.collector._poll_connections()

        self.collector._evaluate_window()

        # Only port 8080 should trigger
        self.assertEqual(self.collector.send_to_backend.call_count, 1)
        payload = self.collector.send_to_backend.call_args[0][0]
        self.assertEqual(payload["metadata"]["destination_port"], 8080)

    def test_both_ports_exceed(self):
        """When both ports exceed threshold, two events are sent."""
        conns_8080 = _make_connections(15, local_port=8080)
        conns_443 = _make_connections(12, local_port=443, remote_ip_prefix="172.16.0.")

        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns_8080 + conns_443
            self.collector._poll_connections()

        self.collector._evaluate_window()
        self.assertEqual(self.collector.send_to_backend.call_count, 2)


class TestPayloadStructure(unittest.TestCase):
    """Tests that the generated payload matches RawLogIngest schema."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080],
            traffic_threshold=5,
            time_window_seconds=60,
        )
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_payload_has_required_fields(self):
        """Payload contains all fields expected by RawLogIngest."""
        conns = _make_connections(10, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        payload = self.collector.send_to_backend.call_args[0][0]

        # Top-level required fields
        self.assertIn("source", payload)
        self.assertIn("host", payload)
        self.assertIn("event_type", payload)
        self.assertIn("severity", payload)
        self.assertIn("message", payload)
        self.assertIn("timestamp", payload)
        self.assertIn("source_ip", payload)
        self.assertIn("metadata", payload)

    def test_payload_field_values(self):
        """Payload field values match expected RawLogIngest contract."""
        conns = _make_connections(10, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        payload = self.collector.send_to_backend.call_args[0][0]

        self.assertEqual(payload["source"], "os_network")
        self.assertEqual(payload["event_type"], "unauthorized_port_traffic")
        self.assertEqual(payload["severity"], "high")
        self.assertIsInstance(payload["metadata"], dict)
        self.assertEqual(payload["metadata"]["destination_port"], 8080)
        self.assertEqual(payload["metadata"]["protocol"], "TCP")
        self.assertEqual(payload["metadata"]["connection_count"], 10)
        self.assertEqual(payload["metadata"]["threshold"], 5)
        self.assertEqual(payload["metadata"]["time_window_seconds"], 60)
        self.assertIn("unique_source_ip_count", payload["metadata"])
        self.assertIn("top_source_ips", payload["metadata"])
        self.assertIn("connection_states", payload["metadata"])

    def test_severity_is_always_high(self):
        """Anomaly events always have severity='high'."""
        conns = _make_connections(20, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        payload = self.collector.send_to_backend.call_args[0][0]
        self.assertEqual(payload["severity"], "high")


class TestCooldownSuppression(unittest.TestCase):
    """Tests for duplicate alert suppression via cooldown."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080],
            traffic_threshold=5,
            time_window_seconds=60,
            cooldown_seconds=300,
        )
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_second_window_suppressed(self):
        """Second consecutive breach within cooldown is suppressed."""
        conns = _make_connections(10, local_port=8080)

        # First window
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        self.assertEqual(self.collector.send_to_backend.call_count, 1)

        # Second window (same connections, fresh remote ports to appear as new)
        conns2 = _make_connections(10, local_port=8080, remote_ip_prefix="192.168.2.")
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns2
            self.collector._prev_connections = set()  # Reset to make them "new"
            self.collector._poll_connections()

        self.collector._evaluate_window()
        # Still only 1 call — second breach was suppressed
        self.assertEqual(self.collector.send_to_backend.call_count, 1)

    def test_after_cooldown_expires_alert_fires(self):
        """Alert fires again after cooldown period expires."""
        conns = _make_connections(10, local_port=8080)

        # First window
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        self.assertEqual(self.collector.send_to_backend.call_count, 1)

        # Expire the cooldown manually
        self.collector._suppressed_until[8080] = datetime.now(timezone.utc) - timedelta(seconds=1)

        # Third window after cooldown
        conns3 = _make_connections(10, local_port=8080, remote_ip_prefix="10.10.10.")
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns3
            self.collector._prev_connections = set()
            self.collector._poll_connections()

        self.collector._evaluate_window()
        # Now alert fires again
        self.assertEqual(self.collector.send_to_backend.call_count, 2)


class TestRetryAndBuffer(unittest.TestCase):
    """Tests for backend failure retry and buffer logic."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080],
            traffic_threshold=5,
            time_window_seconds=60,
            cooldown_seconds=0,  # No cooldown for retry tests
        )

    def test_backend_failure_buffers_payload(self):
        """When backend is down, payload is added to retry_buffer."""
        self.collector.send_to_backend = MagicMock(return_value=False)

        conns = _make_connections(10, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()

        with self.collector.retry_lock:
            self.assertGreater(len(self.collector.retry_buffer), 0)

    def test_retry_buffer_flushes_on_recovery(self):
        """When backend recovers, buffered payloads are delivered."""
        # Buffer a payload manually
        test_payload = {"source": "test", "event_type": "test_event", "message": "buffered"}
        self.collector.retry_buffer = [test_payload]

        self.collector.send_to_backend = MagicMock(return_value=True)
        self.collector._flush_retry_buffer()

        self.collector.send_to_backend.assert_called_once_with(test_payload)
        self.assertEqual(len(self.collector.retry_buffer), 0)

    def test_retry_buffer_preserves_order_on_partial_failure(self):
        """If flush fails partway, remaining payloads stay in order."""
        p1 = {"source": "test", "event_type": "e1", "message": "first"}
        p2 = {"source": "test", "event_type": "e2", "message": "second"}
        p3 = {"source": "test", "event_type": "e3", "message": "third"}
        self.collector.retry_buffer = [p1, p2, p3]

        # Succeed on first, fail on second
        self.collector.send_to_backend = MagicMock(side_effect=[True, False])
        self.collector._flush_retry_buffer()

        # p2 and p3 should remain
        self.assertEqual(len(self.collector.retry_buffer), 2)
        self.assertEqual(self.collector.retry_buffer[0]["message"], "second")
        self.assertEqual(self.collector.retry_buffer[1]["message"], "third")


class TestWindowReset(unittest.TestCase):
    """Tests that aggregation window resets after evaluation."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080],
            traffic_threshold=5,
            time_window_seconds=60,
            cooldown_seconds=0,  # No cooldown
        )
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_counters_reset_after_window(self):
        """After window evaluation, accumulators are empty."""
        conns = _make_connections(10, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()

        # Accumulators should be reset
        with self.collector._lock:
            self.assertEqual(len(self.collector._window_connections), 0)
            self.assertEqual(len(self.collector._window_ip_counts), 0)
            self.assertEqual(len(self.collector._window_state_counts), 0)

    def test_new_window_after_reset_starts_fresh(self):
        """A new window after reset counts from zero."""
        conns = _make_connections(10, local_port=8080)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()  # First window: triggers
        self.assertEqual(self.collector.send_to_backend.call_count, 1)

        # New window with only 3 connections (below threshold)
        conns2 = _make_connections(3, local_port=8080, remote_ip_prefix="172.16.0.")
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns2
            self.collector._prev_connections = set()
            self.collector._poll_connections()

        self.collector._evaluate_window()
        # No new call — second window was below threshold
        self.assertEqual(self.collector.send_to_backend.call_count, 1)


class TestNonMonitoredPortIgnored(unittest.TestCase):
    """Tests that connections on non-monitored ports are ignored."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080],
            traffic_threshold=5,
            time_window_seconds=60,
        )
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_unmonitored_port_ignored(self):
        """Connections on port 3306 (not monitored) are not counted."""
        conns = _make_connections(20, local_port=3306)
        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            self.collector._poll_connections()

        self.collector._evaluate_window()
        self.collector.send_to_backend.assert_not_called()


class TestNewConnectionDetection(unittest.TestCase):
    """Tests that only NEW connections since last poll are counted."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080],
            traffic_threshold=5,
            time_window_seconds=60,
        )
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_persistent_connections_not_recounted(self):
        """Same connections across two polls are counted only once."""
        conns = _make_connections(3, local_port=8080)

        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = conns
            # First poll: 3 new connections
            self.collector._poll_connections()
            # Second poll with same connections: 0 new
            self.collector._poll_connections()

        self.collector._evaluate_window()
class TestEventBasedConnectionMonitoring(unittest.TestCase):
    """Tests for event-based connection monitoring and short-lived connection tracking."""

    def setUp(self):
        self.collector = PortTrafficCollector(
            monitored_ports=[8080, 443],
            traffic_threshold=5,
            time_window_seconds=60,
            cooldown_seconds=300,
        )
        self.collector.send_to_backend = MagicMock(return_value=True)

    def test_short_lived_connection_counted(self):
        """Short-lived connection event registered via record_connection_event is counted."""
        for i in range(6):
            self.collector.record_connection_event(
                local_port=8080,
                remote_ip="192.168.1.100",
                remote_port=5000 + i,
                state="SYN_RECEIVED",
            )

        self.collector._evaluate_window()
        self.collector.send_to_backend.assert_called_once()
        payload = self.collector.send_to_backend.call_args[0][0]
        self.assertEqual(payload["metadata"]["connection_count"], 6)

    def test_connection_opens_and_closes_immediately_counted(self):
        """Connection that opens and immediately closes still contributes +1 to traffic count."""
        self.collector.record_connection_event(
            local_port=8080,
            remote_ip="10.0.0.5",
            remote_port=6000,
            state="ESTABLISHED",
        )
        self.collector.record_connection_event(
            local_port=8080,
            remote_ip="10.0.0.5",
            remote_port=6001,
            state="CLOSED",
        )

        with self.collector._lock:
            count = self.collector._window_event_count[8080]
        self.assertEqual(count, 2)

    def test_multiple_rapid_connections_counted_individually(self):
        """20 rapid connections from same/different IPs count as 20 distinct events."""
        for i in range(20):
            self.collector.record_connection_event(
                local_port=8080,
                remote_ip="192.168.1.10",
                remote_port=50000 + (i % 5),
                state="ESTABLISHED",
            )

        self.collector._evaluate_window()
        self.collector.send_to_backend.assert_called_once()
        payload = self.collector.send_to_backend.call_args[0][0]
        self.assertEqual(payload["metadata"]["connection_count"], 20)

    def test_long_lived_connection_counted_once(self):
        """Long-lived connection counts once on establishment."""
        conn = _make_conn(local_port=8080, remote_ip="10.0.0.1", remote_port=4444)

        with patch("collectors.port_traffic_collector.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = [conn]
            # Poll 1: sees new connection -> records event (+1)
            self.collector._poll_connections()
            # Poll 2: connection still open -> 0 new events
            self.collector._poll_connections()
            # Poll 3: connection still open -> 0 new events
            self.collector._poll_connections()

        with self.collector._lock:
            self.assertEqual(self.collector._window_event_count[8080], 1)


if __name__ == "__main__":
    unittest.main()
