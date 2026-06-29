"""
Test suite for the Alert Engine and its lifecycle states.
"""

import unittest
from datetime import datetime, timezone
import hashlib
from app.database import alert_repository
from app.services.alert_engine_service import alert_engine_service
from app.schemas.log import NormalizedSOCLog, Severity, DetectionResult

class TestAlertEngine(unittest.TestCase):
    def setUp(self):
        self.test_fingerprint_1 = f"test-lifecycle-fingerprint-{datetime.now().timestamp()}"
        self.test_fingerprint_2 = f"test-resolve-fingerprint-{datetime.now().timestamp()}"

    def test_alert_lifecycle(self):
        # 1. Create alert
        record_id = alert_repository.create_alert(
            alert_id=f"ALT-{datetime.now().timestamp()}-TEST",
            alert_title="Test Lifecycle Alert",
            alert_type="detection",
            severity="high",
            priority="P2",
            confidence=80,
            risk_score=50,
            status="open",
            occurrence_count=1,
            source="test",
            source_ip="1.1.1.1",
            host="test-host",
            username="testuser",
            event_fingerprint=None,
            alert_fingerprint=self.test_fingerprint_1,
            rule_matches=[],
            correlation_matches=[]
        )
        self.assertTrue(record_id > 0)
        
        # Verify open
        alert = alert_repository.get_alert_by_fingerprint(self.test_fingerprint_1)
        self.assertEqual(alert["status"], "open")
        self.assertIsNone(alert["acknowledged_at"])
        self.assertIsNone(alert["resolved_at"])
        self.assertIsNone(alert["closed_at"])
 
        # 2. Acknowledge
        alert_repository.acknowledge_alert(record_id)
        alert = alert_repository.get_alert_by_fingerprint(self.test_fingerprint_1)
        self.assertEqual(alert["status"], "acknowledged")
        self.assertIsNotNone(alert["acknowledged_at"])
 
        # 3. Investigate
        alert_repository.investigate_alert(record_id)
        alert = alert_repository.get_alert_by_fingerprint(self.test_fingerprint_1)
        self.assertEqual(alert["status"], "investigating")
 
        # 4. Resolve
        alert_repository.resolve_alert(record_id)
        alert = alert_repository.get_alert_by_fingerprint(self.test_fingerprint_1)
        self.assertEqual(alert["status"], "resolved")
        self.assertIsNotNone(alert["resolved_at"])
 
        # 5. Close
        alert_repository.close_alert(record_id)
        alert = alert_repository.get_alert_by_fingerprint(self.test_fingerprint_1)
        self.assertEqual(alert["status"], "closed")
        self.assertIsNotNone(alert["closed_at"])
 
    def test_alert_resolve(self):
        record_id = alert_repository.create_alert(
            alert_id=f"ALT-{datetime.now().timestamp()}-TEST2",
            alert_title="Test Resolve Alert",
            alert_type="detection",
            severity="medium",
            priority="P3",
            confidence=80,
            risk_score=50,
            status="open",
            occurrence_count=1,
            source="test",
            source_ip="1.1.1.1",
            host="test-host",
            username="testuser",
            event_fingerprint=None,
            alert_fingerprint=self.test_fingerprint_2,
            rule_matches=[],
            correlation_matches=[]
        )
        alert_repository.resolve_alert(record_id)
        alert = alert_repository.get_alert_by_fingerprint(self.test_fingerprint_2)
        self.assertEqual(alert["status"], "resolved")
        self.assertIsNotNone(alert["resolved_at"])

    def test_alert_generation_service(self):
        log = NormalizedSOCLog(
            source=f"test-source-{datetime.now().timestamp()}",
            event_type="test-event",
            message="Test message",
            severity=Severity.high,
            timestamp=datetime.now(timezone.utc)
        )
        detection = DetectionResult(
            is_suspicious=True,
            severity=Severity.critical,
            reason="Test critical detection"
        )
        
        # Test alert generation
        alert = alert_engine_service.generate_alert(log, detection)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_type"], "detection")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["status"], "open")
        self.assertEqual(alert["occurrence_count"], 1)
        
        # Test deduplication
        alert2 = alert_engine_service.generate_alert(log, detection)
        self.assertEqual(alert2["id"], alert["id"])
        self.assertEqual(alert2["occurrence_count"], 2)

if __name__ == "__main__":
    unittest.main()
