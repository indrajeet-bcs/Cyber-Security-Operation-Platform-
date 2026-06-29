"""
Test suite for the Notification & Escalation Engine.
"""

from datetime import datetime, timezone, timedelta
import unittest
import unittest.mock
import uuid

from app.database import alert_repository, notification_repository
from app.database.connection import get_connection
from app.core.config import settings
from app.services.notification_engine_service import notification_engine_service
from app.services.notification_metrics_service import notification_metrics_service

class TestNotificationEngine(unittest.TestCase):
    def setUp(self):
        # Temporarily clear settings user/password to force simulation mode by default
        self.original_smtp_user = settings.smtp_user
        self.original_smtp_password = settings.smtp_password
        settings.smtp_user = ""
        settings.smtp_password = ""

        self.created_notification_ids = []
        self.created_alert_ids = []
        
        # Test identifiers
        self.severity = "high"
        self.role = "test_responder"
        self.escalation_role_1 = "test_responder_l1"
        self.escalation_role_2 = "test_responder_l2"
        self.test_policy_name = f"Test Policy {uuid.uuid4().hex[:8]}"
        self.test_recipient_name = f"Test Recipient {uuid.uuid4().hex[:8]}"
        self.test_rec_email = f"test_email_{uuid.uuid4().hex[:8]}@example.com"
        
        # Fixed deterministic time outside quiet hours: 12:00 PM
        self.now = datetime(2026, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        
        # Insert temporary test policy
        policy_sql = """
            INSERT INTO notification_policies (
                policy_name, severity, initial_role, escalation_role, escalation_minutes,
                second_escalation_role, second_escalation_minutes, is_active, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, %s)
            RETURNING id
        """
        
        # Insert temporary test recipient
        recipient_sql = """
            INSERT INTO notification_recipients (
                recipient_name, email, role, team, phone, slack_channel, is_active, created_at, updated_at
            ) VALUES (%s, %s, %s, 'Incident Response', '12345', '#alerts', TRUE, %s, %s)
            RETURNING id
        """
        
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Deactivate any existing policies for 'high' and 'critical' severity to avoid conflicts
            cursor.execute(
                "UPDATE notification_policies SET is_active = FALSE WHERE severity IN ('high', 'critical') AND is_active = TRUE RETURNING id"
            )
            self.deactivated_policy_ids = [r[0] for r in cursor.fetchall()]
            
            # Policy with 1 min and 2 min escalations
            cursor.execute(policy_sql, (self.test_policy_name, self.severity, self.role, self.escalation_role_1, 1, self.escalation_role_2, 2, self.now))
            self.policy_db_id = cursor.fetchone()[0]
            
            # Also insert a critical policy for quiet hours test
            cursor.execute(policy_sql, (f"Test Critical Policy {uuid.uuid4().hex[:8]}", "critical", self.role, self.escalation_role_1, 1, self.escalation_role_2, 2, self.now))
            self.critical_policy_db_id = cursor.fetchone()[0]
            
            # Recipients
            cursor.execute(recipient_sql, (self.test_recipient_name, self.test_rec_email, self.role, self.now, self.now))
            self.rec_db_id = cursor.fetchone()[0]
            
            cursor.execute(recipient_sql, ("L1 Recipient", "l1@example.com", self.escalation_role_1, self.now, self.now))
            self.l1_rec_db_id = cursor.fetchone()[0]
            
            cursor.execute(recipient_sql, ("L2 Recipient", "l2@example.com", self.escalation_role_2, self.now, self.now))
            self.l2_rec_db_id = cursor.fetchone()[0]
            
        # Reset simulate channel success dictionary
        notification_engine_service.simulate_channel_success = {
            "Email": True,
            "Teams": True,
            "Slack": True,
            "Webhook": True,
            "PagerDuty": True
        }

    def tearDown(self):
        # Clean up database records created during test execution
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Delete test policies and recipients
            cursor.execute("DELETE FROM notification_policies WHERE id = %s", (self.policy_db_id,))
            cursor.execute("DELETE FROM notification_policies WHERE id = %s", (self.critical_policy_db_id,))
            cursor.execute("DELETE FROM notification_recipients WHERE id IN (%s, %s, %s)", (self.rec_db_id, self.l1_rec_db_id, self.l2_rec_db_id))
            
            # Re-activate any policies we deactivated
            if self.deactivated_policy_ids:
                placeholder = ', '.join(['%s'] * len(self.deactivated_policy_ids))
                cursor.execute(f"UPDATE notification_policies SET is_active = TRUE WHERE id IN ({placeholder})", tuple(self.deactivated_policy_ids))
            
            # Clean up history entries, escalations and notifications
            if self.created_notification_ids:
                placeholder = ', '.join(['%s'] * len(self.created_notification_ids))
                cursor.execute(f"DELETE FROM notification_history WHERE notification_id IN ({placeholder})", tuple(self.created_notification_ids))
                cursor.execute(f"DELETE FROM notification_escalations WHERE notification_id IN ({placeholder})", tuple(self.created_notification_ids))
                cursor.execute(f"DELETE FROM notifications WHERE notification_id IN ({placeholder})", tuple(self.created_notification_ids))
                
            # Clean up alerts
            if self.created_alert_ids:
                placeholder = ', '.join(['%s'] * len(self.created_alert_ids))
                cursor.execute(f"DELETE FROM alerts WHERE alert_id IN ({placeholder})", tuple(self.created_alert_ids))

        # Restore original settings
        settings.smtp_user = self.original_smtp_user
        settings.smtp_password = self.original_smtp_password

    def _create_mock_alert(self, severity="high") -> dict:
        alert_id = f"ALT-TEST-{uuid.uuid4().hex[:8].upper()}"
        alert_fingerprint = f"test-fingerprint-{uuid.uuid4().hex[:8]}"
        
        record_id = alert_repository.create_alert(
            alert_id=alert_id,
            alert_title="Test Alert Title",
            alert_type="detection",
            severity=severity,
            priority="P2" if severity == "high" else "P1",
            confidence=80,
            risk_score=50,
            status="open",
            occurrence_count=1,
            source="test",
            source_ip="1.1.1.1",
            host="test-host",
            username="testuser",
            event_fingerprint=None,
            alert_fingerprint=alert_fingerprint,
            rule_matches=[],
            correlation_matches=[]
        )
        self.created_alert_ids.append(alert_id)
        
        return {
            "id": record_id,
            "alert_id": alert_id,
            "alert_fingerprint": alert_fingerprint,
            "severity": severity,
            "status": "open"
        }

    def test_notification_status_transitions(self):
        alert = self._create_mock_alert()
        # Ingest and create notification
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.assertIsNotNone(notif)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Delivered should be the current status (since immediate routing succeeded)
        self.assertEqual(notif["status"], "delivered")
        
        # Test invalid transition (delivered -> pending should fail)
        with self.assertRaises(ValueError):
            notification_engine_service.update_notification_status(notif["notification_id"], "pending")
            
        # Test valid transition (delivered -> acknowledged)
        notification_engine_service.update_notification_status(notif["notification_id"], "acknowledged")
        notif_updated = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_updated["status"], "acknowledged")

    def test_notification_deduplication(self):
        alert = self._create_mock_alert()
        # First alert processing creates notification
        notif1 = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif1["notification_id"])
        
        self.assertEqual(notif1["occurrence_count"], 1)
        self.assertEqual(notif1["status"], "delivered")

        # Second identical alert processed immediately
        notif2 = notification_engine_service.process_alert(alert, now=self.now)
        self.assertEqual(notif2["notification_id"], notif1["notification_id"])
        self.assertEqual(notif2["occurrence_count"], 2)
        self.assertEqual(notif2["status"], "suppressed")

    def test_suppression_window(self):
        alert = self._create_mock_alert()
        
        # Process and create notification
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Simulate duplicate processing after suppression window has expired
        future_time = self.now + timedelta(minutes=6)
        notif_after_window = notification_engine_service.process_alert(alert, now=future_time)
        
        # It should trigger a NEW notification (different ID) since window has expired
        self.assertNotEqual(notif_after_window["notification_id"], notif["notification_id"])
        self.created_notification_ids.append(notif_after_window["notification_id"])
        self.assertEqual(notif_after_window["occurrence_count"], 1)
        self.assertEqual(notif_after_window["status"], "delivered")

    def test_escalation_stopped_on_alert_ack(self):
        alert = self._create_mock_alert()
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Verify escalation not stopped yet
        self.assertFalse(notification_engine_service.is_escalation_stopped(notif))
        
        # Acknowledge the alert
        alert_repository.acknowledge_alert(alert["alert_id"])
        
        # Verify escalation is now stopped
        self.assertTrue(notification_engine_service.is_escalation_stopped(notif))

    def test_escalation_stopped_on_alert_resolved(self):
        alert = self._create_mock_alert()
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Resolve the alert
        alert_repository.resolve_alert(alert["alert_id"])
        
        # Verify escalation is now stopped
        self.assertTrue(notification_engine_service.is_escalation_stopped(notif))

    def test_channel_failover(self):
        alert = self._create_mock_alert()
        
        # Force Email to fail
        notification_engine_service.simulate_channel_success["Email"] = False
        
        # Process alert, should failover to Teams and succeed
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        self.assertEqual(notif["status"], "delivered")
        self.assertEqual(notif["delivery_status"], "delivered_via_teams")
        
        # Check channel_used column if it exists in DB schema
        if "channel_used" in notif:
            self.assertEqual(notif["channel_used"], "Teams")

        # Force Email, Teams, Slack, Webhook, and PagerDuty to fail
        for chan in notification_engine_service.simulate_channel_success:
            notification_engine_service.simulate_channel_success[chan] = False
            
        # Create a new alert and process it
        alert2 = self._create_mock_alert()
        notif_failed = notification_engine_service.process_alert(alert2, now=self.now)
        self.created_notification_ids.append(notif_failed["notification_id"])
        
        self.assertEqual(notif_failed["status"], "failed")
        self.assertEqual(notif_failed["delivery_status"], "all_channels_failed")

    def test_metrics_updates(self):
        metrics_before = notification_metrics_service.get_notification_metrics()
        
        # Trigger delivered notification
        alert = self._create_mock_alert()
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Trigger suppressed notification
        notification_engine_service.process_alert(alert, now=self.now)
        
        # Force failures
        for chan in notification_engine_service.simulate_channel_success:
            notification_engine_service.simulate_channel_success[chan] = False
        alert2 = self._create_mock_alert()
        notif_failed = notification_engine_service.process_alert(alert2, now=self.now)
        self.created_notification_ids.append(notif_failed["notification_id"])
        
        metrics_after = notification_metrics_service.get_notification_metrics()
        
        self.assertEqual(metrics_after["total_sent"], metrics_before["total_sent"] + 1)
        self.assertEqual(metrics_after["total_suppressed"], metrics_before["total_suppressed"] + 1)
        self.assertEqual(metrics_after["total_failed"], metrics_before["total_failed"] + 1)

    def test_quiet_hours_suppression(self):
        alert = self._create_mock_alert(severity="high")
        
        # Simulate time in quiet hours (11:00 PM / 23:00)
        quiet_time = datetime(2026, 6, 12, 23, 0, 0, tzinfo=timezone.utc)
        notif = notification_engine_service.process_alert(alert, now=quiet_time)
        self.created_notification_ids.append(notif["notification_id"])
        
        # High severity alert should be suppressed during quiet hours
        self.assertEqual(notif["status"], "suppressed")
        
        # Critical severity alert should bypass quiet hours
        alert_critical = self._create_mock_alert(severity="critical")
        notif_critical = notification_engine_service.process_alert(alert_critical, now=quiet_time)
        self.created_notification_ids.append(notif_critical["notification_id"])
        
        self.assertEqual(notif_critical["status"], "delivered")

    def test_escalation_level_tracking(self):
        alert = self._create_mock_alert()
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Initially at level 0
        self.assertEqual(notif.get("escalation_level", 0), 0)
        
        # Check escalations immediately (should do nothing since 1 minute threshold not reached)
        notification_engine_service.check_and_trigger_escalations(now=self.now)
        notif_after_immediate = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_after_immediate.get("escalation_level", 0), 0)
        
        # Trigger Level 1 escalation (+1.5 minutes)
        l1_time = self.now + timedelta(minutes=1, seconds=30)
        notification_engine_service.check_and_trigger_escalations(now=l1_time)
        notif_l1 = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_l1.get("escalation_level", 0), 1)
        self.assertEqual(notif_l1["status"], "escalated")
        
        # Trigger Level 2 escalation (+2.5 minutes)
        l2_time = self.now + timedelta(minutes=2, seconds=30)
        notification_engine_service.check_and_trigger_escalations(now=l2_time)
        notif_l2 = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_l2.get("escalation_level", 0), 2)
        
        # Try triggering escalations again (+5 minutes), should stay at Level 2
        future_time = self.now + timedelta(minutes=5)
        notification_engine_service.check_and_trigger_escalations(now=future_time)
        notif_final = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_final.get("escalation_level", 0), 2)

    def test_investigating_to_resolved_transition(self):
        alert = self._create_mock_alert()
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Transition: delivered -> acknowledged -> investigating -> resolved
        notification_engine_service.update_notification_status(notif["notification_id"], "acknowledged")
        notification_engine_service.update_notification_status(notif["notification_id"], "investigating")
        notification_engine_service.update_notification_status(notif["notification_id"], "resolved")
        
        notif_resolved = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_resolved["status"], "resolved")

    def test_resolved_to_closed_transition(self):
        alert = self._create_mock_alert()
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Transition: delivered -> acknowledged -> investigating -> resolved -> closed
        notification_engine_service.update_notification_status(notif["notification_id"], "acknowledged")
        notification_engine_service.update_notification_status(notif["notification_id"], "investigating")
        notification_engine_service.update_notification_status(notif["notification_id"], "resolved")
        notification_engine_service.update_notification_status(notif["notification_id"], "closed")
        
        notif_closed = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_closed["status"], "closed")

    def test_dispatch_email_simulation_mode(self):
        # By default, SMTP is unconfigured because of placeholder values.
        # Ensure it falls back to simulation mode and returns the simulate_channel_success value.
        recipient = {"email": "test@example.com"}
        
        notification_engine_service.simulate_channel_success["Email"] = True
        self.assertTrue(notification_engine_service._dispatch_email(recipient, "Test Subject", "Test Body"))
        
        notification_engine_service.simulate_channel_success["Email"] = False
        self.assertFalse(notification_engine_service._dispatch_email(recipient, "Test Subject", "Test Body"))

    @unittest.mock.patch("app.services.notification_engine_service.settings")
    @unittest.mock.patch("smtplib.SMTP")
    def test_dispatch_email_configured_success(self, mock_smtp_class, mock_settings):
        # Configure SMTP settings using mocks
        mock_settings.smtp_host = "smtp.test.com"
        mock_settings.smtp_port = 587
        mock_settings.smtp_user = "test_user@test.com"
        mock_settings.smtp_password = "secure_password"
        mock_settings.smtp_from_email = "alerts@test.com"
        mock_settings.smtp_use_tls = True
        
        mock_smtp_instance = unittest.mock.MagicMock()
        mock_smtp_class.return_value = mock_smtp_instance
        
        recipient = {"email": "recipient@test.com"}
        result = notification_engine_service._dispatch_email(recipient, "Subject", "Body")
        
        self.assertTrue(result)
        mock_smtp_class.assert_called_once_with("smtp.test.com", 587)
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with("test_user@test.com", "secure_password")
        mock_smtp_instance.sendmail.assert_called_once()
        mock_smtp_instance.quit.assert_called_once()

    @unittest.mock.patch("app.services.notification_engine_service.settings")
    @unittest.mock.patch("smtplib.SMTP_SSL")
    def test_dispatch_email_smtp_ssl_success(self, mock_smtp_ssl_class, mock_settings):
        mock_settings.smtp_host = "smtp.test.com"
        mock_settings.smtp_port = 465
        mock_settings.smtp_user = "test_user@test.com"
        mock_settings.smtp_password = "secure_password"
        mock_settings.smtp_from_email = "alerts@test.com"
        mock_settings.smtp_use_tls = False
        
        mock_smtp_ssl_instance = unittest.mock.MagicMock()
        mock_smtp_ssl_class.return_value = mock_smtp_ssl_instance
        
        recipient = {"email": "recipient@test.com"}
        result = notification_engine_service._dispatch_email(recipient, "Subject", "Body")
        
        self.assertTrue(result)
        mock_smtp_ssl_class.assert_called_once_with("smtp.test.com", 465)
        mock_smtp_ssl_instance.login.assert_called_once_with("test_user@test.com", "secure_password")
        mock_smtp_ssl_instance.sendmail.assert_called_once()
        mock_smtp_ssl_instance.quit.assert_called_once()

    @unittest.mock.patch("app.services.notification_engine_service.settings")
    @unittest.mock.patch("smtplib.SMTP")
    def test_dispatch_email_smtp_auth_error(self, mock_smtp_class, mock_settings):
        import smtplib
        mock_settings.smtp_host = "smtp.test.com"
        mock_settings.smtp_port = 587
        mock_settings.smtp_user = "test_user@test.com"
        mock_settings.smtp_password = "secure_password"
        mock_settings.smtp_from_email = "alerts@test.com"
        mock_settings.smtp_use_tls = True
        
        mock_smtp_instance = unittest.mock.MagicMock()
        mock_smtp_class.return_value = mock_smtp_instance
        mock_smtp_instance.login.side_effect = smtplib.SMTPAuthenticationError(535, "Auth failed")
        
        recipient = {"email": "recipient@test.com"}
        result = notification_engine_service._dispatch_email(recipient, "Subject", "Body")
        
        self.assertFalse(result)

    def test_suppressed_notification_escalation(self):
        alert = self._create_mock_alert()
        # First alert makes status delivered
        notif1 = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif1["notification_id"])
        self.assertEqual(notif1["status"], "delivered")

        # Second alert within 5 mins suppresses it
        notif2 = notification_engine_service.process_alert(alert, now=self.now)
        self.assertEqual(notif2["status"], "suppressed")
        self.assertEqual(notif2["occurrence_count"], 2)

        # Check that it is returned as active for escalation query
        active_notifs = notification_repository.get_active_notifications_for_escalation()
        active_ids = [n["notification_id"] for n in active_notifs]
        self.assertIn(notif1["notification_id"], active_ids)

        # Trigger Level 1 escalation (+1.5 minutes)
        l1_time = self.now + timedelta(minutes=1, seconds=30)
        notification_engine_service.check_and_trigger_escalations(now=l1_time)
        
        # Verify status is now escalated and level is 1
        notif_esc = notification_repository.get_notification_by_id(notif1["notification_id"])
        self.assertEqual(notif_esc["status"], "escalated")
        self.assertEqual(notif_esc.get("escalation_level", 0), 1)

    def test_escalation_tz_naive_comparison(self):
        alert = self._create_mock_alert()
        notif = notification_engine_service.process_alert(alert, now=self.now)
        self.created_notification_ids.append(notif["notification_id"])
        
        # Manually force created_at to be a naive datetime in the database
        naive_dt = datetime(2026, 6, 12, 12, 0, 0) # naive
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE notifications SET created_at = %s WHERE notification_id = %s",
                (naive_dt, notif["notification_id"])
            )
            
        # Verify timezone naive comparison doesn't raise TypeError and escalates correctly
        l1_time = self.now + timedelta(minutes=1, seconds=30) # aware
        # This will not crash because check_and_trigger_escalations converts both to UTC aware
        notification_engine_service.check_and_trigger_escalations(now=l1_time)
        
        notif_esc = notification_repository.get_notification_by_id(notif["notification_id"])
        self.assertEqual(notif_esc["status"], "escalated")
        self.assertEqual(notif_esc.get("escalation_level", 0), 1)

if __name__ == "__main__":
    unittest.main()
