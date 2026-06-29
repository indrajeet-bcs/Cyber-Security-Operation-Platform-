"""
Test suite for the Incident Management and Dashboard APIs.
"""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import incident_repository, alert_repository
from app.database.connection import get_connection
from app.services.incident_service import incident_service

class TestIncidents(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.created_incident_ids = []
        self.created_alert_ids = []

    def tearDown(self):
        # Clean up database records created during test execution
        with get_connection() as conn:
            cursor = conn.cursor()
            if self.created_incident_ids:
                placeholder = ', '.join(['%s'] * len(self.created_incident_ids))
                cursor.execute(f"DELETE FROM incidents WHERE incident_id IN ({placeholder})", tuple(self.created_incident_ids))
            if self.created_alert_ids:
                placeholder = ', '.join(['%s'] * len(self.created_alert_ids))
                cursor.execute(f"DELETE FROM alerts WHERE id IN ({placeholder})", tuple(self.created_alert_ids))

    def _create_test_incident(self, title="Test Incident", severity="medium") -> dict:
        incident = incident_service.create_incident(
            alert_id=None,
            title=title,
            severity=severity
        )
        self.created_incident_ids.append(incident["incident_id"])
        return incident

    def test_incident_repository_crud(self):
        # 1. Create incident via repository
        inc_id = f"INC-TEST-{uuid.uuid4().hex[:8].upper()}"
        record_id = incident_repository.create_incident(
            incident_id=inc_id,
            alert_id=None,
            title="Repo CRUD Test",
            severity="low",
            status="open"
        )
        self.created_incident_ids.append(inc_id)
        self.assertTrue(record_id > 0)

        # 2. Get incident
        inc = incident_repository.get_incident(inc_id)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["title"], "Repo CRUD Test")
        self.assertEqual(inc["severity"], "low")
        self.assertEqual(inc["status"], "open")

        # 3. List incidents
        incidents = incident_repository.list_incidents(status="open")
        found = any(i["incident_id"] == inc_id for i in incidents)
        self.assertTrue(found)

    def test_lifecycle_transitions(self):
        # Transition path: open -> acknowledged -> investigating -> closed
        incident = self._create_test_incident()
        inc_id = incident["incident_id"]

        self.assertEqual(incident["status"], "open")
        self.assertIsNone(incident["acknowledged_at"])
        self.assertIsNone(incident["investigating_at"])
        self.assertIsNone(incident["closed_at"])

        # 1. Open -> Acknowledged
        acknowledged_inc = incident_service.acknowledge_incident(inc_id)
        self.assertEqual(acknowledged_inc["status"], "acknowledged")
        self.assertIsNotNone(acknowledged_inc["acknowledged_at"])

        # 2. Acknowledged -> Investigating
        investigating_inc = incident_service.assign_incident(inc_id, "shubham", "SOC_L1")
        self.assertEqual(investigating_inc["status"], "investigating")
        self.assertIsNotNone(investigating_inc["investigating_at"])
        self.assertEqual(investigating_inc["assigned_to"], "shubham")

        # 3. Investigating -> Closed
        closed_inc = incident_service.close_incident(inc_id)
        self.assertEqual(closed_inc["status"], "closed")
        self.assertIsNotNone(closed_inc["closed_at"])

    def test_invalid_transitions(self):
        incident = self._create_test_incident()
        inc_id = incident["incident_id"]

        # Attempt to transition open -> investigating directly should fail
        with self.assertRaises(ValueError):
            incident_service.validate_transition(incident["status"], "investigating")

        # Attempt to transition open -> closed directly should fail
        with self.assertRaises(ValueError):
            incident_service.validate_transition(incident["status"], "closed")

        # Progress to acknowledged
        incident_service.acknowledge_incident(inc_id)
        incident = incident_repository.get_incident(inc_id)

        # Attempt to transition acknowledged -> closed directly should fail
        with self.assertRaises(ValueError):
            incident_service.validate_transition(incident["status"], "closed")

        # Progress to investigating
        incident_service.assign_incident(inc_id, "shubham", "SOC_L1")
        incident = incident_repository.get_incident(inc_id)

        # Attempt to transition investigating -> open should fail
        with self.assertRaises(ValueError):
            incident_service.validate_transition(incident["status"], "open")

        # Close the incident
        incident_service.close_incident(inc_id)
        incident = incident_repository.get_incident(inc_id)

        # Attempt to transition closed -> open should fail
        with self.assertRaises(ValueError):
            incident_service.validate_transition(incident["status"], "open")

    def test_ownership_and_auto_investigation(self):
        # A new incident is created with status="open"
        incident = self._create_test_incident(title="Ownership Incident", severity="critical")
        inc_id = incident["incident_id"]

        # Call assign_incident - triggers automatic transition to investigating
        assigned_inc = incident_service.assign_incident(inc_id, "shubham", "SOC_L1")
        
        self.assertEqual(assigned_inc["assigned_to"], "shubham")
        self.assertEqual(assigned_inc["assigned_role"], "SOC_L1")
        self.assertEqual(assigned_inc["status"], "investigating")
        self.assertIsNotNone(assigned_inc["acknowledged_at"])
        self.assertIsNotNone(assigned_inc["investigating_at"])

        # Check assigning again does not crash or break status
        reassigned_inc = incident_service.assign_incident(inc_id, "aniket", "SOC_L2")
        self.assertEqual(reassigned_inc["assigned_to"], "aniket")
        self.assertEqual(reassigned_inc["assigned_role"], "SOC_L2")
        self.assertEqual(reassigned_inc["status"], "investigating") # stays investigating

    def test_auto_close(self):
        incident = self._create_test_incident()
        inc_id = incident["incident_id"]

        # Move to investigating via assignment
        incident_service.assign_incident(inc_id, "shubham", "SOC_L1")
        
        # Call close
        closed_inc = incident_service.close_incident(inc_id)
        self.assertEqual(closed_inc["status"], "closed")
        self.assertIsNotNone(closed_inc["closed_at"])

    def test_notes_appending(self):
        incident = self._create_test_incident()
        inc_id = incident["incident_id"]

        # Initial notes should be empty/None
        self.assertIsNone(incident["notes"])

        # 1. Append first note
        inc1 = incident_service.add_note(inc_id, "Checked PowerShell logs")
        self.assertEqual(inc1["notes"], "Checked PowerShell logs")

        # 2. Append second note - should append, not replace
        inc2 = incident_service.add_note(inc_id, "Blocked source IP")
        self.assertEqual(inc2["notes"], "Checked PowerShell logs\nBlocked source IP")

        # 3. Append third note
        inc3 = incident_service.add_note(inc_id, "Disabled compromised account")
        self.assertEqual(inc3["notes"], "Checked PowerShell logs\nBlocked source IP\nDisabled compromised account")

    def test_dashboard_summary(self):
        # Fetch current summary state to calculate diff
        before = incident_service.dashboard_summary()

        # Create one critical incident in open state
        self._create_test_incident(title="Critical Open", severity="critical")

        # Create one high incident in investigating state
        inc_high = self._create_test_incident(title="High Investigating", severity="high")
        incident_service.assign_incident(inc_high["incident_id"], "shubham", "SOC_L1")

        # Create one medium incident in closed state
        inc_med = self._create_test_incident(title="Medium Closed", severity="medium")
        incident_service.assign_incident(inc_med["incident_id"], "shubham", "SOC_L1")
        incident_service.close_incident(inc_med["incident_id"])

        # Fetch new summary
        after = incident_service.dashboard_summary()

        self.assertEqual(after["open_incidents"] - before["open_incidents"], 1)
        self.assertEqual(after["investigating_incidents"] - before["investigating_incidents"], 1)
        self.assertEqual(after["closed_incidents"] - before["closed_incidents"], 1)

        self.assertEqual(after["critical_incidents"] - before["critical_incidents"], 1)
        self.assertEqual(after["high_incidents"] - before["high_incidents"], 1)
        self.assertEqual(after["medium_incidents"] - before["medium_incidents"], 1)

    def test_api_endpoints(self):
        # Create incident for API testing
        incident = self._create_test_incident(title="API Test Incident", severity="high")
        inc_id = incident["incident_id"]

        # 1. GET /incidents
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        found = any(i["incident_id"] == inc_id for i in data)
        self.assertTrue(found)

        # 2. GET /incident/{incident_id}
        response = self.client.get(f"/api/incident/{inc_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["title"], "API Test Incident")

        # 3. GET /incident/{incident_id} not found
        response = self.client.get("/api/incident/INC-INVALID-ID")
        self.assertEqual(response.status_code, 404)

        # 4. POST /incident/{incident_id}/assign
        payload = {"assigned_to": "shubham", "assigned_role": "SOC_L1"}
        response = self.client.post(f"/api/incident/{inc_id}/assign", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "investigating")
        self.assertEqual(response.json()["assigned_to"], "shubham")

        # 5. POST /incident/{incident_id}/notes
        payload_note = {"note": "Checked PowerShell logs"}
        response = self.client.post(f"/api/incident/{inc_id}/notes", json=payload_note)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["notes"], "Checked PowerShell logs")

        # 6. POST /incident/{incident_id}/close
        response = self.client.post(f"/api/incident/{inc_id}/close")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "closed")

        # 7. Invalid transition via API (trying to assign a closed incident to trigger open -> investig. transition)
        # Wait, if we call assign on closed, status remains closed, which is fine, but trying to move closed to acknowledged should fail
        # Let's test transition validation failure by sending close again (closed -> closed is invalid)
        response = self.client.post(f"/api/incident/{inc_id}/close")
        self.assertEqual(response.status_code, 400)
        self.assertIn("detail", response.json())

        # 8. GET /dashboard/summary
        response = self.client.get("/api/dashboard/summary")
        self.assertEqual(response.status_code, 200)
        summary = response.json()
        self.assertIn("open_incidents", summary)
        self.assertIn("closed_incidents", summary)
        self.assertIn("critical_incidents", summary)

    def test_alert_auto_creates_incident(self):
        alert_id = f"ALT-TEST-{uuid.uuid4().hex[:8].upper()}"
        alert_fingerprint = f"test-incident-integration-{uuid.uuid4().hex[:8]}"
        
        record_id = alert_repository.create_alert(
            alert_id=alert_id,
            alert_title="Test Integration Alert",
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
            alert_fingerprint=alert_fingerprint,
            rule_matches=[],
            correlation_matches=[]
        )
        self.created_alert_ids.append(record_id)
        self.assertTrue(record_id > 0)

        # Retrieve incident linking to this alert
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE alert_id = %s", (record_id,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            inc = {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
            
            # Store the incident_id so it gets cleaned up in tearDown
            self.created_incident_ids.append(inc["incident_id"])
            
            self.assertEqual(inc["title"], "Test Integration Alert")
            self.assertEqual(inc["severity"], "high")
            self.assertEqual(inc["status"], "open")

if __name__ == "__main__":
    unittest.main()
