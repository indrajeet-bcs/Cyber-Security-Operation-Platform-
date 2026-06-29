import unittest
import json
import hashlib
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.log import RawLogIngest
from app.services.log_type_detection_service import log_type_detection_service
from app.services.unknown_log_service import unknown_log_service
from app.database import unknown_log_repository
from app.database.connection import get_connection

class TestLogTypeDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Dynamically create the unknown_logs table if it doesn't exist for test isolation
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS unknown_logs (
                        id SERIAL PRIMARY KEY,
                        source VARCHAR(255),
                        raw_payload JSONB,
                        detected_format VARCHAR(50),
                        parser_confidence INTEGER,
                        classification_reason TEXT,
                        received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        collector_name VARCHAR(255),
                        unknown_hash VARCHAR(64) UNIQUE,
                        occurrence_count INTEGER DEFAULT 1,
                        log_type VARCHAR(50) DEFAULT 'unknown',
                        detection_confidence INTEGER,
                        first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                conn.commit()
                print("[TEST SETUP] Verified/created unknown_logs table in database.")
        except Exception as exc:
            print(f"[TEST WARNING] Failed to set up unknown_logs table: {exc}")

    def setUp(self):
        # Clean up database table before each test
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("TRUNCATE TABLE unknown_logs RESTART IDENTITY;")
                conn.commit()
        except Exception:
            pass
        self.client = TestClient(app)

    # -------------------------------------------------------------------------
    # UNIT TESTS: LogTypeDetectionService
    # -------------------------------------------------------------------------

    def test_windows_xml_classification(self):
        raw = RawLogIngest(
            source="windows-xml-collector",
            event_type="windows_raw",
            message="<Event><System><EventID>4624</EventID><Provider Name='Security'/></System></Event>",
            metadata={"event_id": "4624", "provider": "Security"}
        )
        parse_result = {
            "detected_format": "windows_xml",
            "payload": {
                "metadata": {
                    "event_id": "4624",
                    "provider": "Security"
                }
            }
        }
        
        res = log_type_detection_service.detect_log_type(raw, parse_result)
        
        self.assertEqual(res["log_type"], "windows_event")
        self.assertEqual(res["log_subtype"], "authentication")
        self.assertEqual(res["confidence"], 95)
        self.assertIn("Provider", res["classification_reason"])

    def test_chrome_browser_classification(self):
        raw = RawLogIngest(
            source="chrome-browser",
            event_type="browser.url_visit",
            message="https://google.com"
        )
        parse_result = {"detected_format": "text"}
        
        res = log_type_detection_service.detect_log_type(raw, parse_result)
        
        self.assertEqual(res["log_type"], "chrome_browser")
        self.assertEqual(res["log_subtype"], "url_visit")
        self.assertEqual(res["confidence"], 95)

    def test_docker_classification(self):
        # Docker Lifecycle Event
        raw_event = RawLogIngest(
            source="docker",
            event_type="docker.container_started",
            message="Started container test"
        )
        res_event = log_type_detection_service.detect_log_type(raw_event, {})
        self.assertEqual(res_event["log_type"], "docker_event")
        self.assertEqual(res_event["log_subtype"], "container_lifecycle")
        
        # Docker Container Log
        raw_log = RawLogIngest(
            source="docker",
            event_type="docker.stdout",
            message="Application log output"
        )
        res_log = log_type_detection_service.detect_log_type(raw_log, {})
        self.assertEqual(res_log["log_type"], "docker_container_log")
        self.assertEqual(res_log["log_subtype"], "stdout")

    def test_syslog_classification(self):
        raw = RawLogIngest(
            source="syslog-collector",
            event_type="syslog_raw",
            message="<34>Oct 1 su[1234]: Bad su attempt by user root"
        )
        parse_result = {"detected_format": "syslog"}
        
        res = log_type_detection_service.detect_log_type(raw, parse_result)
        
        self.assertEqual(res["log_type"], "syslog")
        self.assertEqual(res["log_subtype"], "authentication")
        self.assertEqual(res["confidence"], 95)

    def test_web_access_classification(self):
        raw = RawLogIngest(
            source="nginx-access",
            event_type="http.access",
            message='192.168.1.1 - - [08/Jun/2026] "GET / HTTP/1.1" 200'
        )
        parse_result = {"detected_format": "web"}
        
        res = log_type_detection_service.detect_log_type(raw, parse_result)
        
        self.assertEqual(res["log_type"], "nginx_access")
        self.assertEqual(res["log_subtype"], "access")

    def test_firewall_classification(self):
        raw = RawLogIngest(
            source="firewall",
            event_type="traffic",
            message="src=192.168.1.1 dst=10.0.0.1 action=deny"
        )
        parse_result = {"detected_format": "key_value"}
        
        res = log_type_detection_service.detect_log_type(raw, parse_result)
        
        self.assertEqual(res["log_type"], "firewall_log")
        self.assertEqual(res["log_subtype"], "deny")

    def test_unknown_classification(self):
        raw = RawLogIngest(
            source="random-source",
            event_type="random_event",
            message="completely unclassified message content"
        )
        parse_result = {"detected_format": "text"}
        
        res = log_type_detection_service.detect_log_type(raw, parse_result)
        
        self.assertEqual(res["log_type"], "unknown")
        self.assertNotIn("log_subtype", res)
        self.assertEqual(res["confidence"], 20)
        self.assertEqual(res["classification_reason"], "No matching classifier")

    # -------------------------------------------------------------------------
    # UNIT TESTS: UnknownLogService (Hashing, Deduplication)
    # -------------------------------------------------------------------------

    def test_unknown_hash_deterministic(self):
        raw = RawLogIngest(
            source="test_src",
            event_type="test_event",
            message="test_msg",
            timestamp="2026-06-08T12:00:00Z"
        )
        
        # Calculate expected hash using source, message, event_type
        hash_input = "test_srctest_msgtest_event"
        expected_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        
        # Run service save which calculates hash
        unknown_log_service.save_unknown_log(raw, {"detected_format": "text"}, {"confidence": 20})
        
        # Verify it exists in database
        record = unknown_log_repository.find_by_unknown_hash(expected_hash)
        self.assertIsNotNone(record)
        self.assertEqual(record["occurrence_count"], 1)

    def test_collector_name_mapping(self):
        # Windows collector
        raw_win = RawLogIngest(source="windows-event-viewer", message="msg", event_type="type")
        unknown_log_service.save_unknown_log(raw_win, {}, {})
        
        # Docker collector
        raw_doc = RawLogIngest(source="docker", message="msg", event_type="type")
        unknown_log_service.save_unknown_log(raw_doc, {}, {})
        
        # Custom collector fallback
        raw_cust = RawLogIngest(source="my-custom-shipper", message="msg", event_type="type")
        unknown_log_service.save_unknown_log(raw_cust, {}, {})

        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT source, collector_name FROM unknown_logs ORDER BY id;")
            rows = cursor.fetchall()
            
            self.assertEqual(rows[0][1], "windows_event_collector")
            self.assertEqual(rows[1][1], "docker_collector")
            self.assertEqual(rows[2][1], "my_custom_shipper_collector")

    def test_duplicate_occurrence_increments(self):
        raw = RawLogIngest(
            source="dup_test",
            event_type="dup_event",
            message="dup_message"
        )
        
        # Ingest 3 duplicate logs
        unknown_log_service.save_unknown_log(raw, {}, {})
        unknown_log_service.save_unknown_log(raw, {}, {})
        unknown_log_service.save_unknown_log(raw, {}, {})
        
        # Check database rows
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT occurrence_count FROM unknown_logs;")
            rows = cursor.fetchall()
            
            # There should only be 1 unique row in the DB with occurrence_count = 3
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], 3)

    def test_database_isolation_does_not_crash(self):
        raw = RawLogIngest(
            source="db_fail_test",
            event_type="db_fail",
            message="should not fail ingest"
        )
        
        # Patch insert_unknown_log to throw a database connection exception
        with patch("app.database.unknown_log_repository.insert_unknown_log", side_effect=Exception("DB connection lost")):
            try:
                # Should not raise exception
                unknown_log_service.save_unknown_log(raw, {}, {})
            except Exception as e:
                self.fail(f"save_unknown_log raised exception {e} on DB failure; expected complete isolation.")

    # -------------------------------------------------------------------------
    # INTEGRATION TESTS: Ingestion Pipeline Routing & Logs Storage
    # -------------------------------------------------------------------------

    def test_pipeline_known_log(self):
        payload = {
            "source": "windows-event-viewer",
            "event_type": "windows_event",
            "message": "Security logon success",
            "severity": "low",
            "timestamp": "2026-06-08T12:00:00Z",
            "metadata": {
                "event_id": "4624",
                "provider": "Microsoft-Windows-Security-Auditing"
            }
        }
        
        response = self.client.post("/api/logs/", json=payload)
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        
        # Verify classification is attached to metadata
        self.assertIn("log_classification", data["metadata"])
        classification = data["metadata"]["log_classification"]
        self.assertEqual(classification["log_type"], "windows_event")
        self.assertEqual(classification["log_subtype"], "authentication")
        self.assertEqual(classification["confidence"], 95)
        
        # Verify it was NOT written to unknown_logs
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM unknown_logs;")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 0)

    def test_pipeline_unknown_log_saved_and_continued(self):
        payload = {
            "source": "mystery-sensor",
            "event_type": "unidentified_category",
            "message": "Unknown payload: 0x90 0x90 0x90",
            "severity": "medium",
            "timestamp": "2026-06-08T12:00:00Z"
        }
        
        response = self.client.post("/api/logs/", json=payload)
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        
        # 1. Verify classification is attached to metadata
        classification = data["metadata"]["log_classification"]
        self.assertEqual(classification["log_type"], "unknown")
        self.assertEqual(classification["confidence"], 20)
        
        # 2. Verify unknown log was saved to the database table
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT source, collector_name, raw_payload, occurrence_count FROM unknown_logs;")
            rows = cursor.fetchall()
            
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], "mystery-sensor")
            self.assertEqual(rows[0][1], "mystery_sensor_collector")
            self.assertEqual(rows[0][3], 1)
            
        # 3. Verify it continued through the pipeline to main logs store
        # In-memory store or DB should have it (TestClient request succeeded)
        self.assertEqual(data["source"], "mystery-sensor")
        self.assertEqual(data["event_type"], "unidentified_category")

if __name__ == "__main__":
    unittest.main()
