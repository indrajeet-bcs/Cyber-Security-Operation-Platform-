#!/usr/bin/env python3
"""
Verification script for SOC Platform Invalid Log Quarantine Storage.
Sends valid, warning, and invalid payloads to the FastAPI backend and queries the DB to assert results.
"""

import sys
import json
import hashlib
import requests
from pathlib import Path

# Add backend directory to path
sys.path.append(str(Path(__file__).resolve().parent))

from app.database.connection import get_connection

BACKEND_URL = "http://127.0.0.1:8000/api/logs/"


def get_quarantine_record(quarantine_hash: str):
    """Helper to retrieve a quarantine record directly from the database."""
    sql = """
        SELECT id, source, validation_status, validation_errors, quarantined_count, rejection_reason
        FROM invalid_logs
        WHERE quarantine_hash = %s
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (quarantine_hash,))
            row = cursor.fetchone()
            if row:
                errors_val = row[3]
                if isinstance(errors_val, str):
                    errors_val = json.loads(errors_val)
                elif errors_val is None:
                    errors_val = []
                
                return {
                    "id": row[0],
                    "source": row[1],
                    "validation_status": row[2],
                    "validation_errors": errors_val,
                    "quarantined_count": row[4],
                    "rejection_reason": row[5]
                }
            return None
    except Exception as exc:
        print(f"[-] Database query failed: {exc}")
        return None


def cleanup_test_records():
    """Removes test quarantine records from the database to ensure test idempotency."""
    sql = """
        DELETE FROM invalid_logs
        WHERE source IN ('test-invalid-collector', 'test-invalid-ts', 'test-oversized')
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            print(f"[+] Cleaned up any existing test records from the database.")
    except Exception as exc:
        print(f"[-] Database cleanup failed: {exc}")


def calculate_hash(source: str, event_type: str, message: str, timestamp: str) -> str:
    """Helper to calculate the quarantine hash deterministically."""
    hash_input = f"{source or ''}{event_type or ''}{message or ''}{timestamp or ''}"
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()


def run_tests():
    print("=" * 60)
    print("Running Invalid Log Quarantine Integration Tests...")
    print("=" * 60)

    # Clean up first
    cleanup_test_records()

    # --- TEST 1: Valid Log Ingestion ---
    print("\n[Test 1] Ingesting a VALID log...")
    valid_payload = {
        "source": "test-valid-collector",
        "event_type": "auth.success",
        "message": "User authenticated successfully",
        "severity": "low",
        "timestamp": "2026-06-05T15:00:00Z",
        "host": "test-host",
        "source_ip": "10.0.0.1"
    }
    resp = requests.post(BACKEND_URL, json=valid_payload)
    print(f"  - Status Code: {resp.status_code}")
    assert resp.status_code == 200, "Valid log failed ingestion"
    data = resp.json()
    assert data["source"] == "test-valid-collector"
    assert data["event_type"] == "auth.success"
    print("[SUCCESS] Test 1 Passed: Valid log ingested.")

    # --- TEST 2: Log Ingestion with Warnings ---
    print("\n[Test 2] Ingesting a log with WARNINGS (missing message, non-standard severity, invalid IP)...")
    warning_payload = {
        "source": "test-warning-collector",
        "event_type": "system.info",
        # Missing "message"
        "severity": "extremely_high",  # Non-standard severity
        "timestamp": "2026-06-05T15:05:00Z",
        "source_ip": "999.999.999.999"  # Invalid IP format
    }
    resp = requests.post(BACKEND_URL, json=warning_payload)
    print(f"  - Status Code: {resp.status_code}")
    assert resp.status_code == 200, "Warning log failed ingestion"
    data = resp.json()
    warnings = data.get("metadata", {}).get("validation_warnings", [])
    print(f"  - Captured Warnings: {warnings}")
    assert "Missing message" in warnings
    assert "Non-standard severity value" in warnings
    assert "Invalid source_ip format" in warnings
    print("[SUCCESS] Test 2 Passed: Warning log ingested with warnings attached to metadata.")

    # --- TEST 3: Invalid Log Ingestion (Missing event_type) ---
    print("\n[Test 3] Ingesting an INVALID log (Missing event_type)...")
    invalid_payload = {
        "source": "test-invalid-collector",
        "message": "Missing event type error log",
        "severity": "high",
        "timestamp": "2026-06-05T15:10:00Z"
    }
    expected_hash = calculate_hash("test-invalid-collector", "", "Missing event type error log", "2026-06-05T15:10:00Z")
    
    resp = requests.post(BACKEND_URL, json=invalid_payload)
    print(f"  - Status Code: {resp.status_code}")
    assert resp.status_code == 400, "Invalid log did not trigger 400 Bad Request"
    data = resp.json()
    print(f"  - Response: {data}")
    assert data["status"] == "quarantined"
    assert "event_type" in data["reason"].lower()

    # Query DB to check if it's stored in the invalid_logs table
    db_record = get_quarantine_record(expected_hash)
    assert db_record is not None, "Quarantine record not found in database"
    print(f"  - Database Record found: ID={db_record['id']}, Count={db_record['quarantined_count']}, Reason='{db_record['rejection_reason']}'")
    assert db_record["source"] == "test-invalid-collector"
    assert db_record["validation_status"] == "INVALID"
    assert db_record["quarantined_count"] == 1
    print("[SUCCESS] Test 3 Passed: Invalid log rejected and successfully quarantined in DB.")

    # --- TEST 4: Duplicate Invalid Log Handling ---
    print("\n[Test 4] Ingesting DUPLICATE INVALID log (same payload)...")
    resp = requests.post(BACKEND_URL, json=invalid_payload)
    print(f"  - Status Code: {resp.status_code}")
    assert resp.status_code == 400
    
    # Query DB to check if the count incremented
    db_record_dup = get_quarantine_record(expected_hash)
    assert db_record_dup is not None
    print(f"  - Database Record count after duplicate: Count={db_record_dup['quarantined_count']}")
    assert db_record_dup["quarantined_count"] == db_record["quarantined_count"] + 1, "Quarantine count did not increment"
    print("[SUCCESS] Test 4 Passed: Duplicate invalid log correctly incremented quarantined_count without creating new rows.")

    # --- TEST 5: Invalid Log Ingestion (Invalid timestamp format) ---
    print("\n[Test 5] Ingesting an INVALID log (Invalid timestamp format)...")
    invalid_ts_payload = {
        "source": "test-invalid-ts",
        "event_type": "app.crash",
        "message": "Application crash warning",
        "severity": "critical",
        "timestamp": "not-a-timestamp-iso-format"
    }
    resp = requests.post(BACKEND_URL, json=invalid_ts_payload)
    print(f"  - Status Code: {resp.status_code}")
    assert resp.status_code == 400
    data = resp.json()
    assert data["status"] == "quarantined"
    assert "timestamp" in data["reason"].lower()
    
    ts_hash = calculate_hash("test-invalid-ts", "app.crash", "Application crash warning", "not-a-timestamp-iso-format")
    db_record_ts = get_quarantine_record(ts_hash)
    assert db_record_ts is not None
    print(f"  - Database Record found: ID={db_record_ts['id']}, Reason='{db_record_ts['rejection_reason']}'")
    print("[SUCCESS] Test 5 Passed: Invalid timestamp log rejected and quarantined in DB.")

    # --- TEST 6: Invalid Log Ingestion (Oversized payload) ---
    print("\n[Test 6] Ingesting an INVALID log (Oversized payload)...")
    large_message = "A" * 105000  # 105 KB
    oversized_payload = {
        "source": "test-oversized",
        "event_type": "debug.dump",
        "message": large_message,
        "severity": "low"
    }
    resp = requests.post(BACKEND_URL, json=oversized_payload)
    print(f"  - Status Code: {resp.status_code}")
    assert resp.status_code == 400
    data = resp.json()
    assert data["status"] == "quarantined"
    assert "oversized" in data["reason"].lower()
    print("[SUCCESS] Test 6 Passed: Oversized payload rejected and quarantined.")

    print("\n" + "=" * 60)
    print("ALL QUARANTINE INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        run_tests()
    except AssertionError as exc:
        print(f"\n[FAILURE] Assertion failed: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"\n[CRITICAL] Unexpected error: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
