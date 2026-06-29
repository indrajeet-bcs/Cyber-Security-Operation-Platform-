#!/usr/bin/env python3
"""
Verification script for Chrome Browser Log Collector.
Creates a mock History SQLite DB, simulates browser events, polls them using the collector,
and verifies ingestion in the running FastAPI backend.
"""

import os
import sys
import tempfile
import sqlite3
import shutil
import time
import requests
from pathlib import Path

# Add backend directory to path
sys.path.append(str(Path(__file__).resolve().parent))

from collectors.chrome_browser_collector import ChromeBrowserCollector, webkit_to_datetime_str


def setup_mock_db(db_path: str):
    """Creates a mock Chrome History SQLite database schema."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create urls table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER,
            hidden INTEGER DEFAULT 0
        )
    """)

    # Create visits table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER,
            visit_time INTEGER,
            from_visit INTEGER,
            transition INTEGER,
            segment_id INTEGER,
            visit_duration INTEGER,
            increment_resolve_status INTEGER,
            opener_visit INTEGER,
            FOREIGN KEY(url) REFERENCES urls(id)
        )
    """)

    # Create keyword_search_terms table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keyword_search_terms (
            keyword_id INTEGER,
            url_id INTEGER,
            lower_term TEXT,
            term TEXT,
            FOREIGN KEY(url_id) REFERENCES urls(id)
        )
    """)

    # Create downloads table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guid TEXT,
            current_path TEXT,
            target_path TEXT,
            start_time INTEGER,
            received_bytes INTEGER,
            total_bytes INTEGER,
            state INTEGER,
            danger_type INTEGER,
            interrupt_reason INTEGER,
            hash BLOB,
            end_time INTEGER,
            opened INTEGER,
            last_access_time INTEGER,
            transient INTEGER,
            referrer TEXT,
            site_referrer TEXT,
            embedder_download_data TEXT,
            tab_url TEXT,
            tab_referrer_url TEXT,
            http_method TEXT,
            by_ext_id TEXT,
            by_ext_name TEXT,
            etag TEXT,
            last_modified TEXT,
            mime_type TEXT,
            original_mime_type TEXT
        )
    """)

    conn.commit()
    conn.close()


def add_mock_visit(db_path: str, url: str, title: str, webkit_time: int, transition: int, search_term: str = None):
    """Inserts a mock URL visit and optional search query."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time) VALUES (?, ?, 1, 0, ?)",
        (url, title, webkit_time)
    )
    url_id = cursor.lastrowid

    cursor.execute(
        "INSERT INTO visits (url, visit_time, transition) VALUES (?, ?, ?)",
        (url_id, webkit_time, transition)
    )
    visit_id = cursor.lastrowid

    if search_term:
        cursor.execute(
            "INSERT INTO keyword_search_terms (url_id, term) VALUES (?, ?)",
            (url_id, search_term)
        )

    conn.commit()
    conn.close()
    return visit_id


def add_mock_download(db_path: str, file_path: str, webkit_time: int, total_bytes: int, tab_url: str):
    """Inserts a mock file download."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO downloads (current_path, target_path, start_time, received_bytes, total_bytes, state, tab_url)
        VALUES (?, ?, ?, ?, ?, 1, ?)
    """, (file_path, file_path, webkit_time, total_bytes, total_bytes, tab_url))
    download_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return download_id


def run_tests():
    print("=" * 60)
    print("Running Chrome Collector Integration Tests...")
    print("=" * 60)

    # 1. Setup mock profiles in a temp directory
    temp_dir = tempfile.mkdtemp()
    profile_name = "MockProfile"
    mock_history_dir = os.path.join(temp_dir, profile_name)
    os.makedirs(mock_history_dir)
    db_path = os.path.join(mock_history_dir, "History")

    try:
        setup_mock_db(db_path)
        print(f"[+] Created mock database at {db_path}")

        # Add initial mock data before collector startup to simulate historical records
        webkit_now = 13361664000000000  # Microseconds since 1601
        add_mock_visit(db_path, "https://google.com", "Google", webkit_now, 1)
        add_mock_download(db_path, "C:\\Downloads\\installer.exe", webkit_now, 1048576, "https://google.com")

        # 2. Instantiate collector and point it to the mock directory
        collector = ChromeBrowserCollector(poll_interval=1.0)
        
        # Override discover_profiles to only return our mock profile
        collector.discover_profiles = lambda: {profile_name: db_path}

        # Initialize tracking - should find the max visit and download IDs and not send them
        collector.initialize_tracking()
        
        assert collector.last_visit_ids[profile_name] == 1, "Failed to initialize last_visit_id"
        assert collector.last_download_ids[profile_name] == 1, "Failed to initialize last_download_id"
        print("[SUCCESS] Collector successfully initialized tracking and ignored historical events.")

        # 3. Add NEW events that happen AFTER initialization
        print("\n[+] Simulating new browser activity...")
        webkit_new_1 = webkit_now + 5000000  # +5 seconds
        visit_id = add_mock_visit(
            db_path, 
            "https://github.com/google/flatbuffers", 
            "GitHub - FlatBuffers", 
            webkit_new_1, 
            0
        )

        webkit_new_2 = webkit_now + 10000000  # +10 seconds
        search_visit_id = add_mock_visit(
            db_path, 
            "https://www.google.com/search?q=FastAPI+SOC", 
            "FastAPI SOC - Google Search", 
            webkit_new_2, 
            5, 
            "FastAPI SOC"
        )

        webkit_new_3 = webkit_now + 15000000  # +15 seconds
        download_id = add_mock_download(
            db_path, 
            "C:\\Downloads\\soc_agent.zip", 
            webkit_new_3, 
            5242880, 
            "https://github.com/google/flatbuffers"
        )

        # 4. Trigger polling
        print("\n[+] Triggering collector polling...")
        collector.poll_all_profiles()

        # Check tracking advanced
        assert collector.last_visit_ids[profile_name] == search_visit_id, "last_visit_id did not advance"
        assert collector.last_download_ids[profile_name] == download_id, "last_download_id did not advance"
        print("[SUCCESS] Tracking pointers advanced correctly.")

        # 5. Verify the logs in the FastAPI backend
        print("\n[+] Querying FastAPI backend to verify ingestion...")
        resp = requests.get("http://127.0.0.1:8000/api/logs/")
        assert resp.status_code == 200, "Failed to fetch logs from backend"
        
        logs = resp.json()
        chrome_logs = [log for log in logs if log["source"] == "chrome-browser"]
        
        # We expect 3 Chrome logs: browser.url_visit, browser.search, browser.download
        print(f"    Total chrome logs found in backend: {len(chrome_logs)}")
        for log in chrome_logs:
            print(f"    - Event Type: {log['event_type']}, Message: {log['message']}")
            print(f"      Metadata: {log['metadata']}")

        event_types = [log["event_type"] for log in chrome_logs]
        assert "browser.url_visit" in event_types, "Missing browser.url_visit event"
        assert "browser.search" in event_types, "Missing browser.search event"
        assert "browser.download" in event_types, "Missing browser.download event"
        
        # Verify no duplicate entries are sent on a second poll
        print("\n[+] Polling again without adding new events (duplicate check)...")
        # Store log count
        initial_log_count = len(requests.get("http://127.0.0.1:8000/api/logs/").json())
        collector.poll_all_profiles()
        second_log_count = len(requests.get("http://127.0.0.1:8000/api/logs/").json())
        assert initial_log_count == second_log_count, f"Duplicate logs were added: {initial_log_count} vs {second_log_count}"
        print("[SUCCESS] Duplicate check passed. No duplicate logs were sent.")

        print("\n" + "=" * 60)
        print("ALL CHROME COLLECTOR INTEGRATION TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)

    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n[FAILURE] Integration tests failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
