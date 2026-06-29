#!/usr/bin/env python3
"""
Chrome Browser Log Collector Agent for Windows.
Polls Google Chrome History SQLite databases across all user profiles,
maps URL visits, search terms, and downloads to the SOC log schema,
and forwards them to the FastAPI backend.
"""

import os
import shutil
import tempfile
import sqlite3
import socket
import time
import sys
from datetime import datetime, timezone
import requests

BACKEND_URL = "http://127.0.0.1:8000/api/logs/"
POLL_INTERVAL = 5.0  # seconds


def webkit_to_datetime_str(webkit_ts: int) -> str:
    """Convert WebKit timestamp (microseconds since Jan 1, 1601 UTC) to ISO-8601 string."""
    if not webkit_ts or webkit_ts <= 0:
        return datetime.now(timezone.utc).isoformat()
    try:
        # Difference in seconds between UNIX epoch (1970) and WebKit epoch (1601) is 11,644,473,600
        unix_ts = (webkit_ts / 1_000_000.0) - 11644473600.0
        if unix_ts < 0:
            return datetime.now(timezone.utc).isoformat()
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def decode_transition(transition: int) -> str:
    """Decode Chrome transition core type value to a readable name."""
    core_type = transition & 0xFF
    mapping = {
        0: "Link",
        1: "Typed",
        2: "Auto_Bookmark",
        3: "Auto_Subframe",
        4: "Manual_Subframe",
        5: "Generated",
        6: "Auto_Toplevel",
        7: "Form_Submit",
        8: "Reload",
        9: "Keyword",
        10: "Keyword_Generated"
    }
    return mapping.get(core_type, f"Other ({core_type})")


class ChromeBrowserCollector:
    def __init__(self, backend_url: str = BACKEND_URL, poll_interval: float = POLL_INTERVAL):
        self.backend_url = backend_url
        self.poll_interval = poll_interval
        self.host_name = socket.gethostname() or "local-windows-machine"
        self.profiles = {}  # profile_name -> history_path
        self.profile_ids = {}  # profile_name -> unique int profile ID
        self.last_visit_ids = {}  # profile_name -> last seen visit_id
        self.last_download_ids = {}  # profile_name -> last seen download_id

    def discover_profiles(self) -> dict[str, str]:
        """Detect the user's local Chrome User Data folder and scan for profile History files."""
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            # Fallback to home directory AppData\Local
            home = os.path.expanduser("~")
            local_app_data = os.path.join(home, "AppData", "Local")

        user_data_dir = os.path.join(local_app_data, "Google", "Chrome", "User Data")
        
        profiles = {}
        if not os.path.exists(user_data_dir):
            print(f"[!] Chrome User Data directory not found at: {user_data_dir}")
            return profiles

        # Check directories under User Data
        try:
            for entry in os.listdir(user_data_dir):
                entry_path = os.path.join(user_data_dir, entry)
                if os.path.isdir(entry_path):
                    # Check if a History file exists directly inside this profile folder
                    history_path = os.path.join(entry_path, "History")
                    if os.path.exists(history_path):
                        profiles[entry] = history_path
        except Exception as e:
            print(f"[!] Error scanning Chrome User Data profiles: {e}")

        return profiles

    def query_db(self, profile_name: str, query: str, params: tuple = ()) -> list[dict]:
        """Query the SQLite database by making a temporary copy to bypass locks."""
        history_path = self.profiles.get(profile_name)
        if not history_path or not os.path.exists(history_path):
            return []

        temp_dir = tempfile.gettempdir()
        temp_history_path = os.path.join(temp_dir, f"chrome_history_temp_{profile_name}.db")
        
        rows = []
        try:
            # Copy file to temporary folder to prevent DB locking issues
            shutil.copy2(history_path, temp_history_path)
            
            conn = sqlite3.connect(temp_history_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
        except Exception as e:
            print(f"[-] Error querying History database for profile [{profile_name}]: {e}")
        finally:
            # Safely clean up the temp file
            if os.path.exists(temp_history_path):
                try:
                    os.remove(temp_history_path)
                except Exception:
                    pass
        return rows

    def get_max_id(self, profile_name: str, table: str) -> int:
        """Helper to get the current maximum ID in a table."""
        query = f"SELECT MAX(id) as max_id FROM {table}"
        try:
            rows = self.query_db(profile_name, query)
            if rows and rows[0]["max_id"] is not None:
                return int(rows[0]["max_id"])
        except Exception as e:
            print(f"[-] Failed to get max ID from [{table}] in [{profile_name}]: {e}")
        return 0

    def initialize_tracking(self):
        """Discovers profiles and initializes tracking indices so we only forward new events."""
        print("\n" + "=" * 50)
        print("Initializing Chrome Browser Event Tracking Agent")
        print("=" * 50)
        
        discovered = self.discover_profiles()
        if not discovered:
            print("[!] No active Chrome profiles with History databases found.")
            return

        sorted_names = sorted(discovered.keys())
        for idx, name in enumerate(sorted_names):
            self.profile_ids[name] = idx + 1
            self.profiles[name] = discovered[name]
            
            # Find current max IDs
            max_visit = self.get_max_id(name, "visits")
            max_download = self.get_max_id(name, "downloads")
            
            self.last_visit_ids[name] = max_visit
            self.last_download_ids[name] = max_download
            
            print(f"[+] Profile [{name}] (ID: {self.profile_ids[name]}):")
            print(f"    History Path: {self.profiles[name]}")
            print(f"    Current Max Visit ID: {max_visit}")
            print(f"    Current Max Download ID: {max_download}")

    def check_for_resets(self, profile_name: str):
        """Check if history was cleared/rotated and reset tracking pointer if needed."""
        # Check visits table
        current_max_visit = self.get_max_id(profile_name, "visits")
        last_visit = self.last_visit_ids.get(profile_name, 0)
        if current_max_visit < last_visit:
            print(f"[*] Chrome History visits for profile [{profile_name}] was cleared or reset. Resetting tracking from {last_visit} to {current_max_visit}")
            self.last_visit_ids[profile_name] = current_max_visit

        # Check downloads table
        current_max_download = self.get_max_id(profile_name, "downloads")
        last_download = self.last_download_ids.get(profile_name, 0)
        if current_max_download < last_download:
            print(f"[*] Chrome History downloads for profile [{profile_name}] was cleared or reset. Resetting tracking from {last_download} to {current_max_download}")
            self.last_download_ids[profile_name] = current_max_download

    def send_to_backend(self, payload: dict) -> bool:
        """Sends the normalized log payload to the FastAPI backend API."""
        try:
            response = requests.post(self.backend_url, json=payload, timeout=5)
            if response.status_code in (200, 201):
                print(f"  [SUCCESS] Sent event: {payload['event_type']} - Record: {payload['record_number']} - Message: {payload['message'][:60]}...")
                return True
            elif response.status_code == 409:
                data = response.json()
                print(f"  [SKIP] Duplicate event (record_number={payload.get('record_number')}) already stored as log id={data.get('existing_log_id')}. Skipping.")
                return True
            else:
                print(f"  [X] Failed to send event. Status code: {response.status_code}, Response: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"  [X] Backend connection error: {e}. Retrying on next poll.")
            return False

    def poll_visits(self, profile_name: str):
        """Polls URL visits and keyword searches."""
        last_visit_id = self.last_visit_ids.get(profile_name, 0)
        profile_id = self.profile_ids[profile_name]

        query = """
            SELECT
                v.id AS visit_id,
                u.url AS url,
                u.title AS title,
                u.visit_count AS visit_count,
                u.typed_count AS typed_count,
                v.visit_time AS visit_time,
                v.transition AS transition,
                k.term AS search_term
            FROM visits v
            JOIN urls u ON v.url = u.id
            LEFT JOIN keyword_search_terms k ON k.url_id = u.id
            WHERE v.id > ?
            ORDER BY v.id ASC
        """
        rows = self.query_db(profile_name, query, (last_visit_id,))
        if not rows:
            return

        print(f"[*] Found {len(rows)} new URL visit(s) in [{profile_name}] profile.")
        for row in rows:
            visit_id = row["visit_id"]
            url = row["url"]
            title = row["title"] or ""
            visit_count = row["visit_count"] or 1
            typed_count = row["typed_count"] or 0
            visit_time = row["visit_time"]
            transition = row["transition"]
            search_term = row["search_term"]

            timestamp_str = webkit_to_datetime_str(visit_time)
            transition_name = decode_transition(transition)

            # Assign unique record_number to prevent duplicates across profiles
            record_number = (profile_id * 100_000_000) + visit_id

            if search_term:
                event_type = "browser.search"
                message = f"Search query: '{search_term}' on URL: {url}"
            else:
                event_type = "browser.url_visit"
                message = f"Visited URL: {url}"

            payload = {
                "source": "chrome-browser",
                "event_type": event_type,
                "message": message,
                "severity": "info",
                "timestamp": timestamp_str,
                "host": self.host_name,
                "record_number": record_number,
                "metadata": {
                    "browser": "chrome",
                    "profile": profile_name,
                    "title": title,
                    "visit_count": visit_count,
                    "typed_count": typed_count,
                    "transition_type": transition,
                    "transition_name": transition_name,
                    "visit_id": visit_id
                }
            }
            if search_term:
                payload["metadata"]["search_term"] = search_term

            if self.send_to_backend(payload):
                self.last_visit_ids[profile_name] = visit_id

    def poll_downloads(self, profile_name: str):
        """Polls file downloads."""
        last_download_id = self.last_download_ids.get(profile_name, 0)
        profile_id = self.profile_ids[profile_name]

        query = """
            SELECT
                id AS download_id,
                guid,
                current_path,
                target_path,
                start_time,
                received_bytes,
                total_bytes,
                referrer,
                tab_url
            FROM downloads
            WHERE id > ?
            ORDER BY id ASC
        """
        rows = self.query_db(profile_name, query, (last_download_id,))
        if not rows:
            return

        print(f"[*] Found {len(rows)} new file download(s) in [{profile_name}] profile.")
        for row in rows:
            download_id = row["download_id"]
            current_path = row["current_path"] or ""
            target_path = row["target_path"] or ""
            start_time = row["start_time"]
            received_bytes = row["received_bytes"] or 0
            total_bytes = row["total_bytes"] or 0
            referrer = row["referrer"] or ""
            tab_url = row["tab_url"] or ""

            timestamp_str = webkit_to_datetime_str(start_time)
            file_path = target_path or current_path or "unknown_file"
            file_name = os.path.basename(file_path)

            message = f"Downloaded file: {file_name} from {tab_url} to {file_path}"
            record_number = (profile_id * 100_000_000) + download_id

            payload = {
                "source": "chrome-browser",
                "event_type": "browser.download",
                "message": message,
                "severity": "info",
                "timestamp": timestamp_str,
                "host": self.host_name,
                "record_number": record_number,
                "metadata": {
                    "browser": "chrome",
                    "profile": profile_name,
                    "download_id": download_id,
                    "file_name": file_name,
                    "file_path": file_path,
                    "total_bytes": total_bytes,
                    "received_bytes": received_bytes,
                    "referrer": referrer,
                    "tab_url": tab_url
                }
            }

            if self.send_to_backend(payload):
                self.last_download_ids[profile_name] = download_id

    def poll_all_profiles(self):
        """Performs checking and polling on all active profiles."""
        for name in list(self.profiles.keys()):
            try:
                # 1. Reset check in case history was cleared
                self.check_for_resets(name)
                # 2. Poll URL visits
                self.poll_visits(name)
                # 3. Poll downloads
                self.poll_downloads(name)
            except Exception as e:
                print(f"[-] Error during polling for profile [{name}]: {e}")

    def run(self):
        self.initialize_tracking()
        print(f"\n[*] Chrome Browser Log Collector Agent is running. Polling every {self.poll_interval}s...")
        try:
            while True:
                # Dynamically re-scan for profiles in case new profiles were created or deleted
                discovered = self.discover_profiles()
                for name, path in discovered.items():
                    if name not in self.profiles:
                        # New profile discovered
                        print(f"[*] Discovered new Chrome profile: {name}")
                        idx = len(self.profile_ids) + 1
                        self.profile_ids[name] = idx
                        self.profiles[name] = path
                        self.last_visit_ids[name] = self.get_max_id(name, "visits")
                        self.last_download_ids[name] = self.get_max_id(name, "downloads")

                self.poll_all_profiles()
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            print("\n[!] Agent stopped by user.")


if __name__ == "__main__":
    try:
        collector = ChromeBrowserCollector()
        collector.run()
    except Exception as exc:
        print(f"[CRITICAL] Chrome Browser Collector agent failed to start: {exc}")
        sys.exit(1)
