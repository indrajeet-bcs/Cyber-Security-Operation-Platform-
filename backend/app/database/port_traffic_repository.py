"""
Port Traffic Repository — handles database operations for port_traffic_records.
"""

from datetime import datetime
from typing import Any, List, Optional
from psycopg2.extras import RealDictCursor

from app.database.connection import get_connection
from app.utils.logger import logger


_INSERT_RECORD_SQL = """
    INSERT INTO port_traffic_records (
        monitored_port,
        source_ip,
        destination_ip,
        protocol,
        first_seen_at,
        last_seen_at,
        activity_count,
        observed_duration_seconds,
        monitoring_window_start,
        monitoring_window_end,
        classification,
        created_at
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()
    )
    RETURNING id;
"""

_SELECT_RECORDS_IN_WINDOW = """
    SELECT 
        id,
        monitored_port,
        source_ip,
        destination_ip,
        protocol,
        first_seen_at,
        last_seen_at,
        activity_count,
        observed_duration_seconds,
        monitoring_window_start,
        monitoring_window_end,
        classification,
        created_at
    FROM port_traffic_records
    WHERE monitored_port = %s
      AND monitoring_window_end >= %s
      AND monitoring_window_start <= %s
    ORDER BY first_seen_at ASC;
"""

_SELECT_MONITORED_PORTS = """
    SELECT DISTINCT monitored_port
    FROM port_traffic_records
    ORDER BY monitored_port ASC;
"""


def bulk_insert_port_traffic_records(
    monitored_port: int,
    window_start: datetime,
    window_end: datetime,
    records: List[dict],
) -> List[int]:
    """Inserts a batch of port traffic records into port_traffic_records."""
    inserted_ids = []
    if not records:
        return inserted_ids

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            for r in records:
                cursor.execute(
                    _INSERT_RECORD_SQL,
                    (
                        monitored_port,
                        r["source_ip"],
                        r.get("destination_ip"),
                        r.get("protocol", "TCP"),
                        r["first_seen_at"],
                        r["last_seen_at"],
                        r.get("activity_count", 1),
                        r.get("observed_duration_seconds", 0.0),
                        window_start,
                        window_end,
                        r.get("classification", "OBSERVED"),
                    ),
                )
                row = cursor.fetchone()
                if row:
                    inserted_ids.append(row[0])
            logger.info(
                f"[DB] Inserted {len(inserted_ids)} port_traffic_records for port {monitored_port}"
            )
    except Exception as exc:
        logger.error(f"[DB] Failed to bulk insert port traffic records: {exc}")
        raise

    return inserted_ids


def get_port_records_in_window(
    port: int, start_time: datetime, end_time: datetime
) -> List[dict]:
    """Fetches port_traffic_records matching port and overlapping monitoring window."""
    records = []
    try:
        with get_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute(_SELECT_RECORDS_IN_WINDOW, (port, start_time, end_time))
            rows = cursor.fetchall()
            for row in rows:
                records.append(dict(row))
    except Exception as exc:
        logger.error(f"[DB] Failed to query port_traffic_records: {exc}")
        # Fallback to empty list if DB query fails
        return []

    return records


def get_monitored_ports_list() -> List[int]:
    """Fetches list of distinct monitored ports that have recorded traffic."""
    ports = []
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_SELECT_MONITORED_PORTS)
            rows = cursor.fetchall()
            ports = [row[0] for row in rows]
    except Exception as exc:
        logger.error(f"[DB] Failed to query monitored ports list: {exc}")
        return []

    return ports
