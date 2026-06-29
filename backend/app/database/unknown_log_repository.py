"""
Unknown log repository — handles database operations for the `unknown_logs` table.
Uses raw SQL via psycopg2 and the get_connection context manager.
"""

import json
from datetime import datetime
from app.database.connection import get_connection
from app.utils.logger import logger

_INSERT_UNKNOWN_LOG_SQL = """
    INSERT INTO unknown_logs (
        source,
        raw_payload,
        detected_format,
        parser_confidence,
        classification_reason,
        received_at,
        collector_name,
        unknown_hash,
        occurrence_count,
        log_type,
        detection_confidence,
        first_seen
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    ) RETURNING id
"""

_FIND_BY_HASH_SQL = """
    SELECT id, occurrence_count
    FROM unknown_logs
    WHERE unknown_hash = %s
    LIMIT 1
"""

_INCREMENT_COUNT_SQL = """
    UPDATE unknown_logs
    SET occurrence_count = occurrence_count + 1
    WHERE id = %s
"""


def find_by_unknown_hash(unknown_hash: str) -> dict | None:
    """
    Finds an unknown log record by its hash.
    Returns a dictionary containing 'id' and 'occurrence_count', or None.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_FIND_BY_HASH_SQL, (unknown_hash,))
            row = cursor.fetchone()
            if row:
                return {"id": row[0], "occurrence_count": row[1]}
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to find unknown log by hash {unknown_hash}: {exc}")
        raise


def insert_unknown_log(
    source: str | None,
    raw_payload: str,
    detected_format: str,
    parser_confidence: int,
    classification_reason: str,
    received_at: datetime,
    collector_name: str,
    unknown_hash: str,
    occurrence_count: int,
    log_type: str,
    detection_confidence: int,
    first_seen: datetime,
) -> int:
    """
    Inserts a new record into the unknown_logs table.
    Returns the newly generated ID of the record.
    """
    values = (
        source,
        raw_payload,
        detected_format,
        parser_confidence,
        classification_reason,
        received_at,
        collector_name,
        unknown_hash,
        occurrence_count,
        log_type,
        detection_confidence,
        first_seen,
    )

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INSERT_UNKNOWN_LOG_SQL, values)
            row = cursor.fetchone()
            record_id = row[0] if row else 0
            logger.info(
                f"[DB] Unknown log stored — source={source} "
                f"collector={collector_name} hash={unknown_hash} id={record_id}"
            )
            return record_id
    except Exception as exc:
        logger.error(f"[DB] Failed to insert unknown log into PostgreSQL: {exc}")
        raise


def increment_occurrence_count(record_id: int) -> None:
    """
    Increments the occurrence count of an existing record in the unknown_logs table.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INCREMENT_COUNT_SQL, (record_id,))
            logger.info(f"[DB] Incremented occurrence_count for unknown log record id={record_id}")
    except Exception as exc:
        logger.error(f"[DB] Failed to increment occurrence count for record id={record_id}: {exc}")
        raise
