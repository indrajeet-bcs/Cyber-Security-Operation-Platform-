"""
Invalid log repository — handles database operations for the `invalid_logs` table.
Uses raw SQL via psycopg2 and connection helpers to query and insert quarantined logs.
"""

import json
from datetime import datetime
from app.database.connection import get_connection
from app.utils.logger import logger

_INSERT_INVALID_LOG_SQL = """
    INSERT INTO invalid_logs (
        source,
        raw_payload,
        validation_status,
        validation_errors,
        validation_warnings,
        validation_stage,
        quarantine_hash,
        quarantined_count,
        received_at,
        collector_name,
        rejection_reason
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    ) RETURNING id
"""

_FIND_BY_HASH_SQL = """
    SELECT id, quarantined_count
    FROM invalid_logs
    WHERE quarantine_hash = %s
    LIMIT 1
"""

_INCREMENT_COUNT_SQL = """
    UPDATE invalid_logs
    SET quarantined_count = quarantined_count + 1
    WHERE id = %s
"""


def insert_invalid_log(
    source: str | None,
    raw_payload: str,
    validation_status: str,
    validation_errors: list[str],
    validation_warnings: list[str],
    validation_stage: str,
    quarantine_hash: str,
    quarantined_count: int,
    received_at: datetime,
    collector_name: str | None,
    rejection_reason: str | None,
) -> int:
    """
    Inserts a new quarantine record into the invalid_logs table.
    Returns the newly generated ID of the record.
    """
    errors_json = json.dumps(validation_errors)
    warnings_json = json.dumps(validation_warnings)

    values = (
        source,
        raw_payload,
        validation_status,
        errors_json,
        warnings_json,
        validation_stage,
        quarantine_hash,
        quarantined_count,
        received_at,
        collector_name,
        rejection_reason,
    )

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INSERT_INVALID_LOG_SQL, values)
            row = cursor.fetchone()
            record_id = row[0] if row else 0
            logger.info(
                f"[DB] Invalid log stored in quarantine — "
                f"source={source} stage={validation_stage} "
                f"hash={quarantine_hash} id={record_id}"
            )
            return record_id
    except Exception as exc:
        logger.error(f"[DB] Failed to insert invalid log into PostgreSQL: {exc}")
        raise


def find_by_quarantine_hash(quarantine_hash: str) -> dict | None:
    """
    Finds a quarantine record by its hash.
    Returns a dictionary containing 'id' and 'quarantined_count', or None.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_FIND_BY_HASH_SQL, (quarantine_hash,))
            row = cursor.fetchone()
            if row:
                return {"id": row[0], "quarantined_count": row[1]}
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to find invalid log by hash {quarantine_hash}: {exc}")
        raise


def increment_quarantine_count(record_id: int) -> None:
    """
    Increments the quarantine count of an existing record in the invalid_logs table.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INCREMENT_COUNT_SQL, (record_id,))
            logger.info(f"[DB] Incremented quarantined_count for record id={record_id}")
    except Exception as exc:
        logger.error(f"[DB] Failed to increment quarantine count for record id={record_id}: {exc}")
        raise
