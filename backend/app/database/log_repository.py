"""
Log repository — handles all PostgreSQL operations for the logs table.

Inserts fully normalized + detected log records into the existing `logs` table.
Uses raw SQL via psycopg2 so no ORM model definition is required.
"""

import json

from app.database.connection import get_connection
from app.schemas.log import DetectionResult, LogResponse
from app.utils.logger import logger

# Raw INSERT query — maps exactly to the existing `logs` table columns.
_INSERT_LOG_SQL = """
    INSERT INTO logs (
        source,
        host,
        event_type,
        message,
        severity,
        timestamp,
        source_ip,
        user_name,
        metadata,
        is_suspicious,
        detection_severity,
        detection_reason,
        ingested_at,
        record_number
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    )
"""


def insert_log(log: LogResponse) -> None:
    """
    Inserts a fully processed LogResponse into the PostgreSQL logs table.

    Called by log_service AFTER:
      - normalization is complete
      - detection result is attached
      - in-memory store has been updated

    If the insert fails for any reason, the error is logged and the
    exception is re-raised so the caller can handle it without crashing.
    """
    detection: DetectionResult | None = log.detection

    # Serialize metadata dict → JSON string for JSONB column
    metadata_json = json.dumps(log.metadata) if log.metadata else None

    values = (
        log.source,                                          # source
        log.host,                                           # host
        log.event_type,                                     # event_type
        log.message,                                        # message
        log.severity.value if log.severity else None,       # severity (enum → str)
        log.timestamp,                                      # timestamp
        log.source_ip,                                      # source_ip
        log.user,                                           # user_name
        metadata_json,                                      # metadata (JSONB)
        detection.is_suspicious if detection else False,    # is_suspicious
        detection.severity.value if detection else None,    # detection_severity
        detection.reason if detection else None,            # detection_reason
        log.ingested_at,                                    # ingested_at
        log.record_number,                                  # record_number
    )

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INSERT_LOG_SQL, values)
            logger.info(
                f"[DB] Log inserted into PostgreSQL — "
                f"source={log.source} host={log.host} "
                f"record_number={log.record_number}"
            )
    except Exception as exc:
        logger.error(f"[DB] Failed to insert log into PostgreSQL: {exc}")
        raise
