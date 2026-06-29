"""
Correlation repository — handles all PostgreSQL operations for the `correlation_events` table.

Inserts correlation detection results produced by the CorrelationService.
Uses raw SQL via psycopg2 so no ORM model definition is required.
Identical pattern to log_repository.py and rule_repository.py.

Table columns (created manually via DBeaver):
    id, correlation_id, correlation_type, severity, confidence, risk_score,
    related_user, related_source_ip, related_host, event_count,
    first_seen, last_seen, correlation_reason, correlation_status,
    event_fingerprint, created_at
"""

from app.database.connection import get_connection
from app.utils.logger import logger

# ---------------------------------------------------------------------------
# SQL Queries
# ---------------------------------------------------------------------------

_INSERT_CORRELATION_SQL = """
    INSERT INTO correlation_events (
        correlation_id,
        correlation_type,
        severity,
        confidence,
        risk_score,
        related_user,
        related_source_ip,
        related_host,
        event_count,
        first_seen,
        last_seen,
        correlation_reason,
        correlation_status,
        event_fingerprint,
        created_at
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    )
"""

_GET_RECENT_CORRELATIONS_SQL = """
    SELECT
        id,
        correlation_id,
        correlation_type,
        severity,
        confidence,
        risk_score,
        related_user,
        related_source_ip,
        related_host,
        event_count,
        first_seen,
        last_seen,
        correlation_reason,
        correlation_status,
        event_fingerprint,
        created_at
    FROM correlation_events
    ORDER BY created_at DESC
    LIMIT %s;
"""

# Column order matching the SELECT query above
_COLUMNS = (
    "id",
    "correlation_id",
    "correlation_type",
    "severity",
    "confidence",
    "risk_score",
    "related_user",
    "related_source_ip",
    "related_host",
    "event_count",
    "first_seen",
    "last_seen",
    "correlation_reason",
    "correlation_status",
    "event_fingerprint",
    "created_at",
)


def _row_to_dict(row: tuple) -> dict:
    """Converts a DB row tuple to a dict keyed by column name."""
    return dict(zip(_COLUMNS, row))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def insert_correlation_event(event: dict) -> None:
    """
    Inserts a correlation detection result into the PostgreSQL correlation_events table.

    Called by CorrelationService on a background daemon thread so that
    DB writes never block the ingestion pipeline.

    If the insert fails for any reason, the error is logged and the
    exception is re-raised so the caller can handle it without crashing.
    """
    values = (
        event.get("correlation_id"),
        event.get("correlation_type"),
        event.get("severity"),
        event.get("confidence", 0),
        event.get("risk_score", 0),
        event.get("related_user"),
        event.get("related_source_ip"),
        event.get("related_host"),
        event.get("event_count", 1),
        event.get("first_seen"),
        event.get("last_seen"),
        event.get("correlation_reason"),
        event.get("correlation_status", "active"),
        event.get("event_fingerprint"),
        event.get("created_at"),
    )

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INSERT_CORRELATION_SQL, values)
            logger.info(
                f"[DB] Correlation event inserted — "
                f"type={event.get('correlation_type')} "
                f"severity={event.get('severity')} "
                f"correlation_id={event.get('correlation_id')}"
            )
    except Exception as exc:
        logger.error(f"[DB] Failed to insert correlation event: {exc}")
        raise


def get_recent_correlations(limit: int = 100) -> list[dict]:
    """
    Returns the most recent correlation events from the database.

    Each event is represented as a dict with keys matching the table columns.
    Returns an empty list if the table is empty or on DB failure.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_GET_RECENT_CORRELATIONS_SQL, (limit,))
            rows = cursor.fetchall()
            events = [_row_to_dict(r) for r in rows]
            logger.info(
                f"[CorrelationRepository] Loaded {len(events)} recent correlation events."
            )
            return events
    except Exception as exc:
        logger.error(f"[CorrelationRepository] Failed to load correlation events: {exc}")
        raise
