"""
Alert repository — handles all PostgreSQL operations for the alerts table.
Uses raw SQL via psycopg2 and the get_connection context manager.
"""

import json
from datetime import datetime, timezone
from app.database.connection import get_connection
from app.utils.logger import logger

# ---------------------------------------------------------------------------
# SQL Queries
# ---------------------------------------------------------------------------

_INSERT_ALERT_SQL = """
    INSERT INTO alerts (
        alert_id,
        alert_title,
        alert_type,
        severity,
        priority,
        confidence,
        risk_score,
        status,
        occurrence_count,
        source,
        source_ip,
        host,
        username,
        event_fingerprint,
        alert_fingerprint,
        rule_matches,
        correlation_matches,
        first_seen,
        last_seen,
        created_at,
        updated_at
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    ) RETURNING id
"""

_GET_ALERT_BY_FINGERPRINT_SQL = """
    SELECT
        id,
        alert_id,
        alert_title,
        alert_type,
        severity,
        priority,
        confidence,
        risk_score,
        status,
        occurrence_count,
        source,
        source_ip,
        host,
        username,
        event_fingerprint,
        alert_fingerprint,
        rule_matches,
        correlation_matches,
        first_seen,
        last_seen,
        created_at,
        updated_at,
        acknowledged_at,
        resolved_at,
        closed_at
    FROM alerts
    WHERE alert_fingerprint = %s
    LIMIT 1
"""

_GET_ALERT_BY_ALERT_ID_SQL = """
    SELECT
        id,
        alert_id,
        alert_title,
        alert_type,
        severity,
        priority,
        confidence,
        risk_score,
        status,
        occurrence_count,
        source,
        source_ip,
        host,
        username,
        event_fingerprint,
        alert_fingerprint,
        rule_matches,
        correlation_matches,
        first_seen,
        last_seen,
        created_at,
        updated_at,
        acknowledged_at,
        resolved_at,
        closed_at
    FROM alerts
    WHERE alert_id = %s
    LIMIT 1
"""

_UPDATE_ALERT_SQL = """
    UPDATE alerts
    SET
        severity = %s,
        priority = %s,
        confidence = %s,
        risk_score = %s,
        occurrence_count = %s,
        last_seen = %s,
        updated_at = %s,
        rule_matches = %s,
        correlation_matches = %s
    WHERE id = %s
"""

_INCREMENT_OCCURRENCE_COUNT_SQL = """
    UPDATE alerts
    SET occurrence_count = occurrence_count + %s,
        last_seen = %s,
        updated_at = %s
    WHERE id = %s
"""

# Lifecycle State Transitions
_ACKNOWLEDGE_ALERT_SQL = """
    UPDATE alerts
    SET status = 'acknowledged',
        acknowledged_at = %s,
        updated_at = %s
    WHERE alert_id = %s OR id::text = %s
"""

_INVESTIGATE_ALERT_SQL = """
    UPDATE alerts
    SET status = 'investigating',
        updated_at = %s
    WHERE alert_id = %s OR id::text = %s
"""

_RESOLVE_ALERT_SQL = """
    UPDATE alerts
    SET status = 'resolved',
        resolved_at = %s,
        updated_at = %s
    WHERE alert_id = %s OR id::text = %s
"""

_CLOSE_ALERT_SQL = """
    UPDATE alerts
    SET status = 'closed',
        closed_at = %s,
        updated_at = %s
    WHERE alert_id = %s OR id::text = %s
"""

_COUNT_ALERTS_TODAY_SQL = """
    SELECT COUNT(id) FROM alerts
    WHERE created_at >= %s AND created_at < %s
"""


# ---------------------------------------------------------------------------
# Helper Methods
# ---------------------------------------------------------------------------

def _row_to_dict(row: tuple) -> dict:
    return {
        "id": row[0],
        "alert_id": row[1],
        "alert_title": row[2],
        "alert_type": row[3],
        "severity": row[4],
        "priority": row[5],
        "confidence": row[6],
        "risk_score": row[7],
        "status": row[8],
        "occurrence_count": row[9],
        "source": row[10],
        "source_ip": row[11],
        "host": row[12],
        "username": row[13],
        "event_fingerprint": row[14],
        "alert_fingerprint": row[15],
        "rule_matches": row[16],
        "correlation_matches": row[17],
        "first_seen": row[18],
        "last_seen": row[19],
        "created_at": row[20],
        "updated_at": row[21],
        "acknowledged_at": row[22],
        "resolved_at": row[23],
        "closed_at": row[24],
    }


def get_next_alert_counter_for_day(date: datetime) -> int:
    """
    Returns the next counter for generating alert IDs like ALT-YYYYMMDD-XXXX.
    """
    start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
    import datetime as dt
    end_of_day = start_of_day + dt.timedelta(days=1)
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_COUNT_ALERTS_TODAY_SQL, (start_of_day, end_of_day))
            row = cursor.fetchone()
            count = row[0] if row else 0
            return count + 1
    except Exception as exc:
        logger.error(f"[DB] Failed to get alert counter: {exc}")
        return 1


# ---------------------------------------------------------------------------
# Core Methods
# ---------------------------------------------------------------------------

def create_alert(
    alert_id: str,
    alert_title: str,
    alert_type: str,
    severity: str,
    priority: str,
    confidence: int | None,
    risk_score: int | None,
    status: str,
    occurrence_count: int,
    source: str | None,
    source_ip: str | None,
    host: str | None,
    username: str | None,
    event_fingerprint: str | None,
    alert_fingerprint: str,
    rule_matches: list | None,
    correlation_matches: list | None,
) -> int:
    """
    Creates a new alert in the database.
    """
    now = datetime.now(timezone.utc)
    
    rule_matches_json = json.dumps(rule_matches) if rule_matches else None
    correlation_matches_json = json.dumps(correlation_matches) if correlation_matches else None

    values = (
        alert_id,
        alert_title,
        alert_type,
        severity,
        priority,
        confidence,
        risk_score,
        status,
        occurrence_count,
        source,
        source_ip,
        host,
        username,
        event_fingerprint,
        alert_fingerprint,
        rule_matches_json,
        correlation_matches_json,
        now, # first_seen
        now, # last_seen
        now, # created_at
        now, # updated_at
    )
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INSERT_ALERT_SQL, values)
            row = cursor.fetchone()
            record_id = row[0] if row else 0
            logger.info(f"[DB] Alert created in PostgreSQL: alert_id={alert_id} severity={severity}")
    except Exception as exc:
        logger.error(f"[DB] Failed to insert alert: {exc}")
        raise

    # Auto-create incident on alert creation
    if record_id > 0:
        try:
            from app.services.incident_service import incident_service
            incident_service.create_incident(
                alert_id=record_id,
                title=alert_title,
                severity=severity
            )
        except Exception as e:
            logger.error(f"[DB] Failed to auto-create incident for alert_id={record_id}: {e}")

    return record_id


def get_alert_by_fingerprint(alert_fingerprint: str) -> dict | None:
    """
    Finds an alert by its unique fingerprint.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_GET_ALERT_BY_FINGERPRINT_SQL, (alert_fingerprint,))
            row = cursor.fetchone()
            if row:
                return _row_to_dict(row)
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to get alert by fingerprint: {exc}")
        raise


def get_alert_by_alert_id(alert_id: str) -> dict | None:
    """
    Finds an alert by its generated alert_id.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_GET_ALERT_BY_ALERT_ID_SQL, (alert_id,))
            row = cursor.fetchone()
            if row:
                return _row_to_dict(row)
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to get alert by alert_id: {exc}")
        raise


def update_alert(
    record_id: int,
    severity: str,
    priority: str,
    confidence: int | None,
    risk_score: int | None,
    occurrence_count: int,
    rule_matches: list | None,
    correlation_matches: list | None,
) -> None:
    """
    Updates an existing alert (escalations, adding rule matches, etc).
    """
    now = datetime.now(timezone.utc)
    rule_matches_json = json.dumps(rule_matches) if rule_matches else None
    correlation_matches_json = json.dumps(correlation_matches) if correlation_matches else None
    
    values = (
        severity,
        priority,
        confidence,
        risk_score,
        occurrence_count,
        now, # last_seen
        now, # updated_at
        rule_matches_json,
        correlation_matches_json,
        record_id,
    )
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_UPDATE_ALERT_SQL, values)
            logger.info(f"[DB] Alert id={record_id} updated in PostgreSQL")
    except Exception as exc:
        logger.error(f"[DB] Failed to update alert id={record_id}: {exc}")
        raise


def increment_occurrence_count(record_id: int, increment_by: int = 1) -> None:
    """
    Simple increment for occurrence count.
    """
    now = datetime.now(timezone.utc)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INCREMENT_OCCURRENCE_COUNT_SQL, (increment_by, now, now, record_id))
    except Exception as exc:
        logger.error(f"[DB] Failed to increment occurrence count for alert id={record_id}: {exc}")
        raise


# ---------------------------------------------------------------------------
# Lifecycle State Methods
# ---------------------------------------------------------------------------

def acknowledge_alert(alert_id: int | str) -> None:
    now = datetime.now(timezone.utc)
    id_str = str(alert_id)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_ACKNOWLEDGE_ALERT_SQL, (now, now, id_str, id_str))
            logger.info(f"[INFO] Alert {alert_id} Acknowledged")
    except Exception as exc:
        logger.error(f"[DB] Failed to acknowledge alert {alert_id}: {exc}")
        raise

def investigate_alert(alert_id: int | str) -> None:
    now = datetime.now(timezone.utc)
    id_str = str(alert_id)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_INVESTIGATE_ALERT_SQL, (now, id_str, id_str))
            logger.info(f"[INFO] Alert {alert_id} Investigating")
    except Exception as exc:
        logger.error(f"[DB] Failed to investigate alert {alert_id}: {exc}")
        raise

def resolve_alert(alert_id: int | str) -> None:
    now = datetime.now(timezone.utc)
    id_str = str(alert_id)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_RESOLVE_ALERT_SQL, (now, now, id_str, id_str))
            logger.info(f"[INFO] Alert {alert_id} Resolved")
    except Exception as exc:
        logger.error(f"[DB] Failed to resolve alert {alert_id}: {exc}")
        raise

def close_alert(alert_id: int | str) -> None:
    now = datetime.now(timezone.utc)
    id_str = str(alert_id)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_CLOSE_ALERT_SQL, (now, now, id_str, id_str))
            logger.info(f"[INFO] Alert {alert_id} Closed")
    except Exception as exc:
        logger.error(f"[DB] Failed to close alert {alert_id}: {exc}")
        raise
