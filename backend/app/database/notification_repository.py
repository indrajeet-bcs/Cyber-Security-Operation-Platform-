"""
Notification repository — handles all PostgreSQL operations for notification-related tables.
Uses raw SQL via psycopg2 and the get_connection context manager.
Gracefully handles missing schema columns dynamically.
"""

from datetime import datetime, timezone
import logging
from app.database.connection import get_connection
from app.utils.logger import logger

_EXISTING_COLUMNS = set()

def validate_schema() -> bool:
    """
    Queries database metadata to verify the existence of columns in the notifications table.
    Caches the existing columns in _EXISTING_COLUMNS.
    Logs [ERROR] Notification schema validation failed if required columns are missing.
    """
    global _EXISTING_COLUMNS
    required_cols = {"escalation_stopped", "channel_used", "suppression_until", "escalation_level"}
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'notifications'
            """)
            rows = cursor.fetchall()
            _EXISTING_COLUMNS = {row[0] for row in rows}
    except Exception as exc:
        logger.error(f"[ERROR] Notification schema inspection failed: {exc}")
        _EXISTING_COLUMNS = set()
        
    missing = required_cols - _EXISTING_COLUMNS
    if missing:
        logger.error(f"[ERROR] Notification schema validation failed")
        return False
    return True

def _ensure_schema_loaded():
    """
    Ensures that the existing columns cache is loaded.
    """
    if not _EXISTING_COLUMNS:
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'notifications'
                """)
                rows = cursor.fetchall()
                for r in rows:
                    _EXISTING_COLUMNS.add(r[0])
        except Exception as exc:
            logger.error(f"[DB] Error loading notification schema: {exc}")

def get_active_policy(severity: str) -> dict | None:
    """
    Fetches the active notification policy details for the given severity.
    """
    sql = """
        SELECT id, policy_name, severity, initial_role, escalation_role, escalation_minutes, 
               second_escalation_role, second_escalation_minutes, is_active, created_at
        FROM notification_policies
        WHERE severity = %s AND is_active = TRUE
        LIMIT 1
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (severity.lower(),))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "policy_name": row[1],
                    "severity": row[2],
                    "initial_role": row[3],
                    "escalation_role": row[4],
                    "escalation_minutes": row[5],
                    "second_escalation_role": row[6],
                    "second_escalation_minutes": row[7],
                    "is_active": row[8],
                    "created_at": row[9],
                }
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to get active policy for severity={severity}: {exc}")
        raise

def get_recipients_by_role(role: str) -> list[dict]:
    """
    Queries active recipients for a specific role from the notification_recipients table.
    """
    sql = """
        SELECT id, recipient_name, email, role, team, phone, slack_channel, is_active, created_at, updated_at
        FROM notification_recipients
        WHERE role = %s AND is_active = TRUE
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (role,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "recipient_name": r[1],
                    "email": r[2],
                    "role": r[3],
                    "team": r[4],
                    "phone": r[5],
                    "slack_channel": r[6],
                    "is_active": r[7],
                    "created_at": r[8],
                    "updated_at": r[9],
                }
                for r in rows
            ]
    except Exception as exc:
        logger.error(f"[DB] Failed to get recipients by role={role}: {exc}")
        raise

def create_notification(
    notification_id: str,
    alert_id: str,
    notification_fingerprint: str,
    severity: str,
    recipient_group: str,
    status: str,
    occurrence_count: int = 1,
    delivery_attempts: int = 0,
    last_delivery_attempt: datetime | None = None,
    delivery_status: str | None = None,
    acknowledged_by: str | None = None,
    acknowledged_at: datetime | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    escalation_level: int = 0,
    channel_used: str | None = None,
    suppression_until: datetime | None = None,
    escalation_stopped: bool = False,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> int:
    """
    Inserts a new notification record into notifications table.
    Dynamically omits columns that are missing from the schema.
    """
    _ensure_schema_loaded()
    now = datetime.now(timezone.utc)
    c_time = created_at or now
    u_time = updated_at or now
    
    data = {
        "notification_id": notification_id,
        "alert_id": alert_id,
        "notification_fingerprint": notification_fingerprint,
        "severity": severity,
        "recipient_group": recipient_group,
        "status": status,
        "occurrence_count": occurrence_count,
        "delivery_attempts": delivery_attempts,
        "first_seen": first_seen or c_time,
        "last_seen": last_seen or u_time,
        "created_at": c_time,
        "updated_at": u_time,
    }
    
    optional_fields = {
        "last_delivery_attempt": last_delivery_attempt,
        "delivery_status": delivery_status,
        "acknowledged_by": acknowledged_by,
        "acknowledged_at": acknowledged_at,
        "escalation_level": escalation_level,
        "channel_used": channel_used,
        "suppression_until": suppression_until,
        "escalation_stopped": escalation_stopped,
    }
    
    for field, val in optional_fields.items():
        if field in _EXISTING_COLUMNS:
            data[field] = val
            
    cols = list(data.keys())
    vals = list(data.values())
    placeholders = ", ".join(["%s"] * len(cols))
    sql = f"""
        INSERT INTO notifications ({", ".join(cols)})
        VALUES ({placeholders})
        RETURNING id
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, vals)
            row = cursor.fetchone()
            return row[0] if row else 0
    except Exception as exc:
        logger.error(f"[DB] Failed to create notification: {exc}")
        raise

def get_notification_by_fingerprint(fingerprint: str) -> dict | None:
    """
    Finds a notification by its fingerprint, dynamically selecting only existing columns.
    """
    _ensure_schema_loaded()
    cols = [
        "id", "notification_id", "alert_id", "notification_fingerprint",
        "severity", "recipient_group", "status", "occurrence_count",
        "delivery_attempts", "last_delivery_attempt", "delivery_status",
        "acknowledged_by", "acknowledged_at", "first_seen", "last_seen",
        "created_at", "updated_at"
    ]
    extra_cols = ["escalation_level", "channel_used", "suppression_until", "escalation_stopped"]
    for col in extra_cols:
        if col in _EXISTING_COLUMNS:
            cols.append(col)
            
    sql = f"SELECT {', '.join(cols)} FROM notifications WHERE notification_fingerprint = %s LIMIT 1"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (fingerprint,))
            row = cursor.fetchone()
            if row:
                return dict(zip(cols, row))
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to get notification by fingerprint={fingerprint}: {exc}")
        raise

def get_notification_by_id(notification_id: str) -> dict | None:
    """
    Finds a notification by its notification_id, dynamically selecting only existing columns.
    """
    _ensure_schema_loaded()
    cols = [
        "id", "notification_id", "alert_id", "notification_fingerprint",
        "severity", "recipient_group", "status", "occurrence_count",
        "delivery_attempts", "last_delivery_attempt", "delivery_status",
        "acknowledged_by", "acknowledged_at", "first_seen", "last_seen",
        "created_at", "updated_at"
    ]
    extra_cols = ["escalation_level", "channel_used", "suppression_until", "escalation_stopped"]
    for col in extra_cols:
        if col in _EXISTING_COLUMNS:
            cols.append(col)
            
    sql = f"SELECT {', '.join(cols)} FROM notifications WHERE notification_id = %s LIMIT 1"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (notification_id,))
            row = cursor.fetchone()
            if row:
                return dict(zip(cols, row))
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to get notification by id={notification_id}: {exc}")
        raise

def update_notification_status(
    notification_id: str,
    status: str,
    occurrence_count: int | None = None,
    delivery_status: str | None = None,
    channel_used: str | None = None,
    suppression_until: datetime | None = None,
    escalation_level: int | None = None,
    escalation_stopped: bool | None = None,
    updated_at: datetime | None = None,
) -> None:
    """
    Updates the status and specified columns for a notification.
    Dynamically updates only columns that are present in the schema.
    """
    _ensure_schema_loaded()
    now = datetime.now(timezone.utc)
    u_time = updated_at or now
    updates = {
        "status": status,
        "updated_at": u_time,
    }
    
    if occurrence_count is not None:
        updates["occurrence_count"] = occurrence_count
    if delivery_status is not None:
        updates["delivery_status"] = delivery_status
        
    optional_fields = {
        "channel_used": channel_used,
        "suppression_until": suppression_until,
        "escalation_level": escalation_level,
        "escalation_stopped": escalation_stopped,
    }
    for field, val in optional_fields.items():
        if val is not None and field in _EXISTING_COLUMNS:
            updates[field] = val
            
    set_clauses = []
    vals = []
    for col, val in updates.items():
        set_clauses.append(f"{col} = %s")
        vals.append(val)
        
    vals.append(notification_id)
    sql = f"""
        UPDATE notifications
        SET {", ".join(set_clauses)}
        WHERE notification_id = %s
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, vals)
    except Exception as exc:
        logger.error(f"[DB] Failed to update notification status for id={notification_id}: {exc}")
        raise

def acknowledge_notification(notification_id_or_alert_id: str, acknowledged_by: str) -> None:
    """
    Acknowledges a notification by changing status to 'acknowledged'.
    """
    _ensure_schema_loaded()
    now = datetime.now(timezone.utc)
    
    set_clauses = ["status = %s", "acknowledged_by = %s", "acknowledged_at = %s", "updated_at = %s"]
    vals = ["acknowledged", acknowledged_by, now, now]
    
    if "escalation_stopped" in _EXISTING_COLUMNS:
        set_clauses.append("escalation_stopped = TRUE")
        
    sql = f"""
        UPDATE notifications
        SET {", ".join(set_clauses)}
        WHERE notification_id = %s OR alert_id = %s
    """
    full_vals = vals + [notification_id_or_alert_id, notification_id_or_alert_id]
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, full_vals)
    except Exception as exc:
        logger.error(f"[DB] Failed to acknowledge notification id_or_alert_id={notification_id_or_alert_id}: {exc}")
        raise

def stop_escalation(notification_id_or_alert_id: str) -> None:
    """
    Stops further escalation logic by setting escalation_stopped = TRUE if column exists.
    """
    _ensure_schema_loaded()
    if "escalation_stopped" not in _EXISTING_COLUMNS:
        logger.warning(f"[DB] escalation_stopped column is missing. Cannot persist stop_escalation to DB.")
        return
        
    now = datetime.now(timezone.utc)
    sql = """
        UPDATE notifications
        SET escalation_stopped = TRUE, updated_at = %s
        WHERE notification_id = %s OR alert_id = %s
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (now, notification_id_or_alert_id, notification_id_or_alert_id))
    except Exception as exc:
        logger.error(f"[DB] Failed to stop escalation for id_or_alert_id={notification_id_or_alert_id}: {exc}")
        raise

def increment_delivery_attempts(notification_id: str, delivery_status: str) -> None:
    """
    Increments delivery attempts and updates last attempt timestamp.
    """
    now = datetime.now(timezone.utc)
    sql = """
        UPDATE notifications
        SET delivery_attempts = delivery_attempts + 1,
            last_delivery_attempt = %s,
            delivery_status = %s,
            updated_at = %s
        WHERE notification_id = %s
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (now, delivery_status, now, notification_id))
    except Exception as exc:
        logger.error(f"[DB] Failed to increment delivery attempts for notification_id={notification_id}: {exc}")
        raise

def create_escalation_event(
    escalation_id: str,
    notification_id: str,
    alert_id: str,
    escalation_level: int,
    escalation_target: str,
    escalation_reason: str,
    acknowledged: bool = False
) -> int:
    """
    Inserts a new record into notification_escalations.
    """
    now = datetime.now(timezone.utc)
    sql = """
        INSERT INTO notification_escalations (
            escalation_id, notification_id, alert_id, escalation_level,
            escalation_target, escalation_reason, acknowledged, escalated_at, created_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        ) RETURNING id
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (escalation_id, notification_id, alert_id, escalation_level, escalation_target, escalation_reason, acknowledged, now, now))
            row = cursor.fetchone()
            return row[0] if row else 0
    except Exception as exc:
        logger.error(f"[DB] Failed to create escalation event: {exc}")
        raise

def has_escalation_event(notification_id: str, escalation_level: int) -> bool:
    """
    Checks if a given escalation level was already triggered for a notification.
    """
    sql = """
        SELECT COUNT(id) FROM notification_escalations
        WHERE notification_id = %s AND escalation_level = %s
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (notification_id, escalation_level))
            row = cursor.fetchone()
            return (row[0] > 0) if row else False
    except Exception as exc:
        logger.error(f"[DB] Failed to check escalation event: {exc}")
        raise

def create_history_entry(
    notification_id: str,
    alert_id: str,
    recipient_email: str | None,
    recipient_role: str | None,
    severity: str,
    delivery_status: str,
    escalation_level: int,
    sent_at: datetime | None = None,
    acknowledged_at: datetime | None = None
) -> int:
    """
    Inserts a record into notification_history.
    """
    now = datetime.now(timezone.utc)
    sql = """
        INSERT INTO notification_history (
            notification_id, alert_id, recipient_email, recipient_role,
            severity, delivery_status, escalation_level, sent_at, acknowledged_at, created_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        ) RETURNING id
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (notification_id, alert_id, recipient_email, recipient_role, severity, delivery_status, escalation_level, sent_at, acknowledged_at, now))
            row = cursor.fetchone()
            return row[0] if row else 0
    except Exception as exc:
        logger.error(f"[DB] Failed to create history entry: {exc}")
        raise

def get_failed_notifications_for_retry(max_attempts: int, retry_cutoff: datetime) -> list[dict]:
    """
    Retrieves notifications in 'failed' status that have not reached max attempts and are ready for retry.
    """
    _ensure_schema_loaded()
    cols = [
        "id", "notification_id", "alert_id", "notification_fingerprint",
        "severity", "recipient_group", "status", "occurrence_count",
        "delivery_attempts", "last_delivery_attempt", "delivery_status",
        "acknowledged_by", "acknowledged_at", "first_seen", "last_seen",
        "created_at", "updated_at"
    ]
    extra_cols = ["escalation_level", "channel_used", "suppression_until", "escalation_stopped"]
    for col in extra_cols:
        if col in _EXISTING_COLUMNS:
            cols.append(col)
            
    where_clause = "status = 'failed' AND delivery_attempts < %s AND (last_delivery_attempt IS NULL OR last_delivery_attempt <= %s)"
    if "escalation_stopped" in _EXISTING_COLUMNS:
        where_clause += " AND (escalation_stopped = FALSE OR escalation_stopped IS NULL)"
        
    sql = f"SELECT {', '.join(cols)} FROM notifications WHERE {where_clause}"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (max_attempts, retry_cutoff))
            rows = cursor.fetchall()
            return [dict(zip(cols, r)) for r in rows]
    except Exception as exc:
        logger.error(f"[DB] Failed to query failed notifications for retry: {exc}")
        raise

def get_pending_batch_notifications(severities: list[str], max_age_minutes: int) -> list[dict]:
    """
    Retrieves notifications in 'pending' status for batch processing (P3/P4).
    """
    _ensure_schema_loaded()
    cols = [
        "id", "notification_id", "alert_id", "notification_fingerprint",
        "severity", "recipient_group", "status", "occurrence_count",
        "delivery_attempts", "last_delivery_attempt", "delivery_status",
        "acknowledged_by", "acknowledged_at", "first_seen", "last_seen",
        "created_at", "updated_at"
    ]
    extra_cols = ["escalation_level", "channel_used", "suppression_until", "escalation_stopped"]
    for col in extra_cols:
        if col in _EXISTING_COLUMNS:
            cols.append(col)
            
    where_clause = "status = 'pending' AND severity = ANY(%s)"
    if "escalation_stopped" in _EXISTING_COLUMNS:
        where_clause += " AND (escalation_stopped = FALSE OR escalation_stopped IS NULL)"
        
    sql = f"SELECT {', '.join(cols)} FROM notifications WHERE {where_clause}"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (severities,))
            rows = cursor.fetchall()
            return [dict(zip(cols, r)) for r in rows]
    except Exception as exc:
        logger.error(f"[DB] Failed to query pending batch notifications: {exc}")
        raise

def update_daily_metric(column_name: str, increment_by: int = 1) -> None:
    """
    Increments a specific metrics count in notification_metrics for the current date.
    Uses a safe check and insert/update logic.
    """
    valid_cols = {"total_sent", "total_failed", "total_suppressed", "total_escalated", "total_retried"}
    if column_name not in valid_cols:
        raise ValueError(f"Invalid metrics column name: {column_name}")
        
    now_date = datetime.now(timezone.utc).date()
    created_at = datetime.now(timezone.utc)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM notification_metrics WHERE metric_date = %s", (now_date,))
            row = cursor.fetchone()
            if row:
                cursor.execute(f"""
                    UPDATE notification_metrics
                    SET {column_name} = COALESCE({column_name}, 0) + %s
                    WHERE metric_date = %s
                """, (increment_by, now_date))
            else:
                cursor.execute(f"""
                    INSERT INTO notification_metrics (metric_date, total_sent, total_failed, total_suppressed, total_escalated, total_retried, avg_delivery_time_seconds, created_at)
                    VALUES (%s, 0, 0, 0, 0, 0, 0.0, %s)
                """, (now_date, created_at))
                cursor.execute(f"""
                    UPDATE notification_metrics
                    SET {column_name} = %s
                    WHERE metric_date = %s
                """, (increment_by, now_date))
    except Exception as exc:
        logger.error(f"[DB] Failed to update daily metric {column_name}: {exc}")
        raise

def update_daily_avg_delivery_time(seconds: float) -> None:
    """
    Calculates and updates running daily average delivery time.
    """
    now_date = datetime.now(timezone.utc).date()
    created_at = datetime.now(timezone.utc)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT total_sent, avg_delivery_time_seconds FROM notification_metrics WHERE metric_date = %s", (now_date,))
            row = cursor.fetchone()
            if row:
                total_sent = row[0] or 1
                current_avg = float(row[1] or 0.0)
                if total_sent <= 1:
                    new_avg = seconds
                else:
                    new_avg = ((current_avg * (total_sent - 1)) + seconds) / total_sent
                
                cursor.execute("""
                    UPDATE notification_metrics
                    SET avg_delivery_time_seconds = %s
                    WHERE metric_date = %s
                """, (new_avg, now_date))
            else:
                cursor.execute("""
                    INSERT INTO notification_metrics (metric_date, total_sent, total_failed, total_suppressed, total_escalated, total_retried, avg_delivery_time_seconds, created_at)
                    VALUES (%s, 1, 0, 0, 0, 0, %s, %s)
                """, (now_date, seconds, created_at))
    except Exception as exc:
        logger.error(f"[DB] Failed to update daily average delivery time: {exc}")
        raise

def get_daily_metrics() -> dict:
    """
    Fetches the metric counts for the current date.
    """
    now_date = datetime.now(timezone.utc).date()
    sql = """
        SELECT metric_date, total_sent, total_failed, total_suppressed, total_escalated, total_retried, avg_delivery_time_seconds
        FROM notification_metrics
        WHERE metric_date = %s
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (now_date,))
            row = cursor.fetchone()
            if row:
                return {
                    "metric_date": row[0],
                    "total_sent": row[1],
                    "total_failed": row[2],
                    "total_suppressed": row[3],
                    "total_escalated": row[4],
                    "total_retried": row[5],
                    "avg_delivery_time_seconds": float(row[6] or 0.0),
                }
            return {
                "metric_date": now_date,
                "total_sent": 0,
                "total_failed": 0,
                "total_suppressed": 0,
                "total_escalated": 0,
                "total_retried": 0,
                "avg_delivery_time_seconds": 0.0,
            }
    except Exception as exc:
        logger.error(f"[DB] Failed to get daily metrics: {exc}")
        raise

def get_active_notifications_for_escalation() -> list[dict]:
    """
    Retrieves notifications in status 'sent', 'delivered', 'escalated', or 'suppressed' that are active.
    """
    _ensure_schema_loaded()
    cols = [
        "id", "notification_id", "alert_id", "notification_fingerprint",
        "severity", "recipient_group", "status", "occurrence_count",
        "delivery_attempts", "last_delivery_attempt", "delivery_status",
        "acknowledged_by", "acknowledged_at", "first_seen", "last_seen",
        "created_at", "updated_at"
    ]
    extra_cols = ["escalation_level", "channel_used", "suppression_until", "escalation_stopped"]
    for col in extra_cols:
        if col in _EXISTING_COLUMNS:
            cols.append(col)
            
    where_clause = "status IN ('sent', 'delivered', 'escalated', 'suppressed')"
    if "escalation_stopped" in _EXISTING_COLUMNS:
        where_clause += " AND (escalation_stopped = FALSE OR escalation_stopped IS NULL)"
        
    sql = f"SELECT {', '.join(cols)} FROM notifications WHERE {where_clause}"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            return [dict(zip(cols, r)) for r in rows]
    except Exception as exc:
        logger.error(f"[DB] Failed to query active notifications for escalation: {exc}")
        raise

def delete_notification(notification_id: str) -> None:
    """
    Deletes a notification from the notifications table.
    """
    sql = "DELETE FROM notifications WHERE notification_id = %s"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (notification_id,))
    except Exception as exc:
        logger.error(f"[DB] Failed to delete notification id={notification_id}: {exc}")
        raise
