"""
Incident repository — handles all PostgreSQL operations for the incidents table.
Uses raw SQL via psycopg2 and the get_connection context manager.
"""

from datetime import datetime, timezone
from app.database.connection import get_connection
from app.utils.logger import logger

def _row_to_dict(cursor, row) -> dict:
    if not row:
        return {}
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

def get_next_incident_counter_for_day(date: datetime) -> int:
    """
    Returns the next counter for generating incident IDs like INC-YYYYMMDD-XXXX.
    """
    start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
    import datetime as dt
    end_of_day = start_of_day + dt.timedelta(days=1)
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(id) FROM incidents
                WHERE created_at >= %s AND created_at < %s
            """, (start_of_day, end_of_day))
            row = cursor.fetchone()
            count = row[0] if row else 0
            return count + 1
    except Exception as exc:
        logger.error(f"[DB] Failed to get incident counter: {exc}")
        return 1

def create_incident(
    incident_id: str,
    alert_id: int | None,
    title: str,
    severity: str,
    status: str = "open"
) -> int:
    """
    Inserts a new incident into the database and returns its primary key integer ID.
    """
    now = datetime.now(timezone.utc)
    sql = """
        INSERT INTO incidents (
            incident_id,
            alert_id,
            title,
            severity,
            status,
            created_at,
            updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s
        ) RETURNING id
    """
    values = (incident_id, alert_id, title, severity, status, now, now)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, values)
            row = cursor.fetchone()
            record_id = row[0] if row else 0
            logger.info(f"[DB] Incident created in PostgreSQL: incident_id={incident_id} severity={severity}")
            return record_id
    except Exception as exc:
        logger.error(f"[DB] Failed to insert incident: {exc}")
        raise

def get_incident(incident_id: str) -> dict | None:
    """
    Retrieves an incident by its incident_id string (e.g. INC-YYYYMMDD-0001).
    """
    sql = "SELECT * FROM incidents WHERE incident_id = %s LIMIT 1"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (incident_id,))
            row = cursor.fetchone()
            if row:
                return _row_to_dict(cursor, row)
            return None
    except Exception as exc:
        logger.error(f"[DB] Failed to get incident {incident_id}: {exc}")
        raise

def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0
) -> list[dict]:
    """
    Lists incidents matching optional filters, sorted by created_at DESC.
    """
    query = "SELECT * FROM incidents"
    params = []
    conditions = []
    
    if status:
        conditions.append("status = %s")
        params.append(status)
    if severity:
        conditions.append("severity = %s")
        params.append(severity)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [_row_to_dict(cursor, r) for r in rows]
    except Exception as exc:
        logger.error(f"[DB] Failed to list incidents: {exc}")
        raise

def update_status(incident_id: str, status: str) -> None:
    """
    Updates status and marks the appropriate state transition timestamp.
    """
    now = datetime.now(timezone.utc)
    set_clauses = ["status = %s", "updated_at = %s"]
    params = [status, now]
    
    if status == "acknowledged":
        set_clauses.append("acknowledged_at = %s")
        params.append(now)
    elif status == "investigating":
        set_clauses.append("investigating_at = %s")
        params.append(now)
    elif status == "closed":
        set_clauses.append("closed_at = %s")
        params.append(now)
        
    params.append(incident_id)
    sql = f"UPDATE incidents SET {', '.join(set_clauses)} WHERE incident_id = %s"
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, tuple(params))
            logger.info(f"[DB] Incident {incident_id} status updated to {status}")
    except Exception as exc:
        logger.error(f"[DB] Failed to update incident status {incident_id}: {exc}")
        raise

def assign_incident(
    incident_id: str,
    assigned_to: str,
    assigned_role: str,
    status: str | None = None,
    acknowledged_at: datetime | None = None,
    investigating_at: datetime | None = None
) -> None:
    """
    Assigns an analyst owner/role, and optionally updates status & timestamps.
    """
    now = datetime.now(timezone.utc)
    set_clauses = ["assigned_to = %s", "assigned_role = %s", "updated_at = %s"]
    params = [assigned_to, assigned_role, now]
    
    if status:
        set_clauses.append("status = %s")
        params.append(status)
    if acknowledged_at:
        set_clauses.append("acknowledged_at = %s")
        params.append(acknowledged_at)
    if investigating_at:
        set_clauses.append("investigating_at = %s")
        params.append(investigating_at)
        
    params.append(incident_id)
    sql = f"UPDATE incidents SET {', '.join(set_clauses)} WHERE incident_id = %s"
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, tuple(params))
            logger.info(f"[DB] Incident {incident_id} assigned to {assigned_to} ({assigned_role})")
    except Exception as exc:
        logger.error(f"[DB] Failed to assign incident {incident_id}: {exc}")
        raise

def append_note(incident_id: str, note: str) -> None:
    """
    Appends a note to the incidents text notes field using row-locking.
    """
    now = datetime.now(timezone.utc)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT notes FROM incidents WHERE incident_id = %s FOR UPDATE", (incident_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Incident {incident_id} not found")
            
            existing_notes = row[0]
            if existing_notes:
                updated_notes = f"{existing_notes}\n{note}"
            else:
                updated_notes = note
                
            cursor.execute("""
                UPDATE incidents
                SET notes = %s, updated_at = %s
                WHERE incident_id = %s
            """, (updated_notes, now, incident_id))
            logger.info(f"[DB] Note appended to incident {incident_id}")
    except Exception as exc:
        logger.error(f"[DB] Failed to append note to incident {incident_id}: {exc}")
        raise

def dashboard_summary() -> dict:
    """
    Aggregates incident counts by status and severity in a single optimized query,
    along with total logs and total incidents.
    """
    sql_incidents = """
        SELECT
            COUNT(CASE WHEN status = 'open' THEN 1 END) as open_incidents,
            COUNT(CASE WHEN status = 'acknowledged' THEN 1 END) as acknowledged_incidents,
            COUNT(CASE WHEN status = 'investigating' THEN 1 END) as investigating_incidents,
            COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed_incidents,
            COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_incidents,
            COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_incidents,
            COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_incidents,
            COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_incidents
        FROM incidents
    """
    sql_logs = "SELECT COUNT(*) FROM logs"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Execute incidents summary query
            cursor.execute(sql_incidents)
            inc_row = cursor.fetchone()
            
            # Execute logs count query
            cursor.execute(sql_logs)
            log_row = cursor.fetchone()
            total_logs = log_row[0] if log_row else 0
            
            if inc_row:
                open_inc = inc_row[0] or 0
                ack_inc = inc_row[1] or 0
                inv_inc = inc_row[2] or 0
                closed_inc = inc_row[3] or 0
                
                # Formula: open + acknowledged + investigating + closed
                total_inc = open_inc + ack_inc + inv_inc + closed_inc
                
                return {
                    "total_incidents": total_inc,
                    "total_logs": total_logs,
                    "open_incidents": open_inc,
                    "acknowledged_incidents": ack_inc,
                    "investigating_incidents": inv_inc,
                    "closed_incidents": closed_inc,
                    "critical_incidents": inc_row[4] or 0,
                    "high_incidents": inc_row[5] or 0,
                    "medium_incidents": inc_row[6] or 0,
                    "low_incidents": inc_row[7] or 0,
                }
            return {
                "total_incidents": 0,
                "total_logs": total_logs,
                "open_incidents": 0,
                "acknowledged_incidents": 0,
                "investigating_incidents": 0,
                "closed_incidents": 0,
                "critical_incidents": 0,
                "high_incidents": 0,
                "medium_incidents": 0,
                "low_incidents": 0,
            }
    except Exception as exc:
        logger.error(f"[DB] Failed to calculate dashboard summary: {exc}")
        raise
