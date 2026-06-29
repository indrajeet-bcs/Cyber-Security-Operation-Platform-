"""
Rule repository — handles all PostgreSQL read operations for the `detection_rules` table.

Uses raw SQL via psycopg2 and the get_connection context manager.
Identical pattern to log_repository.py — no ORM, no model definitions.

Table columns (created manually via DBeaver):
    id, rule_name, rule_code, rule_type, severity, source_type,
    event_type_pattern, message_pattern, threshold_count,
    threshold_minutes, risk_score, is_enabled, created_by,
    created_at, updated_at
"""

from app.database.connection import get_connection
from app.utils.logger import logger

# ---------------------------------------------------------------------------
# SQL Queries
# ---------------------------------------------------------------------------

_GET_ENABLED_RULES_SQL = """
    SELECT
        id,
        rule_name,
        rule_code,
        rule_type,
        severity,
        source_type,
        event_type_pattern,
        message_pattern,
        threshold_count,
        threshold_minutes,
        risk_score,
        is_enabled,
        created_by,
        created_at,
        updated_at
    FROM detection_rules
    WHERE is_enabled = TRUE
    ORDER BY id;
"""

_GET_RULE_BY_CODE_SQL = """
    SELECT
        id,
        rule_name,
        rule_code,
        rule_type,
        severity,
        source_type,
        event_type_pattern,
        message_pattern,
        threshold_count,
        threshold_minutes,
        risk_score,
        is_enabled,
        created_by,
        created_at,
        updated_at
    FROM detection_rules
    WHERE rule_code = %s
    LIMIT 1;
"""

# Column order matching both SELECT queries above
_COLUMNS = (
    "id",
    "rule_name",
    "rule_code",
    "rule_type",
    "severity",
    "source_type",
    "event_type_pattern",
    "message_pattern",
    "threshold_count",
    "threshold_minutes",
    "risk_score",
    "is_enabled",
    "created_by",
    "created_at",
    "updated_at",
)


def _row_to_dict(row: tuple) -> dict:
    """Converts a DB row tuple to a dict keyed by column name."""
    return dict(zip(_COLUMNS, row))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_enabled_rules() -> list[dict]:
    """
    Returns all enabled rules from the detection_rules table.

    Each rule is represented as a dict with keys matching the table columns.
    Returns an empty list if the table is empty or on DB failure.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_GET_ENABLED_RULES_SQL)
            rows = cursor.fetchall()
            rules = [_row_to_dict(r) for r in rows]
            logger.info(f"[RuleRepository] Loaded {len(rules)} enabled rules from database.")
            return rules
    except Exception as exc:
        logger.error(f"[RuleRepository] Failed to load enabled rules: {exc}")
        raise


def get_rule_by_code(rule_code: str) -> dict | None:
    """
    Returns a single rule dict by its rule_code, or None if not found.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(_GET_RULE_BY_CODE_SQL, (rule_code,))
            row = cursor.fetchone()
            if row:
                return _row_to_dict(row)
            return None
    except Exception as exc:
        logger.error(f"[RuleRepository] Failed to fetch rule '{rule_code}': {exc}")
        raise


def reload_rules() -> list[dict]:
    """
    Forces a fresh query to the database and returns all enabled rules.
    Intended to be called when the rule cache needs to be refreshed
    (e.g., after admin updates a rule via DBeaver or a management endpoint).
    """
    logger.info("[RuleRepository] Reloading rules from database...")
    return get_enabled_rules()
