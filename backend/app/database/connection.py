"""
Database connection helpers.
Reuses the existing SQLAlchemy engine defined in db.py.
Provides a simple context manager for raw SQL operations (INSERT, SELECT).
"""

from contextlib import contextmanager

from app.database.db import engine
from app.utils.logger import logger


@contextmanager
def get_connection():
    """
    Yields a raw DBAPI connection from the SQLAlchemy engine pool.
    Commits on success, rolls back on any exception, always closes.

    Usage:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO ...")
    """
    conn = engine.raw_connection()
    try:
        yield conn
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error(f"[DB] Transaction rolled back due to error: {exc}")
        raise
    finally:
        conn.close()
