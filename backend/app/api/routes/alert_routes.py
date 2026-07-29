"""
Alert API Routes — Exposes paginated, filterable, searchable alert listing
from the existing alerts table. Read-only. Does not modify alert generation.
"""

from fastapi import APIRouter, HTTPException, Query
from app.database import alert_repository
from app.utils.logger import logger

router = APIRouter(tags=["Alerts"])


@router.get("/alerts")
async def list_alerts(
    severity: str | None = Query(None, description="Filter by severity (critical, high, medium, low)"),
    status: str | None = Query(None, description="Filter by status (open, acknowledged, investigating, resolved, closed)"),
    source_ip: str | None = Query(None, description="Filter by source IP (partial match)"),
    source: str | None = Query(None, description="Filter by log source (partial match)"),
    search: str | None = Query(None, description="Free-text search across alert_id, title, IP, source, host, username, rule_matches"),
    sort_by: str = Query("created_at", description="Sort column"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
):
    """
    Returns paginated alerts from the database with total count.
    Response: { "total": int, "alerts": [...] }
    """
    try:
        result = alert_repository.list_alerts(
            severity=severity,
            status=status,
            source_ip=source_ip,
            source=source,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=limit,
        )
        # Serialize datetime fields to ISO strings
        for alert in result["alerts"]:
            for key in ("first_seen", "last_seen", "created_at", "updated_at",
                        "acknowledged_at", "resolved_at", "closed_at"):
                if alert.get(key) is not None:
                    alert[key] = alert[key].isoformat()
        return result
    except Exception as exc:
        logger.error(f"[Alerts API] Failed to list alerts: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """
    Returns a single alert by alert_id (e.g. ALT-20260728-0001) or by database id.
    """
    try:
        # Try by alert_id string first
        alert = alert_repository.get_alert_by_alert_id(alert_id)
        if not alert:
            # Try by numeric database id
            try:
                db_id = int(alert_id)
                alert = alert_repository.get_alert_by_db_id(db_id)
            except ValueError:
                pass

        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

        # Serialize datetime fields
        for key in ("first_seen", "last_seen", "created_at", "updated_at",
                    "acknowledged_at", "resolved_at", "closed_at"):
            if alert.get(key) is not None:
                alert[key] = alert[key].isoformat()

        return alert
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"[Alerts API] Failed to get alert {alert_id}: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))
