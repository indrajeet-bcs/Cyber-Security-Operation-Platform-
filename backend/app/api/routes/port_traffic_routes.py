"""
Port Traffic Analysis & Reporting Routes — FastAPI API router for port traffic analysis.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query

from app.database import port_traffic_repository
from app.schemas.port_traffic import (
    PortTrafficIngestRequest,
    PortTrafficReportResponse,
    LivePortStatusResponse,
)
from app.services.port_traffic_analysis_service import port_traffic_analysis_service
from app.utils.logger import logger

router = APIRouter(prefix="/port-traffic", tags=["Port Traffic Analysis"])


@router.post("/record", status_code=201)
async def record_normal_traffic(payload: PortTrafficIngestRequest):
    """
    Ingests periodic normal port traffic activity history into port_traffic_records.
    Decoupled from security threshold alerts.
    """
    try:
        records_dicts = [r.model_dump() for r in payload.records]
        inserted_ids = port_traffic_repository.bulk_insert_port_traffic_records(
            monitored_port=payload.monitored_port,
            window_start=payload.window_start,
            window_end=payload.window_end,
            records=records_dicts,
        )

        return {
            "status": "success",
            "message": f"Inserted {len(inserted_ids)} records for port {payload.monitored_port}",
            "inserted_count": len(inserted_ids),
        }
    except Exception as exc:
        logger.error(f"[API] Error recording port traffic history: {exc}")
        raise HTTPException(
            status_code=500, detail=f"Failed to store port traffic records: {str(exc)}"
        )


@router.get("/monitored-ports", response_model=List[int])
async def get_monitored_ports():
    """Returns list of all monitored ports that have traffic data."""
    try:
        return port_traffic_analysis_service.get_monitored_ports()
    except Exception as exc:
        logger.error(f"[API] Error fetching monitored ports: {exc}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch monitored ports: {str(exc)}"
        )


@router.get("/report", response_model=PortTrafficReportResponse)
async def get_port_traffic_report(
    port: int = Query(..., description="Monitored port number, e.g. 8080"),
    start_time: Optional[datetime] = Query(
        None, description="Start of monitoring window (ISO format)"
    ),
    end_time: Optional[datetime] = Query(
        None, description="End of monitoring window (ISO format)"
    ),
    bucket_minutes: int = Query(
        5, ge=1, le=60, description="Timeline bucket resolution in minutes"
    ),
):
    """
    Generates a factual traffic analysis report for a monitored port across a specified window.
    """
    now = datetime.now(timezone.utc)
    if not end_time:
        end_time = now
    if not start_time:
        start_time = end_time - timedelta(hours=1)

    if start_time >= end_time:
        raise HTTPException(
            status_code=400, detail="start_time must be earlier than end_time"
        )

    try:
        report = port_traffic_analysis_service.generate_report(
            port=port,
            start_time=start_time,
            end_time=end_time,
            bucket_minutes=bucket_minutes,
        )
        return report
    except Exception as exc:
        logger.error(
            f"[API] Error generating port traffic report for port {port}: {exc}"
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to generate port traffic report: {str(exc)}"
        )


@router.get("/live-status", response_model=LivePortStatusResponse)
async def get_live_status(
    hours: float = Query(6.0, ge=0.1, le=168.0, description="Hours of historical data to include")
):
    """
    Returns real-time OS socket state of monitored ports combined with historical 
    traffic from the last N hours.
    """
    try:
        return port_traffic_analysis_service.get_live_port_status(hours=hours)
    except Exception as exc:
        logger.error(f"[API] Error fetching live port status: {exc}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch live port status: {str(exc)}"
        )
