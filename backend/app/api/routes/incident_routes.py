"""
Incident API Routes — Declares all endpoints for incident operations.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from app.services.incident_service import incident_service

router = APIRouter(tags=["incidents"])

class AssignRequest(BaseModel):
    assigned_to: str
    assigned_role: str

class NoteRequest(BaseModel):
    note: str

@router.get("/incidents")
async def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    skip: int = 0,
    limit: int = 100
):
    try:
        return incident_service.list_incidents(status=status, severity=severity, skip=skip, limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/incident/{incident_id}")
async def get_incident(incident_id: str):
    try:
        incident = incident_service.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
        return incident
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post("/incident/{incident_id}/assign")
async def assign_incident(incident_id: str, payload: AssignRequest):
    try:
        return incident_service.assign_incident(
            incident_id=incident_id,
            assigned_to=payload.assigned_to,
            assigned_role=payload.assigned_role
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post("/incident/{incident_id}/close")
async def close_incident(incident_id: str):
    try:
        return incident_service.close_incident(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post("/incident/{incident_id}/notes")
async def add_note(incident_id: str, payload: NoteRequest):
    try:
        return incident_service.add_note(incident_id, payload.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/dashboard/summary")
async def get_dashboard_summary():
    try:
        return incident_service.dashboard_summary()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
