from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.schemas.log import LogResponse, RawLogIngest
from app.services.log_service import log_service

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/", response_model=list[LogResponse])
async def list_logs(skip: int = 0, limit: int = 100):
    return log_service.list_logs(skip=skip, limit=limit)


@router.get("/{log_id}", response_model=LogResponse)
async def get_log(log_id: int):
    log = log_service.get_log(log_id)
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


@router.post("/", response_model=LogResponse)
async def ingest_log(payload: RawLogIngest):
    try:
        result = log_service.ingest_log(payload)

        # Duplicate detected — service returns a sentinel dict
        if isinstance(result, dict) and result.get("_duplicate"):
            return JSONResponse(
                status_code=409,
                content={
                    "message": "Duplicate log skipped",
                    "existing_log_id": result["existing_log_id"],
                },
            )

        # Quarantined invalid log detected
        if isinstance(result, dict) and result.get("status") == "quarantined":
            return JSONResponse(
                status_code=400,
                content=result,
            )

        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

