from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler

from app.api.routes import auth, logs, incident_routes
from app.core.config import settings
from app.utils.logger import logger

app = FastAPI(title=settings.app_name, debug=settings.debug)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(incident_routes.router, prefix="/api")


scheduler = BackgroundScheduler()


@app.on_event("startup")
async def startup():
    logger.info("SOC Platform API started")
    from app.database.notification_repository import validate_schema
    validate_schema()
    
    # Start periodic escalation scheduler
    from app.services.notification_engine_service import notification_engine_service
    scheduler.add_job(
        notification_engine_service.check_and_trigger_escalations,
        "interval",
        seconds=60,
        id="escalation_check_job"
    )
    scheduler.start()
    logger.info("Escalation background scheduler started")


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown()
    logger.info("Escalation background scheduler stopped")


# Trigger reload to load .env settings
@app.get("/health")
async def health():
    return {"status": "ok"} 