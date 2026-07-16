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


def initialize_database():
    import os
    import psycopg2
    logger.info("[DB] Starting automatic database schema initialization...")
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        schema_path = os.path.join(base_dir, "database", "schema.sql")
        
        if not os.path.exists(schema_path):
            logger.warning(f"[DB] Schema file not found at {schema_path}, skipping auto-init.")
            return
            
        with open(schema_path, "r") as f:
            sql = f.read()
            
        conn = psycopg2.connect(settings.database_url)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute(sql)
        logger.info("[DB] Database schema initialized successfully.")
        
        cursor.execute("SELECT COUNT(*) FROM detection_rules;")
        count = cursor.fetchone()[0]
        if count == 0:
            logger.info("[DB] detection_rules table is empty. Auto-seeding default rules and configurations...")
            _seed_defaults(cursor)
            
        cursor.close()
        conn.close()
    except Exception as exc:
        logger.error(f"[DB] Database initialization failed: {exc}")

def _seed_defaults(cursor):
    users = [
        ('analyst', 'alice@soc.local', 'dummy_hash_alice', 'analyst'),
        ('lead_analyst', 'bob@soc.local', 'dummy_hash_bob', 'lead_analyst'),
        ('soc_manager', 'charlie@soc.local', 'dummy_hash_charlie', 'soc_manager'),
        ('admin', 'admin@soc.local', 'dummy_hash_admin', 'admin')
    ]
    for username, email, pwd, role in users:
        cursor.execute(
            "INSERT INTO users (username, email, hashed_password, role) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING;",
            (username, email, pwd, role)
        )

    rules = [
        ("SQL Injection Attempt", "SQL_INJECTION", "pattern", "critical", "web", None, "/(union|select|insert|update|delete|drop|alter).*from/i", None, None, 90, True, "admin"),
        ("Malicious Binary Downloaded", "MALICIOUS_DOWNLOAD", "pattern", "high", "chrome", None, "/(\\.exe|\\.dll|\\.bat|\\.sh|\\.ps1) downloaded from untrusted/i", None, None, 80, True, "admin"),
        ("Suspicious Process Spawned", "SUSPICIOUS_PROCESS", "pattern", "high", "windows", None, "/whoami|net user|ipconfig|powershell -enc/i", None, None, 85, True, "admin"),
        ("Docker Container Command Execution", "SUSPICIOUS_DOCKER_EXEC", "pattern", "critical", "docker", None, "/docker exec.*(sh|bash|nc|curl|wget)/i", None, None, 95, True, "admin"),
        ("Multiple Failed Login Attempts", "FAILED_LOGIN_BURST", "threshold", "high", "auth", "login.failure", None, 3, 5, 75, True, "admin"),
        ("Reconnaissance Port Scan", "PORT_SCAN", "threshold", "medium", "firewall", "connection.rejected", None, 5, 2, 50, True, "admin")
    ]
    for r in rules:
        cursor.execute(
            """INSERT INTO detection_rules (
                rule_name, rule_code, rule_type, severity, source_type, 
                event_type_pattern, message_pattern, threshold_count, 
                threshold_minutes, risk_score, is_enabled, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING;""",
            r
        )

    policies = [
        ("Low Severity Policy", "low", "analyst", "lead_analyst", 30, "soc_manager", 60),
        ("Medium Severity Policy", "medium", "analyst", "lead_analyst", 15, "soc_manager", 30),
        ("High Severity Policy", "high", "lead_analyst", "soc_manager", 10, None, None),
        ("Critical Severity Policy", "critical", "lead_analyst", "soc_manager", 5, None, None),
    ]
    for p in policies:
        cursor.execute("SELECT COUNT(*) FROM notification_policies WHERE severity = %s;", (p[1],))
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                """INSERT INTO notification_policies (
                    policy_name, severity, initial_role, escalation_role, escalation_minutes,
                    second_escalation_role, second_escalation_minutes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s);""",
                p
            )

    recipients = [
        ("Alice Analyst", "alice@soc.local", "analyst", "Tier-1 SOC", "123-456-7890", "#soc-alerts"),
        ("Bob Lead Analyst", "bob@soc.local", "lead_analyst", "Incident Response", "123-456-7891", "#soc-escalations"),
        ("Charlie Manager", "charlie@soc.local", "soc_manager", "SOC Management", "123-456-7892", "#soc-priority"),
    ]
    for rec in recipients:
        cursor.execute("SELECT COUNT(*) FROM notification_recipients WHERE email = %s;", (rec[1],))
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                """INSERT INTO notification_recipients (
                    recipient_name, email, role, team, phone, slack_channel
                ) VALUES (%s, %s, %s, %s, %s, %s);""",
                rec
            )
    logger.info("[DB] Auto-seeded rules and configurations.")

@app.on_event("startup")
async def startup():
    logger.info("SOC Platform API started")
    initialize_database()
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