-- ============================================================
-- SOC Platform - Full Database Schema
-- Run this against the soc_platform database to create all tables
-- ============================================================

-- ----------------------------------------------------------------
-- 1. logs
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS logs (
    id                  SERIAL PRIMARY KEY,
    source              TEXT,
    host                TEXT,
    event_type          TEXT,
    message             TEXT,
    severity            TEXT,
    timestamp           TIMESTAMPTZ,
    source_ip           TEXT,
    user_name           TEXT,
    metadata            JSONB,
    is_suspicious       BOOLEAN DEFAULT FALSE,
    detection_severity  TEXT,
    detection_reason    TEXT,
    ingested_at         TIMESTAMPTZ DEFAULT NOW(),
    record_number       TEXT
);

-- ----------------------------------------------------------------
-- 2. alerts
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id                      SERIAL PRIMARY KEY,
    alert_id                TEXT UNIQUE NOT NULL,
    alert_title             TEXT,
    alert_type              TEXT,
    severity                TEXT,
    priority                TEXT,
    confidence              INTEGER,
    risk_score              INTEGER,
    status                  TEXT DEFAULT 'open',
    occurrence_count        INTEGER DEFAULT 1,
    source                  TEXT,
    source_ip               TEXT,
    host                    TEXT,
    username                TEXT,
    event_fingerprint       TEXT,
    alert_fingerprint       TEXT UNIQUE NOT NULL,
    rule_matches            TEXT,
    correlation_matches     TEXT,
    first_seen              TIMESTAMPTZ,
    last_seen               TIMESTAMPTZ,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW(),
    acknowledged_at         TIMESTAMPTZ,
    resolved_at             TIMESTAMPTZ,
    closed_at               TIMESTAMPTZ
);

-- ----------------------------------------------------------------
-- 3. incidents
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                  SERIAL PRIMARY KEY,
    incident_id         TEXT UNIQUE NOT NULL,
    alert_id            INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    title               TEXT,
    severity            TEXT,
    status              TEXT DEFAULT 'open',
    assigned_to         TEXT,
    assigned_role       TEXT,
    notes               TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    acknowledged_at     TIMESTAMPTZ,
    investigating_at    TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ
);

-- ----------------------------------------------------------------
-- 4. detection_rules
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_rules (
    id                      SERIAL PRIMARY KEY,
    rule_name               TEXT NOT NULL,
    rule_code               TEXT UNIQUE NOT NULL,
    rule_type               TEXT,
    severity                TEXT,
    source_type             TEXT,
    event_type_pattern      TEXT,
    message_pattern         TEXT,
    threshold_count         INTEGER,
    threshold_minutes       INTEGER,
    risk_score              INTEGER,
    is_enabled              BOOLEAN DEFAULT TRUE,
    created_by              TEXT,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ----------------------------------------------------------------
-- 5. correlation_events
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation_events (
    id                      SERIAL PRIMARY KEY,
    correlation_id          TEXT UNIQUE NOT NULL,
    correlation_type        TEXT,
    severity                TEXT,
    confidence              INTEGER DEFAULT 0,
    risk_score              INTEGER DEFAULT 0,
    related_user            TEXT,
    related_source_ip       TEXT,
    related_host            TEXT,
    event_count             INTEGER DEFAULT 1,
    first_seen              TIMESTAMPTZ,
    last_seen               TIMESTAMPTZ,
    correlation_reason      TEXT,
    correlation_status      TEXT DEFAULT 'active',
    event_fingerprint       TEXT,
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ----------------------------------------------------------------
-- 6. invalid_logs (quarantine)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS invalid_logs (
    id                      SERIAL PRIMARY KEY,
    source                  TEXT,
    raw_payload             TEXT,
    validation_status       TEXT,
    validation_errors       TEXT,
    validation_warnings     TEXT,
    validation_stage        TEXT,
    quarantine_hash         TEXT UNIQUE,
    quarantined_count       INTEGER DEFAULT 1,
    received_at             TIMESTAMPTZ,
    collector_name          TEXT,
    rejection_reason        TEXT
);

-- ----------------------------------------------------------------
-- 7. unknown_logs
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS unknown_logs (
    id                      SERIAL PRIMARY KEY,
    source                  TEXT,
    raw_payload             TEXT,
    detected_format         TEXT,
    parser_confidence       INTEGER,
    classification_reason   TEXT,
    received_at             TIMESTAMPTZ,
    collector_name          TEXT,
    unknown_hash            TEXT UNIQUE,
    occurrence_count        INTEGER DEFAULT 1,
    log_type                TEXT,
    detection_confidence    INTEGER,
    first_seen              TIMESTAMPTZ
);

-- ----------------------------------------------------------------
-- 8. notification_policies
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_policies (
    id                          SERIAL PRIMARY KEY,
    policy_name                 TEXT NOT NULL,
    severity                    TEXT NOT NULL,
    initial_role                TEXT,
    escalation_role             TEXT,
    escalation_minutes          INTEGER DEFAULT 30,
    second_escalation_role      TEXT,
    second_escalation_minutes   INTEGER DEFAULT 60,
    is_active                   BOOLEAN DEFAULT TRUE,
    created_at                  TIMESTAMPTZ DEFAULT NOW()
);

-- ----------------------------------------------------------------
-- 9. notification_recipients
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_recipients (
    id                  SERIAL PRIMARY KEY,
    recipient_name      TEXT NOT NULL,
    email               TEXT,
    role                TEXT,
    team                TEXT,
    phone               TEXT,
    slack_channel       TEXT,
    is_active           BOOLEAN DEFAULT TRUE,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ----------------------------------------------------------------
-- 10. notifications
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id                          SERIAL PRIMARY KEY,
    notification_id             TEXT UNIQUE NOT NULL,
    alert_id                    TEXT,
    notification_fingerprint    TEXT UNIQUE,
    severity                    TEXT,
    recipient_group             TEXT,
    status                      TEXT DEFAULT 'pending',
    occurrence_count            INTEGER DEFAULT 1,
    delivery_attempts           INTEGER DEFAULT 0,
    last_delivery_attempt       TIMESTAMPTZ,
    delivery_status             TEXT,
    acknowledged_by             TEXT,
    acknowledged_at             TIMESTAMPTZ,
    first_seen                  TIMESTAMPTZ DEFAULT NOW(),
    last_seen                   TIMESTAMPTZ DEFAULT NOW(),
    escalation_level            INTEGER DEFAULT 0,
    channel_used                TEXT,
    suppression_until           TIMESTAMPTZ,
    escalation_stopped          BOOLEAN DEFAULT FALSE,
    created_at                  TIMESTAMPTZ DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ DEFAULT NOW()
);

-- ----------------------------------------------------------------
-- 11. users (for auth)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE,
    hashed_password TEXT NOT NULL,
    role            TEXT DEFAULT 'analyst',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
