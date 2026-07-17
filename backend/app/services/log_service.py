from datetime import datetime, timezone

from app.schemas.log import LogResponse, NormalizedSOCLog, RawLogIngest
from app.services.normalization_service import normalization_service
from app.services.detection_service import detection_service
from app.services.validation_service import validation_service
from app.services.invalid_log_service import invalid_log_service
from app.services.parsing_service import parsing_service
from app.services.log_type_detection_service import log_type_detection_service
from app.services.unknown_log_service import unknown_log_service
from app.services.rule_engine_service import rule_engine_service
from app.services.correlation_service import correlation_service
from app.services.alert_engine_service import alert_engine_service
from app.database import log_repository
from app.utils.logger import logger


class LogService:
    """In-memory log store — persists normalized SOC events only."""

    def __init__(self) -> None:
        self._logs: dict[int, LogResponse] = {}
        self._next_id = 1

    def load_logs_from_db(self) -> None:
        """Loads historical logs from PostgreSQL into the in-memory cache on startup."""
        from app.database.connection import get_connection
        from app.schemas.log import DetectionResult, LogResponse
        import json
        
        logger.info("[LogService] Loading historical logs from PostgreSQL into RAM...")
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        id, source, host, event_type, message, severity, timestamp, 
                        source_ip, user_name, metadata, is_suspicious, 
                        detection_severity, detection_reason, ingested_at, record_number 
                    FROM logs
                    ORDER BY id ASC;
                """)
                rows = cursor.fetchall()
                
                loaded_count = 0
                max_id = 0
                for row in rows:
                    (
                        log_id, source, host, event_type, message, severity, timestamp,
                        source_ip, user_name, metadata_raw, is_suspicious,
                        detection_severity, detection_reason, ingested_at, record_number_raw
                    ) = row
                    
                    # Deserialize metadata
                    if isinstance(metadata_raw, str):
                        try:
                            metadata = json.loads(metadata_raw)
                        except Exception:
                            metadata = {}
                    elif isinstance(metadata_raw, dict):
                        metadata = metadata_raw
                    else:
                        metadata = {}

                    # Parse record_number
                    try:
                        record_number = int(record_number_raw) if record_number_raw is not None else None
                    except (ValueError, TypeError):
                        record_number = None

                    detection = None
                    if is_suspicious is not None or detection_severity is not None or detection_reason is not None:
                        detection = DetectionResult(
                            is_suspicious=bool(is_suspicious),
                            severity=detection_severity or "info",
                            reason=detection_reason
                        )

                    log_res = LogResponse(
                        id=log_id,
                        source=source or "unknown",
                        host=host,
                        event_type=event_type or "unknown",
                        message=message or "",
                        severity=severity or "info",
                        timestamp=timestamp,
                        source_ip=source_ip,
                        user=user_name,
                        metadata=metadata,
                        ingested_at=ingested_at,
                        detection=detection,
                        record_number=record_number
                    )
                    self._logs[log_id] = log_res
                    max_id = max(max_id, log_id)
                    loaded_count += 1
                
                if loaded_count > 0:
                    self._next_id = max_id + 1
                logger.info(f"[LogService] Successfully loaded {loaded_count} logs from PostgreSQL. Next Log ID: {self._next_id}")
        except Exception as exc:
            logger.error(f"[LogService] Failed to load logs from database on startup: {exc}")

    def list_logs(self, skip: int = 0, limit: int = 100) -> list[LogResponse]:
        ordered = sorted(self._logs.values(), key=lambda log: log.id, reverse=True)
        return ordered[skip : skip + limit]

    def get_log(self, log_id: int) -> LogResponse | None:
        return self._logs.get(log_id)

    def ingest_log(self, raw: RawLogIngest) -> LogResponse | dict:
        # --- Run Validation Enhancements ---
        validation_res = validation_service.validate(raw)

        # Safely determine the log source for logging and routing
        data = raw.model_dump() if hasattr(raw, "model_dump") else (dict(raw) if raw else {})
        source = data.get("source") or data.get("log_source") or data.get("origin") or data.get("facility") or "unknown"

        if validation_res.status == "INVALID":
            rejection_reason = validation_res.errors[0] if validation_res.errors else "Invalid log"
            logger.error(
                f"[ERROR] Log rejected by validation: source={source} "
                f"stage={validation_res.validation_stage} reason={rejection_reason}"
            )
            # Route to quarantine storage and stop processing
            return invalid_log_service.quarantine_invalid_log(raw, validation_res)

        elif validation_res.status == "WARNING":
            logger.warning(
                f"[WARNING] Validation warnings detected: source={source} "
                f"warnings={validation_res.warnings}"
            )
            # Attach validation warnings to the payload's metadata
            if hasattr(raw, "metadata"):
                if raw.metadata is None:
                    raw.metadata = {}
                meta = dict(raw.metadata)
                meta["validation_warnings"] = validation_res.warnings
                raw.metadata = meta
            elif isinstance(raw, dict):
                if "metadata" not in raw or raw["metadata"] is None:
                    raw["metadata"] = {}
                raw["metadata"]["validation_warnings"] = validation_res.warnings

        else:
            logger.info(f"[INFO] Validation passed: source={source}")

        # --- Advanced Parsing & Decoding Layer ---
        parse_result = parsing_service.parse_and_decode_log(raw)

        if parse_result["parsing_status"] == "failed" and not parse_result.get("payload"):
            # Completely unreadable — quarantine immediately
            from app.services.validation_service import ValidationResult
            logger.error(
                f"[ERROR] Unreadable payload quarantined: source={source}"
            )
            unreadable_result = ValidationResult(
                status="INVALID",
                errors=["Unreadable payload after parsing"],
                warnings=[],
                validation_stage="parsing"
            )
            return invalid_log_service.quarantine_invalid_log(raw, unreadable_result)

        # Merge parsed & decoded fields back into a RawLogIngest for normalization
        parsed_payload = parse_result["payload"]
        if parse_result.get("decoding_applied") or parse_result.get("detected_format") not in ("text", "unknown"):
            try:
                # Build a fresh RawLogIngest from merged fields
                # Preserve existing fields; override with parsed values where present
                raw_data = raw.model_dump() if hasattr(raw, "model_dump") else dict(raw)
                for field in ["source", "host", "event_type", "message", "severity", "timestamp", "source_ip", "user", "metadata"]:
                    if field in parsed_payload and parsed_payload[field] is not None:
                        raw_data[field] = parsed_payload[field]
                # Tag metadata with all parse_result fields
                meta = raw_data.get("metadata") or {}
                if not isinstance(meta, dict):
                    meta = {}
                meta["detected_format"] = parse_result["detected_format"]
                if parse_result.get("decoding_applied"):
                    meta["decoding_applied"] = True
                # New fields: ordered decode chain, SHA-256 fingerprint, confidence score
                if parse_result.get("decoding_chain"):
                    meta["decoding_chain"] = parse_result["decoding_chain"]
                if parse_result.get("event_fingerprint"):
                    meta["event_fingerprint"] = parse_result["event_fingerprint"]
                confidence = parse_result.get("parsing_confidence")
                if confidence is not None and confidence < 1.0:
                    meta["parsing_confidence"] = round(confidence, 2)
                raw_data["metadata"] = meta
                raw = RawLogIngest(**raw_data)
            except Exception as exc:
                logger.warning(f"[WARNING] Parsing failed to merge back into schema: {exc}")
                # Continue with original raw — normalization will handle best-effort
        else:
            # Plain text / unknown format: still tag event_fingerprint and detected_format
            # so every log record carries a fingerprint regardless of format.
            try:
                raw_data = raw.model_dump() if hasattr(raw, "model_dump") else dict(raw)
                meta = raw_data.get("metadata") or {}
                if not isinstance(meta, dict):
                    meta = {}
                meta["detected_format"] = parse_result["detected_format"]
                if parse_result.get("event_fingerprint"):
                    meta["event_fingerprint"] = parse_result["event_fingerprint"]
                raw_data["metadata"] = meta
                raw = RawLogIngest(**raw_data)
            except Exception as exc:
                logger.warning(f"[WARNING] Could not tag plain-text metadata: {exc}")

        # --- Automatic Log Type Detection Layer ---
        classification_result = log_type_detection_service.detect_log_type(raw, parse_result)
        
        # Attach classification result to metadata
        meta = raw.metadata or {}
        meta["log_classification"] = classification_result
        raw.metadata = meta

        # If log type is unknown, store it in unknown_logs table
        if classification_result.get("log_type") == "unknown":
            unknown_log_service.save_unknown_log(raw, parse_result, classification_result)

        normalized: NormalizedSOCLog = normalization_service.normalize(raw)

        # --- Advanced Rule Engine ---
        rule_matches = rule_engine_service.evaluate_rules(normalized)
        if rule_matches:
            meta = normalized.metadata if isinstance(normalized.metadata, dict) else {}
            meta["rule_matches"] = rule_matches
            normalized.metadata = meta

        # --- Advanced Correlation Engine ---
        try:
            correlation_matches = correlation_service.correlate(normalized)
            if correlation_matches:
                meta = normalized.metadata if isinstance(normalized.metadata, dict) else {}
                meta["correlation_matches"] = correlation_matches
                normalized.metadata = meta
        except Exception as exc:
            logger.error(
                f"[LogService] Correlation engine failed — continuing without correlation: {exc}"
            )

        # --- Resolve record_number ---
        # Priority: top-level field → metadata["record_number"] fallback
        record_number: int | None = raw.record_number
        if record_number is None and raw.metadata:
            meta_rn = raw.metadata.get("record_number")
            if meta_rn is not None:
                try:
                    record_number = int(meta_rn)
                except (ValueError, TypeError):
                    record_number = None

        # --- Duplicate check (only when record_number is present) ---
        if record_number is not None:
            for existing in self._logs.values():
                if (
                    existing.source == normalized.source
                    and existing.host == normalized.host
                    and existing.event_type == normalized.event_type
                    and existing.record_number == record_number
                ):
                    # Return sentinel dict so the route can respond with 409
                    return {"_duplicate": True, "existing_log_id": existing.id}

        detection_result = detection_service.analyze(normalized)

        # --- Alert Engine ---
        alert = alert_engine_service.generate_alert(normalized, detection_result)

        # --- Notification Engine ---
        if alert:
            try:
                from app.services.notification_engine_service import notification_engine_service
                notification = notification_engine_service.process_alert(alert)
                if notification:
                    if normalized.metadata is None:
                        normalized.metadata = {}
                    normalized.metadata["notification"] = {
                        "notification_id": notification["notification_id"],
                        "status": notification["status"],
                        "recipient_group": notification["recipient_group"],
                        "channel": notification.get("channel_used", "unknown"),
                        "escalation_level": notification.get("escalation_level", 0)
                    }
            except Exception as exc:
                logger.error(f"[ERROR] Notification processing failed: {exc}")

        log_id = self._next_id
        self._next_id += 1

        record = LogResponse(
            id=log_id,
            ingested_at=datetime.now(timezone.utc),
            detection=detection_result,
            record_number=record_number,
            **normalized.model_dump(exclude={"record_number"}),
        )
        self._logs[log_id] = record

        # --- Persist to PostgreSQL (safe — DB failure never crashes the API) ---
        try:
            log_repository.insert_log(record)
        except Exception as exc:
            logger.error(
                f"[LogService] PostgreSQL insert failed for log id={log_id} "
                f"record_number={record_number}: {exc}"
            )

        return record


log_service = LogService()
