import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from app.database import unknown_log_repository
from app.schemas.log import RawLogIngest
from app.utils.logger import logger

class UnknownLogService:
    """
    Handles unknown logs processing, duplicate checking, hashing, and persistence.
    """

    def save_unknown_log(
        self,
        raw: RawLogIngest,
        parse_result: dict[str, Any],
        classification_result: dict[str, Any]
    ) -> None:
        """
        Calculates hash, checks for duplicates, and stores the unknown log.
        Database exceptions are isolated so they do not crash the ingestion pipeline.
        """
        source_str = str(raw.source or "")
        message_str = str(raw.message or "")
        event_type_str = str(raw.event_type or "")

        # 1. Generate deterministic SHA256 hash from source, message, event_type
        hash_input = f"{source_str}{message_str}{event_type_str}"
        unknown_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        # 2. Extract raw payload dict safely (ensuring valid JSON for JSONB column)
        raw_payload_dict = {}
        if hasattr(raw, "model_dump"):
            raw_payload_dict = raw.model_dump()
        elif isinstance(raw, dict):
            raw_payload_dict = raw
        elif isinstance(raw, str):
            try:
                raw_payload_dict = json.loads(raw)
            except Exception:
                raw_payload_dict = {"message": raw}
        else:
            raw_payload_dict = {"payload": str(raw)}
        raw_payload_str = json.dumps(raw_payload_dict, default=str)

        # 3. Resolve collector name based on source
        source_lower = source_str.lower()
        if "chrome" in source_lower:
            collector_name = "chrome_browser_collector"
        elif "docker" in source_lower:
            collector_name = "docker_collector"
        elif "windows" in source_lower:
            collector_name = "windows_event_collector"
        elif "syslog" in source_lower:
            collector_name = "syslog_collector"
        elif "firewall" in source_lower:
            collector_name = "firewall_collector"
        else:
            cleaned = source_lower.replace("-", "_").replace(" ", "_")
            if not cleaned:
                collector_name = "unknown_collector"
            elif not cleaned.endswith("_collector"):
                collector_name = f"{cleaned}_collector"
            else:
                collector_name = cleaned

        # 4. Resolve confidence integers safely
        # Convert float (0.0-1.0) parser confidence to integer percentage (0-100)
        p_conf_float = parse_result.get("parsing_confidence")
        parser_confidence = int(p_conf_float * 100) if p_conf_float is not None else 100
        
        detection_confidence = int(classification_result.get("confidence") or 20)

        # 5. Handle duplicate check & DB operation
        try:
            existing = unknown_log_repository.find_by_unknown_hash(unknown_hash)
            if existing:
                unknown_log_repository.increment_occurrence_count(existing["id"])
            else:
                now_ts = datetime.now(timezone.utc)
                unknown_log_repository.insert_unknown_log(
                    source=raw.source,
                    raw_payload=raw_payload_str,
                    detected_format=parse_result.get("detected_format") or "text",
                    parser_confidence=parser_confidence,
                    classification_reason=classification_result.get("classification_reason") or "No matching classifier",
                    received_at=now_ts,
                    collector_name=collector_name,
                    unknown_hash=unknown_hash,
                    occurrence_count=1,
                    log_type="unknown",
                    detection_confidence=detection_confidence,
                    first_seen=now_ts
                )
            # Log successful save / increment
            logger.info("[INFO] Unknown log stored for future analysis")
        except Exception as exc:
            # Error isolation: log error but do not crash the pipeline
            logger.error(
                f"[DB] Error writing to unknown_logs table: {exc}. "
                f"Bypassed to keep service alive. Payload hash: {unknown_hash}"
            )

unknown_log_service = UnknownLogService()
