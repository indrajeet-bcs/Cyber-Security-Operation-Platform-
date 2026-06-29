import json
import hashlib
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel
from app.database import invalid_log_repository
from app.services.validation_service import ValidationResult
from app.utils.logger import logger

class InvalidLogService:
    # Keys matching aliases
    _SOURCE_KEYS = ("source", "log_source", "origin", "facility")
    _EVENT_TYPE_KEYS = ("event_type", "type", "event", "action", "category")
    _MESSAGE_KEYS = ("message", "msg", "log", "text", "description")
    _TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "event_time", "datetime")

    def quarantine_invalid_log(self, raw: Any, val_res: ValidationResult) -> dict:
        """
        Calculates hash, checks for duplicates, and quarantines the invalid log payload.
        Returns a dictionary to be returned directly from the endpoint.
        """
        # 1. Parse payload to extract fields safely for hash and database insert
        data = {}
        raw_payload_str = ""
        
        if isinstance(raw, str):
            raw_payload_str = raw
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
        elif hasattr(raw, "model_dump"):
            data = raw.model_dump()
            raw_payload_str = raw.model_dump_json()
        elif isinstance(raw, dict):
            data = raw
            try:
                raw_payload_str = json.dumps(raw)
            except Exception:
                raw_payload_str = str(raw)
        else:
            raw_payload_str = str(raw)

        # 2. Extract fields for hash computation
        source = self._pick_str(data, self._SOURCE_KEYS)
        event_type = self._pick_str(data, self._EVENT_TYPE_KEYS)
        message = self._pick_str(data, self._MESSAGE_KEYS)
        timestamp = self._pick_value(data, self._TIMESTAMP_KEYS)
        
        # 3. Generate quarantine hash
        source_hash_str = str(source or '')
        event_type_hash_str = str(event_type or '')
        message_hash_str = str(message or '')
        timestamp_hash_str = str(timestamp or '')
        
        hash_input = f"{source_hash_str}{event_type_hash_str}{message_hash_str}{timestamp_hash_str}"
        quarantine_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

        rejection_reason = val_res.errors[0] if val_res.errors else "Invalid log"
        
        # 4. Resolve collector name
        collector_name = source
        if not collector_name and isinstance(raw, BaseModel) and hasattr(raw, "metadata") and raw.metadata:
            collector_name = raw.metadata.get("collector_name") or raw.metadata.get("collector")
        elif not collector_name and isinstance(data, dict):
            meta = data.get("metadata")
            if isinstance(meta, dict):
                collector_name = meta.get("collector_name") or meta.get("collector")

        # 5. Handle duplicate check & database operation (with try-except for error isolation)
        try:
            existing = invalid_log_repository.find_by_quarantine_hash(quarantine_hash)
            if existing:
                logger.info(
                    f"[INFO] Duplicate invalid log detected: source={source or 'unknown'} "
                    f"stage={val_res.validation_stage} reason={rejection_reason} "
                    f"hash={quarantine_hash}"
                )
                invalid_log_repository.increment_quarantine_count(existing["id"])
            else:
                invalid_log_repository.insert_invalid_log(
                    source=source,
                    raw_payload=raw_payload_str,
                    validation_status=val_res.status,
                    validation_errors=val_res.errors,
                    validation_warnings=val_res.warnings,
                    validation_stage=val_res.validation_stage,
                    quarantine_hash=quarantine_hash,
                    quarantined_count=1,
                    received_at=datetime.now(timezone.utc),
                    collector_name=collector_name,
                    rejection_reason=rejection_reason
                )
                logger.info(
                    f"[INFO] Invalid log stored in quarantine table: source={source or 'unknown'} "
                    f"stage={val_res.validation_stage} reason={rejection_reason} "
                    f"hash={quarantine_hash}"
                )
        except Exception as exc:
            # Error isolation: log but do not crash the application
            logger.error(
                f"[DB] Error writing to quarantine: {exc}. "
                f"Quarantine bypassed to keep service alive. "
                f"Payload: {raw_payload_str[:200]}"
            )

        return {
            "status": "quarantined",
            "reason": rejection_reason
        }

    def _pick_value(self, data: dict[str, Any], keys: tuple[str, ...]) -> Any:
        for key in keys:
            if key in data and data[key] is not None:
                return data[key]
        return None

    def _pick_str(self, data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
        value = self._pick_value(data, keys)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

invalid_log_service = InvalidLogService()
