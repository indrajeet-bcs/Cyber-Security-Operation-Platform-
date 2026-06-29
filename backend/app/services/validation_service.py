import json
import ipaddress
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel
from app.schemas.log import RawLogIngest

class ValidationResult:
    def __init__(self, status: str, errors: list[str], warnings: list[str], validation_stage: str):
        self.status = status
        self.errors = errors
        self.warnings = warnings
        self.validation_stage = validation_stage


class ValidationService:
    # Keys matching normalization service aliases
    _SOURCE_KEYS = ("source", "log_source", "origin", "facility")
    _EVENT_TYPE_KEYS = ("event_type", "type", "event", "action", "category")
    _MESSAGE_KEYS = ("message", "msg", "log", "text", "description")
    _SEVERITY_KEYS = ("severity", "level", "priority")
    _TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "event_time", "datetime")
    _SOURCE_IP_KEYS = ("source_ip", "ip", "src_ip", "client_ip", "remote_addr")
    
    _ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

    def validate(self, raw: Any) -> ValidationResult:
        errors = []
        warnings = []
        
        # 1. Check Empty Payload
        if raw is None:
            return ValidationResult(
                status="INVALID",
                errors=["Empty payload"],
                warnings=[],
                validation_stage="payload_check"
            )
            
        if isinstance(raw, str):
            stripped = raw.strip()
            if not stripped:
                return ValidationResult(
                    status="INVALID",
                    errors=["Empty payload"],
                    warnings=[],
                    validation_stage="payload_check"
                )
                
            # Check Oversized Payload (> 100 KB = 102400 bytes)
            if len(stripped.encode("utf-8")) > 102400:
                return ValidationResult(
                    status="INVALID",
                    errors=["Oversized payload"],
                    warnings=[],
                    validation_stage="payload_check"
                )
                
            # Check Malformed JSON
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return ValidationResult(
                    status="INVALID",
                    errors=[f"Malformed JSON payload: {exc}"],
                    warnings=[],
                    validation_stage="payload_check"
                )
        else:
            # It's a dict or RawLogIngest BaseModel
            if hasattr(raw, "model_dump"):
                data = raw.model_dump()
            elif isinstance(raw, dict):
                data = raw
            else:
                data = {}
                
            # Check Empty Payload (all values None or empty)
            if not data or all(v is None for v in data.values()):
                return ValidationResult(
                    status="INVALID",
                    errors=["Empty payload"],
                    warnings=[],
                    validation_stage="payload_check"
                )
                
            # Check Oversized Payload
            try:
                serialized = json.dumps(data)
                if len(serialized.encode("utf-8")) > 102400:
                    return ValidationResult(
                        status="INVALID",
                        errors=["Oversized payload"],
                        warnings=[],
                        validation_stage="payload_check"
                    )
            except Exception as exc:
                # If serialization fails, treat as invalid/unserializable
                return ValidationResult(
                    status="INVALID",
                    errors=[f"Unserializable payload: {exc}"],
                    warnings=[],
                    validation_stage="payload_check"
                )

        # 2. Field-level validation checks
        validation_stage = "field_check"
        
        # Check required event_type (Condition 1)
        event_type = self._pick_str(data, self._EVENT_TYPE_KEYS)
        if not event_type:
            errors.append("Missing required event_type")
            
        # Check invalid timestamp format (Condition 2)
        timestamp_val = self._pick_value(data, self._TIMESTAMP_KEYS)
        if timestamp_val is not None:
            try:
                self._parse_timestamp(timestamp_val)
            except ValueError as exc:
                errors.append(f"Invalid timestamp format: {exc}")
                
        # Check missing critical fields (Condition 6)
        # We explicitly require event_type for SOC processing
        if not event_type:
            errors.append("Missing critical fields required for SOC processing (event_type)")
            
        # Warnings checks
        # Missing source (Warning 1)
        source = self._pick_str(data, self._SOURCE_KEYS)
        if not source:
            warnings.append("Missing source")
            
        # Missing message (Warning 2)
        message = self._pick_str(data, self._MESSAGE_KEYS)
        if not message:
            warnings.append("Missing message")
            
        # Non-standard severity value (Warning 3)
        severity = self._pick_value(data, self._SEVERITY_KEYS)
        if severity is not None:
            severity_str = str(severity).lower().strip()
            if severity_str not in self._ALLOWED_SEVERITIES:
                warnings.append("Non-standard severity value")
                
        # Invalid source_ip format (Warning 4)
        source_ip = self._pick_str(data, self._SOURCE_IP_KEYS)
        if source_ip is not None:
            try:
                ipaddress.ip_address(source_ip)
            except ValueError:
                warnings.append("Invalid source_ip format")
                
        # Determine Status
        if errors:
            status = "INVALID"
        elif warnings:
            status = "WARNING"
        else:
            status = "VALID"
            
        return ValidationResult(
            status=status,
            errors=errors,
            warnings=warnings,
            validation_stage=validation_stage
        )

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

    def _parse_timestamp(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)


validation_service = ValidationService()
