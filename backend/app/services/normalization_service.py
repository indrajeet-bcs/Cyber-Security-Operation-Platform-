from datetime import datetime, timezone
from typing import Any

from app.schemas.log import NormalizedSOCLog, RawLogIngest, Severity


class NormalizationService:
    """Maps raw / heterogeneous log payloads into a normalized SOC event."""

    _SOURCE_KEYS = ("source", "log_source", "origin", "facility")
    _HOST_KEYS = ("host", "hostname", "host_name", "computer_name")
    _EVENT_TYPE_KEYS = ("event_type", "type", "event", "action", "category")
    _MESSAGE_KEYS = ("message", "msg", "log", "text", "description")
    _SEVERITY_KEYS = ("severity", "level", "priority")
    _TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "event_time", "datetime")
    _SOURCE_IP_KEYS = ("source_ip", "ip", "src_ip", "client_ip", "remote_addr")
    _USER_KEYS = ("user", "username", "account", "user_name")

    _HIGH_SEVERITY_EVENTS = frozenset(
        {
            "auth.failure",
            "privilege.escalation",
            "malware.detected",
            "intrusion.detected",
        }
    )
    _MEDIUM_SEVERITY_EVENTS = frozenset(
        {
            "port.scan",
            "http.suspicious",
            "api.abuse",
            "container.anomaly",
        }
    )

    def normalize(self, raw: RawLogIngest | dict[str, Any]) -> NormalizedSOCLog:
        data = raw.model_dump() if isinstance(raw, RawLogIngest) else dict(raw)

        event_type = self._pick_str(data, self._EVENT_TYPE_KEYS)
        if not event_type:
            raise ValueError(
                "Cannot normalize log: missing event_type (or alias: type, event, action, category)"
            )

        message = self._pick_str(data, self._MESSAGE_KEYS)
        if not message:
            message = self._fallback_message(data)

        source = self._pick_str(data, self._SOURCE_KEYS) or "unknown"
        host = self._pick_str(data, self._HOST_KEYS)
        source_ip = self._pick_str(data, self._SOURCE_IP_KEYS)
        user = self._pick_str(data, self._USER_KEYS)

        # Map Windows Event specific fields and enrich event_type
        metadata_dict = data.get("metadata") or {}
        event_data = None
        if isinstance(metadata_dict, dict):
            event_data = metadata_dict.get("event_data")
        if not isinstance(event_data, dict):
            event_data = data.get("event_data")

        # IpAddress -> source_ip
        if not source_ip and isinstance(event_data, dict):
            ip_val = event_data.get("IpAddress") or event_data.get("Ipaddress") or event_data.get("ipAddress")
            if ip_val:
                source_ip = str(ip_val).strip()
        if not source_ip and "IpAddress" in data:
            source_ip = str(data["IpAddress"]).strip()

        # SubjectUserName -> user
        if not user and isinstance(event_data, dict):
            user_val = event_data.get("SubjectUserName") or event_data.get("Subjectusername") or event_data.get("subjectUserName")
            if user_val:
                user = str(user_val).strip()
        if not user and "SubjectUserName" in data:
            user = str(data["SubjectUserName"]).strip()

        # EventID -> event_type enrichment
        event_id = None
        if isinstance(metadata_dict, dict):
            event_id = metadata_dict.get("event_id")
        if not event_id and isinstance(event_data, dict):
            event_id = event_data.get("EventID") or event_data.get("Eventid")
        if not event_id:
            event_id = data.get("EventID") or data.get("event_id")

        if event_id:
            event_id_str = str(event_id).strip()
            if event_type.lower().strip() in ("windows_event", "windows_raw", "windows"):
                event_type = f"windows_event_{event_id_str}"

        timestamp = self._parse_timestamp(self._pick_value(data, self._TIMESTAMP_KEYS))
        severity = self._resolve_severity(data, event_type)
        metadata = self._build_metadata(data)

        return NormalizedSOCLog(
            source=source,
            host=host,
            event_type=event_type.lower().strip(),
            message=message.strip(),
            severity=severity,
            timestamp=timestamp,
            source_ip=source_ip,
            user=user,
            metadata=metadata,
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
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp format: {value}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _resolve_severity(self, data: dict[str, Any], event_type: str) -> Severity:
        raw_severity = self._pick_value(data, self._SEVERITY_KEYS)
        if raw_severity is not None:
            try:
                return Severity(str(raw_severity).lower().strip())
            except ValueError:
                pass

        normalized_type = event_type.lower().strip()
        if normalized_type in self._HIGH_SEVERITY_EVENTS:
            return Severity.high
        if normalized_type in self._MEDIUM_SEVERITY_EVENTS:
            return Severity.medium
        return Severity.low

    def _fallback_message(self, data: dict[str, Any]) -> str:
        reserved = set(
            self._SOURCE_KEYS
            + self._HOST_KEYS
            + self._EVENT_TYPE_KEYS
            + self._MESSAGE_KEYS
            + self._SEVERITY_KEYS
            + self._TIMESTAMP_KEYS
            + self._SOURCE_IP_KEYS
            + self._USER_KEYS
            + ("metadata", "id", "ingested_at")
        )
        extras = {k: v for k, v in data.items() if k not in reserved and v is not None}
        if extras:
            return f"Unparsed log event: {extras}"
        return "Unparsed log event"

    def _build_metadata(self, data: dict[str, Any]) -> dict[str, Any]:
        reserved = set(
            self._SOURCE_KEYS
            + self._HOST_KEYS
            + self._EVENT_TYPE_KEYS
            + self._MESSAGE_KEYS
            + self._SEVERITY_KEYS
            + self._TIMESTAMP_KEYS
            + self._SOURCE_IP_KEYS
            + self._USER_KEYS
            + ("metadata",)
        )

        metadata: dict[str, Any] = {}
        explicit = data.get("metadata")
        if isinstance(explicit, dict):
            metadata.update(explicit)

        for key, value in data.items():
            if key not in reserved and value is not None:
                metadata[key] = value

        return metadata


normalization_service = NormalizationService()
