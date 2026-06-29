from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RawLogIngest(BaseModel):
    """Flexible raw ingest — agents may send different field names."""

    model_config = ConfigDict(extra="allow")

    source: str | None = None
    host: str | None = None
    event_type: str | None = None
    message: str | None = None
    severity: Severity | str | None = None
    timestamp: datetime | str | None = None
    source_ip: str | None = None
    user: str | None = None
    metadata: dict[str, Any] | None = None
    record_number: int | None = None


class NormalizedSOCLog(BaseModel):
    """Standard SOC event shape used for storage, detection, and UI."""

    source: str
    host: str | None = None
    event_type: str
    message: str
    severity: Severity
    timestamp: datetime
    source_ip: str | None = None
    user: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    record_number: int | None = None


class DetectionResult(BaseModel):
    """Result of threat detection checks."""

    is_suspicious: bool
    severity: Severity
    reason: str | None = None


class LogResponse(NormalizedSOCLog):
    """Normalized log returned by the API."""

    id: int
    ingested_at: datetime
    detection: DetectionResult | None = None
    record_number: int | None = None
