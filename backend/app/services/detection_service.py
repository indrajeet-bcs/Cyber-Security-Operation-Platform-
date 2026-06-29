from app.schemas.log import NormalizedSOCLog, DetectionResult, Severity


class DetectionService:
    """Analyzes normalized logs to identify suspicious activity based on rules."""

    # Temporary in-code blacklist of suspicious/malicious source IPs
    _BLACKLISTED_IPS = {
        "192.168.1.10",
        "10.0.0.99",
        "203.0.113.50",
    }

    def analyze(self, log: NormalizedSOCLog) -> DetectionResult:
        """Evaluates a normalized log against detection rules.

        Rules:
        - If log severity is critical: suspicious = True, severity = critical.
        - If event_type contains 'malware': suspicious = True, severity = high (or critical if log severity is critical).
        - If event_type contains 'unauthorized': suspicious = True, severity = high.
        - If event_type is 'login_failed' AND source_ip is blacklisted: suspicious = True, severity = high.
        """
        event_type = (log.event_type or "").lower().strip()
        source_ip = log.source_ip
        log_severity = log.severity

        # 1. Critical severity events
        if log_severity == Severity.critical:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.critical,
                reason="Critical severity log event",
            )

        # 2. Malware-related events
        if "malware" in event_type:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.critical if log_severity == Severity.critical else Severity.high,
                reason="Malware activity detected",
            )

        # 3. Unauthorized access events
        if "unauthorized" in event_type:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.high,
                reason="Unauthorized access attempt",
            )

        # 4. Blacklisted IP login failures
        if event_type == "login_failed" and source_ip in self._BLACKLISTED_IPS:
            return DetectionResult(
                is_suspicious=True,
                severity=Severity.high,
                reason="Login failure from blacklisted IP",
            )

        # Default fallback: Event is not suspicious
        return DetectionResult(
            is_suspicious=False,
            severity=Severity.low,
            reason=None,
        )


detection_service = DetectionService()
