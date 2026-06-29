"""
Alert Engine Service — Advanced Real-Time SOC Alert Engine.
"""

import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Any

from app.schemas.log import NormalizedSOCLog, Severity, DetectionResult
from app.database import alert_repository
from app.utils.logger import logger

PRIORITY_MAP = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "informational": "P5",
}

SEVERITIES = ["informational", "low", "medium", "high", "critical"]

class AlertEngineService:
    """
    Production-style Alert Engine for real-time alert generation, deduplication,
    severity escalation, and analyst workflow state tracking.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def generate_alert(self, normalized_log: NormalizedSOCLog, detection_result: DetectionResult | None = None) -> dict | None:
        """
        Main entry point for evaluating a normalized log for alert generation.
        Catches all errors to isolate the ingestion pipeline from database issues.
        """
        try:
            return self._generate_alert_internal(normalized_log, detection_result)
        except Exception as exc:
            logger.error(f"[ERROR] Alert Persistence Failure: {exc}", exc_info=True)
            return None

    def _generate_alert_internal(self, normalized_log: NormalizedSOCLog, detection_result: DetectionResult | None = None) -> dict | None:
        metadata = normalized_log.metadata or {}
        rule_matches = metadata.get("rule_matches", [])
        correlation_matches = metadata.get("correlation_matches", [])

        # 1. Evaluate alert generation conditions
        has_high_rule = any(rm.get("severity") in ("high", "critical") for rm in rule_matches)
        has_correlation = len(correlation_matches) > 0
        has_suspicious_detection = detection_result is not None and detection_result.is_suspicious

        if not (has_high_rule or has_correlation or has_suspicious_detection):
            return None

        logger.info("[INFO] Alert Engine Started")

        # 2. Determine Alert details
        alert_title = self._determine_title(normalized_log, rule_matches, correlation_matches, detection_result)
        alert_type = self._determine_type(has_correlation, has_high_rule, has_suspicious_detection)
        max_severity = self._determine_severity(normalized_log, rule_matches, correlation_matches, detection_result)
        base_risk_score = self._calculate_base_risk(rule_matches, correlation_matches, detection_result)
        confidence = self._calculate_confidence(has_correlation, has_high_rule, has_suspicious_detection)
        
        # 3. Generate Fingerprint
        fingerprint_components = [
            normalized_log.source,
            normalized_log.event_type,
            normalized_log.host or "unknown_host",
        ]
        if rule_matches:
            fingerprint_components.append(",".join(sorted([rm.get("rule_code", "") for rm in rule_matches])))
        if correlation_matches:
            fingerprint_components.append(",".join(sorted([cm.get("correlation_name", "") for cm in correlation_matches])))
            
        fingerprint_str = "|".join(fingerprint_components)
        alert_fingerprint = hashlib.sha256(fingerprint_str.encode("utf-8")).hexdigest()

        with self._lock:
            existing_alert = alert_repository.get_alert_by_fingerprint(alert_fingerprint)
            
            # If the existing alert is closed or resolved, we should generate a NEW fingerprint
            # to start a fresh alert. Enterprise SIEMs typically track them separately once closed.
            if existing_alert and existing_alert.get("status") in ("closed", "resolved"):
                # Append current time to force a new fingerprint
                fingerprint_str += f"|{datetime.now(timezone.utc).timestamp()}"
                alert_fingerprint = hashlib.sha256(fingerprint_str.encode("utf-8")).hexdigest()
                existing_alert = None

            if existing_alert:
                # Deduplication & Escalation
                record_id = existing_alert["id"]
                current_count = existing_alert["occurrence_count"] + 1
                
                # Combine matches
                existing_rules = existing_alert.get("rule_matches") or []
                existing_correlations = existing_alert.get("correlation_matches") or []
                
                # Simple merge to avoid massive json objects over time, or just replace with latest
                # For this implementation we will append unique
                new_rule_codes = {rm.get("rule_code") for rm in existing_rules}
                for rm in rule_matches:
                    if rm.get("rule_code") not in new_rule_codes:
                        existing_rules.append(rm)
                        new_rule_codes.add(rm.get("rule_code"))
                        
                # Escalation logic (+5 / +10 as per plan)
                new_severity = existing_alert["severity"]
                new_risk_score = existing_alert["risk_score"] or base_risk_score
                
                if current_count > 20:
                    new_severity = self._escalate_severity(new_severity, 2)
                    new_risk_score = min(100, new_risk_score + 10)
                    logger.info("[INFO] Alert Escalated")
                elif current_count > 5:
                    new_severity = self._escalate_severity(new_severity, 1)
                    new_risk_score = min(100, new_risk_score + 5)
                    logger.info("[INFO] Alert Escalated")

                new_priority = PRIORITY_MAP.get(new_severity, "P4")

                alert_repository.update_alert(
                    record_id=record_id,
                    severity=new_severity,
                    priority=new_priority,
                    confidence=confidence,
                    risk_score=new_risk_score,
                    occurrence_count=current_count,
                    rule_matches=existing_rules,
                    correlation_matches=existing_correlations
                )
                logger.info("[INFO] Alert Updated")
                
                # Return updated
                return alert_repository.get_alert_by_fingerprint(alert_fingerprint)
                
            else:
                # Generate new Alert ID
                today = datetime.now(timezone.utc)
                counter = alert_repository.get_next_alert_counter_for_day(today)
                date_str = today.strftime("%Y%m%d")
                alert_id = f"ALT-{date_str}-{counter:04d}"

                priority = PRIORITY_MAP.get(max_severity, "P4")
                
                if has_correlation and max_severity in ("critical", "high"):
                    logger.warning("[WARNING] Critical Alert Generated")

                record_id = alert_repository.create_alert(
                    alert_id=alert_id,
                    alert_title=alert_title,
                    alert_type=alert_type,
                    severity=max_severity,
                    priority=priority,
                    confidence=confidence,
                    risk_score=base_risk_score,
                    status="open",
                    occurrence_count=1,
                    source=normalized_log.source,
                    source_ip=normalized_log.source_ip,
                    host=normalized_log.host,
                    username=normalized_log.user,
                    event_fingerprint=None,
                    alert_fingerprint=alert_fingerprint,
                    rule_matches=rule_matches,
                    correlation_matches=correlation_matches
                )
                logger.info("[INFO] Alert Created")
                
                return alert_repository.get_alert_by_fingerprint(alert_fingerprint)

    def _determine_title(self, log: NormalizedSOCLog, rules: list, correlations: list, detection: DetectionResult | None) -> str:
        if correlations:
            return f"Correlation Match: {correlations[0].get('correlation_name', 'Unknown')}"
        if rules:
            return f"Rule Match: {rules[0].get('rule_code', 'Unknown')}"
        if detection and detection.is_suspicious:
            return f"Suspicious Activity Detected: {detection.reason or 'Unknown'}"
        return f"Suspicious Log: {log.event_type}"

    def _determine_type(self, has_correlation: bool, has_high_rule: bool, has_suspicious: bool) -> str:
        if has_correlation:
            return "correlation"
        if has_high_rule:
            return "rule_match"
        if has_suspicious:
            return "detection"
        return "other"

    def _determine_severity(self, log: NormalizedSOCLog, rules: list, correlations: list, detection: DetectionResult | None) -> str:
        severities = []
        if log.severity:
            severities.append(log.severity.value if hasattr(log.severity, 'value') else log.severity)
        for r in rules:
            severities.append(r.get("severity", "low"))
        for c in correlations:
            severities.append(c.get("severity", "low"))
        if detection and detection.severity:
            severities.append(detection.severity.value if hasattr(detection.severity, 'value') else detection.severity)

        # Find max severity
        max_idx = -1
        max_sev = "low"
        for s in severities:
            s_lower = s.lower()
            if s_lower in SEVERITIES:
                idx = SEVERITIES.index(s_lower)
                if idx > max_idx:
                    max_idx = idx
                    max_sev = s_lower
        return max_sev

    def _calculate_base_risk(self, rules: list, correlations: list, detection: DetectionResult | None) -> int:
        risks = [0]
        for r in rules:
            if "risk_score" in r: risks.append(r["risk_score"])
        for c in correlations:
            if "risk_score" in c: risks.append(c["risk_score"])
        if detection and detection.severity:
            sev_val = detection.severity.value if hasattr(detection.severity, 'value') else detection.severity
            sev_idx = SEVERITIES.index(sev_val.lower()) if sev_val.lower() in SEVERITIES else 0
            risks.append(sev_idx * 20)
        return max(risks)

    def _calculate_confidence(self, has_correlation: bool, has_high_rule: bool, has_suspicious: bool) -> int:
        score = 0
        if has_correlation: score += 50
        if has_high_rule: score += 40
        if has_suspicious: score += 30
        return min(100, max(50, score))

    def _escalate_severity(self, current_sev: str, levels: int) -> str:
        if current_sev not in SEVERITIES:
            return "high"
        idx = SEVERITIES.index(current_sev)
        new_idx = min(len(SEVERITIES) - 1, idx + levels)
        return SEVERITIES[new_idx]

alert_engine_service = AlertEngineService()
