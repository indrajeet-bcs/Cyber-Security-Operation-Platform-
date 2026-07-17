"""
Notification Engine Service — Manages status transitions, routes, quiet hours, and channel dispatches.
"""

from datetime import datetime, timezone, timedelta
import html as _html_mod
import logging
import platform
import smtplib
import socket
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.core.config import settings
from app.database import alert_repository, notification_repository
from app.services.notification_metrics_service import notification_metrics_service
from app.utils.logger import logger

class NotificationEngineService:
    VALID_TRANSITIONS = {
        "pending": ["sent", "delivered", "failed", "suppressed"],
        "sent": ["delivered", "failed"],
        "delivered": ["acknowledged", "escalated", "suppressed"],
        "failed": ["pending", "sent"],
        "suppressed": ["pending", "closed", "escalated", "acknowledged"],
        "acknowledged": ["investigating", "closed"],
        "investigating": ["resolved", "closed"],
        "resolved": ["closed"],
        "escalated": ["acknowledged", "investigating", "closed", "escalated", "delivered"],
        "closed": []
    }

    def __init__(self) -> None:
        # Dictionary to control channel simulation success in tests
        self.simulate_channel_success = {
            "Email": True,
            "Teams": True,
            "Slack": True,
            "Webhook": True,
            "PagerDuty": True
        }

    def validate_transition(self, current_status: str, new_status: str) -> None:
        """
        Validates whether a state transition from current_status to new_status is valid.
        Raises ValueError if not valid.
        """
        if current_status == new_status:
            return
        valid_next = self.VALID_TRANSITIONS.get(current_status, [])
        if new_status not in valid_next:
            raise ValueError(f"Invalid state transition from '{current_status}' to '{new_status}'")

    def update_notification_status(self, notification_id: str, new_status: str, **kwargs) -> None:
        """
        Updates the status of a notification after validating the transition.
        """
        notif = notification_repository.get_notification_by_id(notification_id)
        if not notif:
            raise ValueError(f"Notification {notification_id} not found")
        
        self.validate_transition(notif["status"], new_status)
        notification_repository.update_notification_status(notification_id, new_status, **kwargs)

    def is_in_quiet_hours(self, dt: datetime) -> bool:
        """
        Checks if the given time is within quiet hours (22:00 to 08:00 local/UTC).
        """
        return dt.hour >= 22 or dt.hour < 8

    def is_escalation_stopped(self, notification: dict) -> bool:
        """
        Verifies if escalation is stopped for a notification.
        Checks both the DB field and the linked alert's status.
        """
        if notification.get("escalation_stopped"):
            return True
            
        alert_id = notification.get("alert_id")
        if not alert_id:
            return False
            
        from app.database import alert_repository
        alert = alert_repository.get_alert_by_alert_id(alert_id)
        if alert:
            status = alert.get("status")
            if status in ("acknowledged", "resolved", "closed", "false_positive"):
                notification_repository.stop_escalation(notification["notification_id"])
                return True
                
        return False

    def process_alert(self, alert: dict, now: datetime | None = None) -> dict | None:
        """
        Processes an ingested alert. Performs deduplication, suppression checks,
        quiet hours check, and immediate routing for high/critical severities.
        """
        now = now or datetime.now(timezone.utc)
        
        notification_fingerprint = alert.get("alert_fingerprint") or alert.get("alert_id")
        if not notification_fingerprint:
            logger.error("[NotificationEngine] Alert lacks alert_fingerprint and alert_id.")
            return None

        # 1. Deduplication & Suppression Window Check
        existing = notification_repository.get_notification_by_fingerprint(notification_fingerprint)
        if existing:
            # First check if escalation is stopped for existing notification
            if self.is_escalation_stopped(existing):
                logger.info(f"[NotificationEngine] Escalation stopped for notification_id={existing['notification_id']}. Skipping.")
                return existing

            # Determine if we are within the suppression window
            # Use suppression_until if present, fallback to created_at + 5 minutes
            suppression_until = existing.get("suppression_until")
            if not suppression_until:
                suppression_until = existing["created_at"] + timedelta(minutes=5)
            
            if now < suppression_until:
                new_count = (existing["occurrence_count"] or 1) + 1
                new_suppression_until = existing["created_at"] + timedelta(minutes=5)
                
                # Check transition: current_status -> suppressed
                self.validate_transition(existing["status"], "suppressed")
                
                notification_repository.update_notification_status(
                    notification_id=existing["notification_id"],
                    status="suppressed",
                    occurrence_count=new_count,
                    suppression_until=new_suppression_until,
                    updated_at=now
                )
                
                notification_repository.create_history_entry(
                    notification_id=existing["notification_id"],
                    alert_id=existing["alert_id"],
                    recipient_email=None,
                    recipient_role=None,
                    severity=existing["severity"],
                    delivery_status="suppressed",
                    escalation_level=existing.get("escalation_level", 0)
                )
                notification_metrics_service.increment_suppressed()
                return notification_repository.get_notification_by_id(existing["notification_id"])
            else:
                # Outside suppression window: delete old notification to avoid unique fingerprint constraint
                notification_repository.delete_notification(existing["notification_id"])
 
        # 2. Get active policy for severity
        severity = alert["severity"]
        policy = notification_repository.get_active_policy(severity)
        recipient_group = policy["policy_name"] if policy else f"{severity}_policy"
        initial_role = policy["initial_role"] if policy else "analyst"
 
        # 3. Quiet Hours Check
        if self.is_in_quiet_hours(now) and severity.lower() != "critical":
            notification_id = f"NTF-{uuid.uuid4().hex[:8].upper()}"
            suppression_until_time = now + timedelta(minutes=5)
            
            notification_repository.create_notification(
                notification_id=notification_id,
                alert_id=alert["alert_id"],
                notification_fingerprint=notification_fingerprint,
                severity=severity,
                recipient_group=recipient_group,
                status="suppressed",
                occurrence_count=1,
                suppression_until=suppression_until_time,
                created_at=now,
                updated_at=now
            )
            notification_repository.create_history_entry(
                notification_id=notification_id,
                alert_id=alert["alert_id"],
                recipient_email=None,
                recipient_role=None,
                severity=severity,
                delivery_status="suppressed",
                escalation_level=0
            )
            notification_metrics_service.increment_suppressed()
            return notification_repository.get_notification_by_id(notification_id)
 
        # 4. Normal Notification Creation
        notification_id = f"NTF-{uuid.uuid4().hex[:8].upper()}"
        notification_repository.create_notification(
            notification_id=notification_id,
            alert_id=alert["alert_id"],
            notification_fingerprint=notification_fingerprint,
            severity=severity,
            recipient_group=recipient_group,
            status="pending",
            occurrence_count=1,
            created_at=now,
            updated_at=now
        )
        
        notification = notification_repository.get_notification_by_id(notification_id)
        
        # 5. Immediate routing for high/critical alerts
        if severity.lower() in ("high", "critical"):
            notification = self.dispatch_notification(notification, role=initial_role)
            
        return notification

    def dispatch_notification(self, notification: dict, role: str | None = None) -> dict:
        """
        Dispatches notification by checking stop triggers, querying recipients,
        and failing over between channels (Email -> Teams -> Slack -> Webhook -> PagerDuty).
        """
        if self.is_escalation_stopped(notification):
            logger.info(f"[NotificationEngine] Escalation stopped for notification_id={notification['notification_id']}. Bypassing dispatch.")
            return notification

        if not role:
            policy = notification_repository.get_active_policy(notification["severity"])
            role = policy["initial_role"] if policy else "analyst"

        recipients = notification_repository.get_recipients_by_role(role)
        if not recipients:
            logger.warning(f"No active recipients found for role: {role}")
            # Transition pending/escalated -> failed
            self.update_notification_status(notification["notification_id"], "failed", delivery_status="No active recipients")
            notification_metrics_service.increment_failed()
            return notification_repository.get_notification_by_id(notification["notification_id"])

        channels = ["Email", "Teams", "Slack", "Webhook", "PagerDuty"]
        sent_successfully = False
        successful_channel = None
        
        notification_repository.increment_delivery_attempts(notification["notification_id"], "attempting")

        # ── Fetch alert data for enterprise-grade email content ──
        alert_data = None
        try:
            alert_data = alert_repository.get_alert_by_alert_id(notification.get("alert_id"))
        except Exception as exc:
            logger.warning(f"[NotificationEngine] Could not fetch alert for email enrichment: {exc}")

        # ── Build rich email subject, plain-text body, and HTML body ──
        email_ctx = self._extract_email_context(notification, alert_data, role)
        email_subject = self._build_email_subject(email_ctx)
        email_body = self._build_email_body(email_ctx)
        email_html = self._build_email_body_html(email_ctx)
        logger.info("[INFO] Email Metadata Added")

        for channel in channels:
            delivered = False
            try:
                if channel == "Email":
                    delivered = all(self._dispatch_email(r, email_subject, email_body, email_html) for r in recipients)
                elif channel == "Teams":
                    delivered = all(self._dispatch_teams(r, f"Alert: {notification['alert_id']}") for r in recipients)
                elif channel == "Slack":
                    delivered = all(self._dispatch_slack(r, f"Alert: {notification['alert_id']}") for r in recipients)
                elif channel == "Webhook":
                    delivered = self._dispatch_webhook("https://mock-webhook.local", {"notification": notification})
                elif channel == "PagerDuty":
                    delivered = self._dispatch_pagerduty("mock-pd-key", notification)
            except Exception as exc:
                logger.error(f"Error sending via channel {channel}: {exc}")
                delivered = False

            # Record attempt in history for all recipients
            for r in recipients:
                notification_repository.create_history_entry(
                    notification_id=notification["notification_id"],
                    alert_id=notification["alert_id"],
                    recipient_email=r["email"],
                    recipient_role=r["role"],
                    severity=notification["severity"],
                    delivery_status="delivered" if delivered else "failed",
                    escalation_level=notification.get("escalation_level", 0)
                )

            if delivered:
                sent_successfully = True
                successful_channel = channel
                break

        if sent_successfully:
            # Calculate delivery time
            now_time = datetime.now(timezone.utc)
            created_time = notification.get("created_at") or now_time
            delivery_time = (now_time - created_time).total_seconds()
            notification_metrics_service.update_delivery_time(delivery_time)
            
            # Re-read current status from DB to avoid stale dict issues
            current_notif = notification_repository.get_notification_by_id(notification["notification_id"])
            current_status = current_notif["status"] if current_notif else notification.get("status")
            
            # If already escalated, keep escalated; otherwise transition to delivered
            new_status = "escalated" if current_status == "escalated" else "delivered"
            self.update_notification_status(
                notification_id=notification["notification_id"],
                new_status=new_status,
                delivery_status=f"delivered_via_{successful_channel.lower()}",
                channel_used=successful_channel
            )
            notification_metrics_service.increment_sent()
        else:
            # Transition pending/escalated -> failed
            self.update_notification_status(
                notification_id=notification["notification_id"],
                new_status="failed",
                delivery_status="all_channels_failed"
            )
            notification_metrics_service.increment_failed()

        return notification_repository.get_notification_by_id(notification["notification_id"])

    def process_retries(self, max_attempts: int = 3, retry_cutoff_minutes: int = 5) -> None:
        """
        Finds failed notifications that are ready to be retried, checking stop triggers first.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=retry_cutoff_minutes)
        failed_notifs = notification_repository.get_failed_notifications_for_retry(max_attempts, cutoff)
        
        for notif in failed_notifs:
            if self.is_escalation_stopped(notif):
                continue
            
            notification_metrics_service.increment_retried()
            self.dispatch_notification(notif)

    def process_batch_queue(self, severities: list[str] = None, max_age_minutes: int = 30) -> None:
        """
        Dispatches pending batch notifications (for lower severities P3/P4).
        """
        severities = severities or ["low", "medium"]
        pending_notifs = notification_repository.get_pending_batch_notifications(severities, max_age_minutes)
        
        for notif in pending_notifs:
            if self.is_escalation_stopped(notif):
                continue
            
            self.dispatch_notification(notif)

    def check_and_trigger_escalations(self, now: datetime | None = None) -> None:
        """
        Checks unacknowledged notifications and triggers escalation (Level 1 / Level 2) based on policy configuration.
        """
        def to_utc(dt: datetime) -> datetime:
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)

        now = to_utc(now or datetime.now(timezone.utc))
        active_notifications = notification_repository.get_active_notifications_for_escalation()
        
        for notification in active_notifications:
            if self.is_escalation_stopped(notification):
                continue
                
            policy = notification_repository.get_active_policy(notification["severity"])
            if not policy:
                continue
                
            escalation_level = notification.get("escalation_level", 0)
            created_at_utc = to_utc(notification["created_at"])
            
            # Level 1 escalation check
            if escalation_level == 0:
                if policy.get("escalation_role") is None or policy.get("escalation_minutes") is None:
                    continue
                esc_time = created_at_utc + timedelta(minutes=policy["escalation_minutes"])
                if now >= esc_time:
                    if not notification_repository.has_escalation_event(notification["notification_id"], 1):
                        escalation_id = f"ESC-{uuid.uuid4().hex[:8].upper()}"
                        role = policy["escalation_role"]
                        notification_repository.create_escalation_event(
                            escalation_id=escalation_id,
                            notification_id=notification["notification_id"],
                            alert_id=notification["alert_id"],
                            escalation_level=1,
                            escalation_target=role,
                            escalation_reason=f"Level-1 escalation: unacknowledged for {policy['escalation_minutes']} minutes"
                        )
                        
                        # Transition delivered/suppressed -> escalated
                        self.update_notification_status(
                            notification_id=notification["notification_id"],
                            new_status="escalated",
                            escalation_level=1
                        )
                        notification_metrics_service.increment_escalated()
                        # Re-fetch notification so dispatch sees updated status
                        refreshed = notification_repository.get_notification_by_id(notification["notification_id"])
                        self.dispatch_notification(refreshed or notification, role=role)
                        
            # Level 2 escalation check
            elif escalation_level == 1:
                if policy.get("second_escalation_role") is None or policy.get("second_escalation_minutes") is None:
                    continue
                esc_time = created_at_utc + timedelta(minutes=policy["second_escalation_minutes"])
                if now >= esc_time:
                    if not notification_repository.has_escalation_event(notification["notification_id"], 2):
                        escalation_id = f"ESC-{uuid.uuid4().hex[:8].upper()}"
                        role = policy["second_escalation_role"]
                        notification_repository.create_escalation_event(
                            escalation_id=escalation_id,
                            notification_id=notification["notification_id"],
                            alert_id=notification["alert_id"],
                            escalation_level=2,
                            escalation_target=role,
                            escalation_reason=f"Level-2 escalation: unacknowledged for {policy['second_escalation_minutes']} minutes"
                        )
                        
                        # Transition escalated -> escalated
                        self.update_notification_status(
                            notification_id=notification["notification_id"],
                            new_status="escalated",
                            escalation_level=2
                        )
                        notification_metrics_service.increment_escalated()
                        # Re-fetch notification so dispatch sees updated status
                        refreshed = notification_repository.get_notification_by_id(notification["notification_id"])
                        self.dispatch_notification(refreshed or notification, role=role)

    # ── Email Content Builders (Enterprise SOC Grade) ─────────────────

    _SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#16a34a",
        "informational": "#2563eb",
    }

    @staticmethod
    def _format_timedelta(td: timedelta) -> str:
        """Formats a timedelta into a human-readable string like '5m 30s'."""
        total_seconds = int(td.total_seconds())
        if total_seconds < 0:
            return "0s"
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
        return " ".join(parts)

    def _extract_email_context(self, notification: dict, alert: dict | None, role: str | None) -> dict:
        """Extracts all context data needed for email subject, body, and HTML rendering."""
        now = datetime.now(timezone.utc)
        escalation_level = notification.get("escalation_level", 0)
        severity_lower = (notification.get("severity") or "medium").lower()
        severity = severity_lower.upper()

        # Notification type and tag
        if escalation_level == 0:
            notif_type = "Initial Notification"
            tag = "NEW"
        elif escalation_level >= 3:
            notif_type = f"Escalation (Level {escalation_level})"
            tag = "SOC MANAGER"
        else:
            notif_type = f"Escalation (Level {escalation_level})"
            tag = "ESCALATED"

        # Time calculations
        created_at = notification.get("created_at") or now
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at)
            except (ValueError, TypeError):
                created_at = now
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        time_since = self._format_timedelta(now - created_at)
        created_at_str = created_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Alert data extraction (safe defaults)
        alert_id = notification.get("alert_id", "N/A")
        notification_id = notification.get("notification_id", "N/A")
        alert_title = "N/A"
        alert_status = "OPEN"
        risk_score = "N/A"
        priority_val = "N/A"
        confidence_val = "N/A"
        source = "N/A"
        host_val = "N/A"
        source_ip = "N/A"
        user = "N/A"
        alert_created_str = created_at_str
        rule_name = "N/A"
        detection_reason = "N/A"
        correlation_id = "N/A"
        correlation_rule = "N/A"
        related_events = "N/A"
        event_type = "N/A"
        message = "N/A"

        if alert:
            alert_title = alert.get("alert_title") or "N/A"
            alert_status = (alert.get("status") or "open").upper()
            risk_score = alert.get("risk_score", "N/A")
            priority_val = alert.get("priority", "N/A")
            confidence_val = alert.get("confidence", "N/A")
            source = alert.get("source") or "N/A"
            host_val = alert.get("host") or "N/A"
            source_ip = alert.get("source_ip") or "N/A"
            user = alert.get("username") or "N/A"
            event_type = alert.get("alert_type") or "N/A"
            message = alert.get("alert_title") or "N/A"

            alert_ct = alert.get("created_at")
            if alert_ct:
                if isinstance(alert_ct, str):
                    alert_created_str = alert_ct
                else:
                    if alert_ct.tzinfo is None:
                        alert_ct = alert_ct.replace(tzinfo=timezone.utc)
                    alert_created_str = alert_ct.strftime("%Y-%m-%d %H:%M:%S UTC")

            # Rule match extraction
            rule_matches = alert.get("rule_matches") or []
            if rule_matches:
                names = [rm.get("rule_name") or rm.get("rule_code", "Unknown") for rm in rule_matches]
                rule_name = ", ".join(names)
                reasons = [rm.get("reason", "") for rm in rule_matches if rm.get("reason")]
                if reasons:
                    detection_reason = "; ".join(reasons)
                    message = reasons[0]

            # Correlation match extraction
            corr_matches = alert.get("correlation_matches") or []
            if corr_matches:
                c_ids = [cm.get("correlation_id", "") for cm in corr_matches if cm.get("correlation_id")]
                correlation_id = ", ".join(c_ids) if c_ids else "N/A"
                c_types = [cm.get("correlation_type", "") for cm in corr_matches if cm.get("correlation_type")]
                correlation_rule = ", ".join(c_types) if c_types else "N/A"
                e_counts = [cm.get("event_count", 0) for cm in corr_matches]
                related_events = str(sum(e_counts)) if e_counts else "N/A"

        # Notification metadata
        occurrence_count = notification.get("occurrence_count", 1)
        is_suppressed = "Yes" if notification.get("status") == "suppressed" else "No"
        is_duplicate = "Yes" if occurrence_count > 1 else "No"
        recipient_group = notification.get("recipient_group") or role or "N/A"
        delivery_attempts = notification.get("delivery_attempts", 0)
        acknowledged = "Yes" if notification.get("acknowledged_by") else "No"
        assigned_to = notification.get("acknowledged_by") or "Unassigned"

        # Escalation policy info
        esc_policy = recipient_group
        esc_interval = "N/A"
        try:
            policy = notification_repository.get_active_policy(notification.get("severity", "high"))
            if policy:
                esc_policy = policy.get("policy_name", recipient_group)
                if escalation_level <= 0:
                    esc_interval = f"{policy.get('escalation_minutes', 'N/A')} minutes"
                elif escalation_level == 1:
                    esc_interval = f"{policy.get('second_escalation_minutes', 'N/A')} minutes"
                else:
                    esc_interval = "Final escalation"
        except Exception:
            pass

        # Severity color for HTML rendering
        severity_color = self._SEVERITY_COLORS.get(severity_lower, "#64748b")

        # System metadata
        env = "Development"
        try:
            if hasattr(settings, "environment"):
                env = settings.environment
        except Exception:
            pass

        return {
            "now": now,
            "now_str": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "escalation_level": escalation_level,
            "severity": severity,
            "severity_lower": severity_lower,
            "severity_color": severity_color,
            "notif_type": notif_type,
            "tag": tag,
            "created_at_str": created_at_str,
            "time_since": time_since,
            "alert_id": alert_id,
            "notification_id": notification_id,
            "alert_title": alert_title,
            "alert_status": alert_status,
            "risk_score": risk_score,
            "priority": priority_val,
            "confidence": confidence_val,
            "source": source,
            "host": host_val,
            "source_ip": source_ip,
            "user": user,
            "event_type": event_type,
            "message": message,
            "alert_created_str": alert_created_str,
            "rule_name": rule_name,
            "detection_reason": detection_reason,
            "correlation_id": correlation_id,
            "correlation_rule": correlation_rule,
            "related_events": related_events,
            "occurrence_count": occurrence_count,
            "is_suppressed": is_suppressed,
            "is_duplicate": is_duplicate,
            "recipient_group": recipient_group,
            "delivery_attempts": delivery_attempts,
            "acknowledged": acknowledged,
            "assigned_to": assigned_to,
            "esc_policy": esc_policy,
            "esc_interval": esc_interval,
            "environment": env,
            "hostname": socket.gethostname(),
            "platform_version": "1.0.0",
        }

    def _build_email_subject(self, ctx: dict) -> str:
        """Builds enterprise-grade email subject: [SEVERITY][L#][STATUS] Title on Host."""
        host_suffix = ""
        if ctx["host"] not in ("N/A", None, ""):
            host_suffix = f" on {ctx['host']}"

        title = ctx["alert_title"]
        if title == "N/A":
            title = f"Alert {ctx['alert_id']}"

        subject = f"[{ctx['severity']}][L{ctx['escalation_level']}][{ctx['tag']}] {title}{host_suffix}"
        logger.info(f"[INFO] Email Subject Generated: {subject}")
        logger.info(f"[INFO] Escalation Level Included: L{ctx['escalation_level']}")
        return subject

    def _build_email_body(self, ctx: dict) -> str:
        """Builds comprehensive plain-text email body matching enterprise SIEM standards."""
        logger.info(f"[INFO] Notification Type Included: {ctx['notif_type']}")

        body = (
            "================================================\n"
            "   AI-Powered SOC Platform Alert Notification\n"
            "================================================\n"
            "\n"
            f"  Notification Type:          {ctx['notif_type']}\n"
            f"  Escalation Level:           L{ctx['escalation_level']}\n"
            f"  Current Alert Status:       {ctx['alert_status']}\n"
            f"  Notification Timestamp:     {ctx['now_str']}\n"
            f"  Original Alert Timestamp:   {ctx['alert_created_str']}\n"
            f"  Escalation Trigger Time:    {ctx['now_str']}\n"
            f"  Time Since First Alert:     {ctx['time_since']}\n"
            "\n"
            "------------------------------------------------\n"
            "                  Alert Details\n"
            "------------------------------------------------\n"
            "\n"
            f"  Alert ID:                   {ctx['alert_id']}\n"
            f"  Alert Title:                {ctx['alert_title']}\n"
            f"  Notification UUID:          {ctx['notification_id']}\n"
            f"  Correlation ID:             {ctx['correlation_id']}\n"
            f"  Severity:                   {ctx['severity']}\n"
            f"  Priority:                   {ctx['priority']}\n"
            f"  Risk Score:                 {ctx['risk_score']}\n"
            f"  Confidence:                 {ctx['confidence']}\n"
            f"  Rule Name:                  {ctx['rule_name']}\n"
            f"  Detection Reason:           {ctx['detection_reason']}\n"
            f"  Source:                     {ctx['source']}\n"
            f"  Host:                       {ctx['host']}\n"
            f"  Source IP:                  {ctx['source_ip']}\n"
            f"  User:                       {ctx['user']}\n"
            f"  Event Type:                 {ctx['event_type']}\n"
            f"  Message:                    {ctx['message']}\n"
            f"  Occurrences:                {ctx['occurrence_count']}\n"
            "\n"
            "------------------------------------------------\n"
            "             Escalation Information\n"
            "------------------------------------------------\n"
            "\n"
            f"  Escalation Level:           L{ctx['escalation_level']}\n"
            f"  Escalation Policy:          {ctx['esc_policy']}\n"
            f"  Escalation Interval:        {ctx['esc_interval']}\n"
            f"  Current Recipient Group:    {ctx['recipient_group']}\n"
            f"  Notification Channel:       EMAIL\n"
            f"  Previous Delivery Attempts: {ctx['delivery_attempts']}\n"
            f"  Suppressed:                 {ctx['is_suppressed']}\n"
            f"  Duplicate Alert:            {ctx['is_duplicate']}\n"
            "\n"
            "------------------------------------------------\n"
            "            Correlation Information\n"
            "------------------------------------------------\n"
            "\n"
            f"  Correlation Rule:           {ctx['correlation_rule']}\n"
            f"  Correlation ID:             {ctx['correlation_id']}\n"
            f"  Related Events:             {ctx['related_events']}\n"
            "\n"
            "------------------------------------------------\n"
            "           Investigation Information\n"
            "------------------------------------------------\n"
            "\n"
            f"  Alert Status:               {ctx['alert_status']}\n"
            f"  Assigned To:                {ctx['assigned_to']}\n"
            f"  Acknowledged:               {ctx['acknowledged']}\n"
            "\n"
            "------------------------------------------------\n"
            "              System Metadata\n"
            "------------------------------------------------\n"
            "\n"
            f"  Environment:                {ctx['environment']}\n"
            f"  SOC Platform Version:       {ctx['platform_version']}\n"
            f"  Hostname:                   {ctx['hostname']}\n"
            f"  Generated By:               Notification Engine\n"
            "\n"
            "================================================\n"
            "\n"
            "This email was generated automatically by the\n"
            "AI-Powered SOC Platform Notification &\n"
            "Escalation Engine.\n"
            "\n"
            "================================================\n"
        )
        return body

    def _build_email_body_html(self, ctx: dict) -> str:
        """Builds professional HTML email body for enterprise SIEM-grade notifications."""
        c = ctx
        sev_color = c["severity_color"]
        esc = _html_mod.escape

        def _row(label, value, bold=False, raw_html=False):
            val_str = str(value) if raw_html else esc(str(value))
            weight = "font-weight:600;" if bold else ""
            return (
                '<tr>'
                f'<td style="padding:5px 12px;color:#64748b;font-size:13px;white-space:nowrap;vertical-align:top;">{esc(label)}</td>'
                f'<td style="padding:5px 12px;color:#1e293b;font-size:13px;{weight}word-break:break-word;">{val_str}</td>'
                '</tr>'
            )

        def _section(title):
            return (
                '<tr><td colspan="2" style="padding:16px 12px 8px;font-size:14px;font-weight:700;'
                f'color:#0f172a;border-bottom:2px solid #e2e8f0;letter-spacing:0.3px;">'
                f'&#9654; {esc(title)}</td></tr>'
            )

        rows = []

        # ── Notification Summary ──
        rows.append(_section("Notification Summary"))
        rows.append(_row("Notification Type", c["notif_type"], bold=True))
        rows.append(_row("Escalation Level", f"L{c['escalation_level']}", bold=True))
        rows.append(_row("Current Alert Status", c["alert_status"], bold=True))
        rows.append(_row("Notification Timestamp", c["now_str"]))
        rows.append(_row("Original Alert Timestamp", c["alert_created_str"]))
        rows.append(_row("Escalation Trigger Time", c["now_str"]))
        rows.append(_row("Time Since First Alert", c["time_since"], bold=True))

        # ── Alert Details ──
        rows.append(_section("Alert Details"))
        rows.append(_row("Alert ID", c["alert_id"], bold=True))
        rows.append(_row("Alert Title", c["alert_title"]))
        rows.append(_row("Notification UUID", c["notification_id"]))
        rows.append(_row("Correlation ID", c["correlation_id"]))
        sev_badge = f'<span style="color:{sev_color};font-weight:700;">{esc(c["severity"])}</span>'
        rows.append(_row("Severity", sev_badge, raw_html=True))
        rows.append(_row("Priority", c["priority"]))
        rows.append(_row("Risk Score", c["risk_score"], bold=True))
        rows.append(_row("Confidence", c["confidence"]))
        rows.append(_row("Rule Name", c["rule_name"]))
        rows.append(_row("Detection Reason", c["detection_reason"]))
        rows.append(_row("Source", c["source"]))
        rows.append(_row("Host", c["host"]))
        rows.append(_row("Source IP", c["source_ip"], bold=True))
        rows.append(_row("User", c["user"]))
        rows.append(_row("Event Type", c["event_type"]))
        rows.append(_row("Message", c["message"]))
        rows.append(_row("Occurrences", c["occurrence_count"], bold=True))

        # ── Escalation Information ──
        rows.append(_section("Escalation Information"))
        rows.append(_row("Escalation Level", f"L{c['escalation_level']}"))
        rows.append(_row("Escalation Policy", c["esc_policy"]))
        rows.append(_row("Escalation Interval", c["esc_interval"]))
        rows.append(_row("Current Recipient Group", c["recipient_group"]))
        rows.append(_row("Notification Channel", "EMAIL"))
        rows.append(_row("Previous Delivery Attempts", c["delivery_attempts"]))
        rows.append(_row("Suppressed", c["is_suppressed"]))
        rows.append(_row("Duplicate Alert", c["is_duplicate"]))

        # ── Correlation Information ──
        rows.append(_section("Correlation Information"))
        rows.append(_row("Correlation Rule", c["correlation_rule"]))
        rows.append(_row("Correlation ID", c["correlation_id"]))
        rows.append(_row("Related Events", c["related_events"]))

        # ── Investigation Information ──
        rows.append(_section("Investigation Information"))
        rows.append(_row("Alert Status", c["alert_status"]))
        rows.append(_row("Assigned To", c["assigned_to"]))
        rows.append(_row("Acknowledged", c["acknowledged"]))

        # ── System Metadata ──
        rows.append(_section("System Metadata"))
        rows.append(_row("Environment", c["environment"]))
        rows.append(_row("SOC Platform Version", c["platform_version"]))
        rows.append(_row("Hostname", c["hostname"]))
        rows.append(_row("Generated By", "Notification Engine"))

        rows_html = "\n".join(rows)

        html = (
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>'
            '<body style="margin:0;padding:0;background-color:#f1f5f9;'
            'font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Arial,sans-serif;">'
            '<table width="100%" cellpadding="0" cellspacing="0" border="0" '
            'style="max-width:700px;margin:20px auto;background:#ffffff;'
            'border-radius:8px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.1);">'
            # Header
            '<tr><td style="background-color:#0f172a;padding:24px 28px;text-align:center;">'
            '<div style="font-size:22px;font-weight:700;color:#ffffff;letter-spacing:0.5px;">'
            '&#128737; AI-Powered SOC Platform</div>'
            '<div style="font-size:12px;color:#94a3b8;margin-top:6px;letter-spacing:0.3px;">'
            'Alert Notification &amp; Escalation Engine</div>'
            '</td></tr>'
            # Severity Bar
            f'<tr><td style="background-color:{sev_color};padding:12px 28px;text-align:center;">'
            f'<span style="color:#ffffff;font-weight:700;font-size:16px;letter-spacing:1.5px;">'
            f'[{esc(c["severity"])}] [L{c["escalation_level"]}] [{esc(c["tag"])}]</span>'
            '</td></tr>'
            # Content
            '<tr><td style="padding:8px 20px 20px;">'
            '<table width="100%" cellpadding="0" cellspacing="0" border="0" '
            'style="font-size:13px;line-height:1.7;">'
            f'{rows_html}'
            '</table></td></tr>'
            # Footer
            '<tr><td style="background-color:#0f172a;padding:16px 28px;text-align:center;">'
            '<div style="font-size:11px;color:#64748b;line-height:1.6;">'
            'This email was generated automatically by the AI-Powered SOC Platform<br>'
            'Notification &amp; Escalation Engine</div>'
            '</td></tr>'
            '</table></body></html>'
        )
        return html

    # ── Channel Dispatchers ────────────────────────────────────────────

    @staticmethod
    def _smtp_configured() -> bool:
        """Returns True only when all required SMTP fields are populated with non-placeholder values."""
        return bool(
            settings.smtp_host
            and settings.smtp_port
            and settings.smtp_user
            and settings.smtp_password
            and settings.smtp_from_email
            and "your-email" not in settings.smtp_user
            and "your-gmail" not in settings.smtp_password
        )

    def _dispatch_email(self, recipient: dict, subject: str, body: str, html_body: str | None = None) -> bool:
        """
        Sends email via SMTP when configured.
        Falls back to simulation mode (for tests) when SMTP is not configured.
        Supports optional HTML body for enterprise-grade email rendering.
        """
        to_email = recipient.get("email")
        if not to_email:
            logger.warning("[Email Dispatch] Recipient has no email address — skipping.")
            return False

        # ── Simulation / test mode ──────────────────────────────────
        if not self._smtp_configured():
            logger.warning(
                f"[Email Dispatch] SMTP not configured — running in simulation mode. "
                f"Would send to {to_email} | Subject: {subject}"
            )
            result = self.simulate_channel_success.get("Email", True)
            if result:
                logger.info("[INFO] Email Sent Successfully")
            return result

        # ── Real SMTP delivery ──────────────────────────────────────
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = settings.smtp_from_email
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            if settings.smtp_use_tls:
                server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
                server.ehlo()
                server.starttls()
                server.ehlo()
            else:
                server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port)

            server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.smtp_from_email, to_email, msg.as_string())
            server.quit()

            logger.info(f"[Email Dispatch] Successfully sent to {to_email} | Subject: {subject}")
            logger.info("[INFO] Email Sent Successfully")
            return True

        except smtplib.SMTPAuthenticationError as exc:
            logger.error(f"[Email Dispatch] SMTP authentication failed: {exc}")
            return False
        except smtplib.SMTPRecipientsRefused as exc:
            logger.error(f"[Email Dispatch] Recipient refused ({to_email}): {exc}")
            return False
        except smtplib.SMTPException as exc:
            logger.error(f"[Email Dispatch] SMTP error sending to {to_email}: {exc}")
            return False
        except Exception as exc:
            logger.error(f"[Email Dispatch] Unexpected error sending to {to_email}: {exc}")
            return False

    def _dispatch_teams(self, recipient: dict, body: str) -> bool:
        logger.info(f"[Teams Dispatch] Sending message to team webhook of {recipient['recipient_name']}")
        return self.simulate_channel_success.get("Teams", True)

    def _dispatch_slack(self, recipient: dict, body: str) -> bool:
        logger.info(f"[Slack Dispatch] Sending to channel {recipient.get('slack_channel')} for {recipient['recipient_name']}")
        return self.simulate_channel_success.get("Slack", True)

    def _dispatch_webhook(self, url: str, payload: dict) -> bool:
        logger.info(f"[Webhook Dispatch] POSTing to {url}")
        return self.simulate_channel_success.get("Webhook", True)

    def _dispatch_pagerduty(self, service_key: str, notification: dict) -> bool:
        logger.info(f"[PagerDuty Dispatch] Triggering incident for notification_id={notification['notification_id']}")
        return self.simulate_channel_success.get("PagerDuty", True)

notification_engine_service = NotificationEngineService()
