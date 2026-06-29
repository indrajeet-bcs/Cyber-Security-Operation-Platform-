"""
Notification metrics service.
Manages daily counts and average delivery times.
"""

from app.database import notification_repository

class NotificationMetricsService:
    def increment_sent(self) -> None:
        notification_repository.update_daily_metric("total_sent")

    def increment_failed(self) -> None:
        notification_repository.update_daily_metric("total_failed")

    def increment_suppressed(self) -> None:
        notification_repository.update_daily_metric("total_suppressed")

    def increment_escalated(self) -> None:
        notification_repository.update_daily_metric("total_escalated")

    def increment_retried(self) -> None:
        notification_repository.update_daily_metric("total_retried")

    def update_delivery_time(self, seconds: float) -> None:
        notification_repository.update_daily_avg_delivery_time(seconds)

    def get_notification_metrics(self) -> dict:
        return notification_repository.get_daily_metrics()

notification_metrics_service = NotificationMetricsService()
