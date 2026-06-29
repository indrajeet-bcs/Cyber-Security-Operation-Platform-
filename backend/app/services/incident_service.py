"""
Incident service — handles all incident management business logic and transition constraints.
"""

from datetime import datetime, timezone
from app.database import incident_repository
from app.utils.logger import logger

class IncidentService:
    @staticmethod
    def validate_transition(current_status: str, target_status: str) -> None:
        """
        Validates whether the transition from current_status to target_status is allowed.
        Allowed transitions:
          open -> acknowledged
          acknowledged -> investigating
          investigating -> closed
        """
        valid_transitions = {
            "open": ["acknowledged"],
            "acknowledged": ["investigating"],
            "investigating": ["closed"],
            "closed": []
        }
        
        allowed = valid_transitions.get(current_status, [])
        if target_status not in allowed:
            raise ValueError(f"Invalid state transition from '{current_status}' to '{target_status}'")

    def create_incident(self, alert_id: int | None, title: str, severity: str) -> dict:
        """
        Generates a unique incident ID (INC-YYYYMMDD-XXXX) and saves the incident.
        """
        now = datetime.now(timezone.utc)
        counter = incident_repository.get_next_incident_counter_for_day(now)
        date_str = now.strftime("%Y%m%d")
        incident_id = f"INC-{date_str}-{counter:04d}"
        
        incident_repository.create_incident(
            incident_id=incident_id,
            alert_id=alert_id,
            title=title,
            severity=severity,
            status="open"
        )
        return incident_repository.get_incident(incident_id)

    def acknowledge_incident(self, incident_id: str) -> dict:
        """
        Transitions status from open to acknowledged.
        """
        incident = incident_repository.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
            
        self.validate_transition(incident["status"], "acknowledged")
        incident_repository.update_status(incident_id, "acknowledged")
        return incident_repository.get_incident(incident_id)

    def assign_incident(self, incident_id: str, assigned_to: str, assigned_role: str) -> dict:
        """
        Assigns the incident to an analyst.
        If status is 'open', it automatically transitions: open -> acknowledged -> investigating
        setting acknowledged_at and investigating_at.
        """
        incident = incident_repository.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
            
        current_status = incident["status"]
        if current_status == "open":
            # Multi-step state transition: open -> acknowledged -> investigating
            self.validate_transition("open", "acknowledged")
            self.validate_transition("acknowledged", "investigating")
            
            now = datetime.now(timezone.utc)
            incident_repository.assign_incident(
                incident_id=incident_id,
                assigned_to=assigned_to,
                assigned_role=assigned_role,
                status="investigating",
                acknowledged_at=now,
                investigating_at=now
            )
        elif current_status == "acknowledged":
            # State transition: acknowledged -> investigating
            self.validate_transition("acknowledged", "investigating")
            
            now = datetime.now(timezone.utc)
            incident_repository.assign_incident(
                incident_id=incident_id,
                assigned_to=assigned_to,
                assigned_role=assigned_role,
                status="investigating",
                investigating_at=now
            )
        else:
            # Just update assignment without status transition
            incident_repository.assign_incident(
                incident_id=incident_id,
                assigned_to=assigned_to,
                assigned_role=assigned_role
            )
            
        return incident_repository.get_incident(incident_id)

    def close_incident(self, incident_id: str) -> dict:
        """
        Closes investigation: investigating -> closed.
        Sets closed_at timestamp.
        """
        incident = incident_repository.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
            
        self.validate_transition(incident["status"], "closed")
        incident_repository.update_status(incident_id, "closed")
        return incident_repository.get_incident(incident_id)

    def add_note(self, incident_id: str, note: str) -> dict:
        """
        Appends note to the incidents text notes field.
        """
        incident_repository.append_note(incident_id, note)
        return incident_repository.get_incident(incident_id)

    def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        skip: int = 0,
        limit: int = 100
    ) -> list[dict]:
        """
        Service layer access to list incidents.
        """
        return incident_repository.list_incidents(status=status, severity=severity, limit=limit, offset=skip)

    def get_incident(self, incident_id: str) -> dict | None:
        """
        Service layer access to get incident details.
        """
        return incident_repository.get_incident(incident_id)

    def dashboard_summary(self) -> dict:
        """
        Service layer access to get dashboard summary.
        """
        return incident_repository.dashboard_summary()

incident_service = IncidentService()
