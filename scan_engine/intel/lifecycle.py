from datetime import datetime
from scan_engine.intel.db import get_session
from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityStatus, VulnerabilityHistory
from scan_engine.audit import AuditService

class LifecycleManager:
    def __init__(self):
        self.session = get_session()
        self.audit_service = AuditService()

    def transition_state(self, vuln_id: str, new_status: VulnerabilityStatus, action_description: str):
        vuln = self.session.get(VulnerabilityRecord, vuln_id)
        if not vuln:
            raise ValueError(f"Vulnerability {vuln_id} not found.")

        old_status = vuln.status
        
        # TRANSITION ENGINE: Strict compliance rules
        valid_transitions = {
            VulnerabilityStatus.DETECTED: [VulnerabilityStatus.AI_FIX_GENERATED, VulnerabilityStatus.REJECTED],
            VulnerabilityStatus.AI_FIX_GENERATED: [VulnerabilityStatus.VALIDATED, VulnerabilityStatus.REJECTED],
            VulnerabilityStatus.VALIDATED: [VulnerabilityStatus.FIXED, VulnerabilityStatus.REJECTED],
            VulnerabilityStatus.FIXED: [VulnerabilityStatus.DETECTED], # Allow re-opening if fix fails later
            VulnerabilityStatus.REJECTED: [VulnerabilityStatus.DETECTED] # Allow re-opening for re-evaluation
        }

        if new_status not in valid_transitions.get(old_status, []):
            # If the current state is the same as new state, skip (idempotent)
            if old_status == new_status:
                return vuln
            raise ValueError(f"ILLEGAL_TRANSITION: Cannot move from {old_status} to {new_status}")

        vuln.status = new_status
        vuln.updated_at = datetime.utcnow()
        self.session.add(vuln)
        
        # Log History for end-to-end traceability
        history = VulnerabilityHistory(
            vulnerability_id=vuln_id,
            old_state=old_status.value if hasattr(old_status, 'value') else str(old_status),
            new_state=new_status.value,
            action=action_description,
            timestamp=datetime.utcnow()
        )
        self.session.add(history)
        
        # Compliance Logging (Immutable audit trail)
        action_type = "RESOLUTION" if new_status == VulnerabilityStatus.FIXED else (
            "DETECTION" if new_status == VulnerabilityStatus.DETECTED else (
            "VALIDATION" if new_status == VulnerabilityStatus.VALIDATED else (
            "AI_FIX" if new_status == VulnerabilityStatus.AI_FIX_GENERATED else "REVIEW"
        )))
        self.audit_service.log_event(action_type, f"Automated Lifecycle Event: {old_status} -> {new_status}. {action_description}", resource_id=vuln_id)

        self.session.commit()
        return vuln
