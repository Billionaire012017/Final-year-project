from datetime import datetime
from scan_engine.intel.db import get_session
from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityState, VulnerabilityHistory

class LifecycleManager:
    def __init__(self):
        self.session = get_session()

    def transition_state(self, vuln_id: str, new_state: VulnerabilityState, action_description: str):
        vuln = self.session.get(VulnerabilityRecord, vuln_id)
        if not vuln:
            raise ValueError(f"Vulnerability {vuln_id} not found.")

        old_state = vuln.state
        
        # In a real system, we'd check valid transitions here.
        # e.g., if old_state == FIXED, typically can't go back unless re-opened.
        
        vuln.state = new_state
        self.session.add(vuln)
        
        # Log History
        history = VulnerabilityHistory(
            vulnerability_id=vuln_id,
            old_state=old_state.value if hasattr(old_state, 'value') else str(old_state),
            new_state=new_state.value,
            action=action_description,
            timestamp=datetime.utcnow()
        )
        self.session.add(history)
        
        self.session.commit()
        return vuln
