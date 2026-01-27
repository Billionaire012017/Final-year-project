from scan_engine.intel.db import get_session
from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityState
from scan_engine.intel.lifecycle import LifecycleManager
from scan_engine.patching.models import PatchSuggestion, RiskLevel, ValidationStatus
from scan_engine.patching.prompt_engine import PromptEngine
from scan_engine.patching.ai_service import MockAIService
from scan_engine.patching.risk_assessor import RiskAssessor
from scan_engine.patching.validator import PatchValidator
from scan_engine.alerts import AlertService
from scan_engine.audit import AuditService
import difflib

class PatchGenerator:
    def __init__(self):
        self.prompt_engine = PromptEngine()
        self.ai_service = MockAIService()
        self.risk_assessor = RiskAssessor()
        self.lifecycle = LifecycleManager()
        self.validator = PatchValidator()
        self.alert_service = AlertService()
        self.audit_service = AuditService()

    def generate_patch(self, vulnerability_id: str) -> PatchSuggestion:
        with get_session() as session:
            vuln = session.get(VulnerabilityRecord, vulnerability_id)
            if not vuln:
                raise ValueError(f"Vulnerability {vulnerability_id} not found.")

            if not vuln.code_snippet:
                 raise ValueError("No code snippet available for this vulnerability.")

            # 1. Create Prompt
            prompt = self.prompt_engine.create_prompt(vuln)

            # 2. Get Patch from AI
            ai_response = self.ai_service.generate_patch(prompt)
            patched_code = ai_response["patched_code"]
            explanation = ai_response["explanation"]

            # 3. Calculate Diff
            diff_gen = difflib.unified_diff(
                vuln.code_snippet.splitlines(),
                patched_code.splitlines(),
                fromfile='original',
                tofile='patched',
                lineterm=''
            )
            diff_text = "\n".join(list(diff_gen))

            # 4. Assess Risk
            confidence, risk_level, risk_desc = self.risk_assessor.assess_patch(
                vuln.code_snippet, patched_code, vuln.severity
            )

            # 5. Save Initial Suggestion (State: PENDING validation)
            suggestion = PatchSuggestion(
                vulnerability_id=vuln.id,
                patched_code=patched_code,
                diff=diff_text,
                explanation=explanation,
                confidence_score=confidence,
                risk_level=risk_level,
                risk_explanation=risk_desc
            )
            
            session.add(suggestion)
            session.commit()
            session.refresh(suggestion)

            # 6. Update State -> FIX_GENERATED
            self.lifecycle.transition_state(vuln.id, VulnerabilityState.FIX_GENERATED, "AI Patch Generated")
            self.audit_service.log_event("PATCH_GENERATED", f"Generated patch for {vuln.id}")

            # 7. Run Validation
            val_status, val_msg = self.validator.validate_patch(vuln, suggestion)
            
            if val_status == ValidationStatus.FAILED:
                self.alert_service.trigger_alert("WARNING", f"Patch validation failed for {vuln.id}: {val_msg}")

            suggestion.validation_status = val_status
            suggestion.validation_message = val_msg
            session.add(suggestion)
            session.commit()

            # 8. Update State -> VALIDATED (if passed)
            if val_status == ValidationStatus.PASSED:
                self.lifecycle.transition_state(vuln.id, VulnerabilityState.VALIDATED, "Patch Passed Validation")
                self.audit_service.log_event("PATCH_VALIDATED", f"Patch passed validation for {vuln.id}")

            return suggestion
