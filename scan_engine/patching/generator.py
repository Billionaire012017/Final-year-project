from scan_engine.intel.db import get_session
from scan_engine.intel.models import VulnerabilityRecord
from scan_engine.patching.models import PatchSuggestion
from scan_engine.patching.prompt_engine import PromptEngine
from scan_engine.patching.ai_service import MockAIService
from scan_engine.patching.risk_assessor import RiskAssessor
import difflib

class PatchGenerator:
    def __init__(self):
        self.session = get_session()
        self.prompt_engine = PromptEngine()
        self.ai_service = MockAIService()
        self.risk_assessor = RiskAssessor()

    def generate_patch(self, vulnerability_id: str) -> PatchSuggestion:
        vuln = self.session.get(VulnerabilityRecord, vulnerability_id)
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

        # 5. Save Suggestion
        suggestion = PatchSuggestion(
            vulnerability_id=vuln.id,
            patched_code=patched_code,
            diff=diff_text,
            explanation=explanation,
            confidence_score=confidence,
            risk_level=risk_level,
            risk_explanation=risk_desc
        )
        
        self.session.add(suggestion)
        vuln.state = "REMEDIATING" # Update state
        self.session.add(vuln)
        self.session.commit()
        self.session.refresh(suggestion)
        
        return suggestion
