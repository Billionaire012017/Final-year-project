import ast
import difflib
from typing import Tuple
from scan_engine.patching.models import RiskLevel

class RiskAssessor:
    def assess_patch(self, original_code: str, patched_code: str, severity: str) -> Tuple[float, RiskLevel, str]:
        # 1. Syntax Check
        try:
            ast.parse(patched_code)
        except SyntaxError:
            return 0.0, RiskLevel.HIGH, "Patched code has syntax errors."

        # 2. Diff Analysis
        diff = list(difflib.unified_diff(original_code.splitlines(), patched_code.splitlines()))
        changes = len([line for line in diff if line.startswith('+') or line.startswith('-')])
        
        # Heuristic: If changes > 50% of original lines (rough approx), risky.
        original_lines = len(original_code.splitlines())
        if original_lines > 0 and changes / original_lines > 1.0:
             return 50.0, RiskLevel.MEDIUM, "Patch changes significant portion of code."

        # 3. Severity Context
        if severity == "CRITICAL" or severity == "HIGH":
             # Critical fixes are risky if automated, but we want to encourage them if syntax is valid.
             # Let's be conservative.
             return 80.0, RiskLevel.MEDIUM, "High severity vulnerability fix requires manual review."

        return 95.0, RiskLevel.LOW, "Patch looks safe and valid."
