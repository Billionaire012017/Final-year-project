import os
import shutil
import tempfile
from scan_engine.intel.models import VulnerabilityRecord
from scan_engine.patching.models import PatchSuggestion, ValidationStatus
from scan_engine.core import ScanEngine # Reuse existing engine logic if adaptable, or use scanners directly.
from scan_engine.scanners.bandit_scanner import BanditScanner
from scan_engine.scanners.semgrep_scanner import SemgrepScanner

from typing import Tuple
class PatchValidator:
    def validate_patch(self, vuln: VulnerabilityRecord, patch: PatchSuggestion) -> Tuple[ValidationStatus, str]:
        # Create a temp file
        try:
            # We need to simulate the file structure or at least the file itself
            # For simplicity, we create a single temp file with the patched content
            # This works for single-file analysis tools like Bandit/Semgrep mostly.
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py', encoding='utf-8') as tmp:
                tmp.write(patch.patched_code)
                tmp_path = tmp.name

            # Determine scanner
            scanner = None
            if vuln.scanner_name == "bandit":
                scanner = BanditScanner()
            elif vuln.scanner_name == "semgrep":
                scanner = SemgrepScanner()
            else:
                return ValidationStatus.ERROR, f"Unknown scanner: {vuln.scanner_name}"

            # Run Scan
            findings = scanner.scan(tmp_path)
            
            # Check if original vulnerability type is still present
            # We match roughly by name or CWE. 
            # In a real system, we'd need precise matching (e.g., line number mapping is hard on diffs, so we rely on signature).
            
            # Simple check: If ANY findings of similar type remain, FAIL.
            # If 0 findings, PASS.
            
            still_present = False
            found_names = []
            
            if len(findings) == 0:
                result_status = ValidationStatus.PASSED
                msg = "No vulnerabilities detected in patched code."
            else:
                # Check if specific issue persists
                for f in findings:
                    found_names.append(f.name)
                    # Heuristic: if name matches original vuln name (e.g., B105)
                    # Bandit: "B105: hardcoded_password_string"
                    if vuln.name.split(':')[0] in f.name: 
                        still_present = True
                
                if still_present:
                     result_status = ValidationStatus.FAILED
                     msg = f"Vulnerability persisted: {', '.join(found_names)}"
                else:
                     # Findings found, but maybe different ones? 
                     # For safety, if new issues introduced, it's also a FAIL or WARN.
                     # Let's call it FAILED for strictness.
                     result_status = ValidationStatus.FAILED
                     msg = f"New or remaining issues found: {', '.join(found_names)}"

            os.remove(tmp_path)
            return result_status, msg

        except Exception as e:
            return ValidationStatus.ERROR, str(e)
