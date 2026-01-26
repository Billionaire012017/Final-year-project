import os
from typing import Optional
from scan_engine.models import Vulnerability
from scan_engine.intel.models import VulnerabilityRecord

class EnrichmentService:
    def enrich_vulnerability(self, vuln: Vulnerability) -> VulnerabilityRecord:
        code_snippet = self._get_code_snippet(vuln.file_path, vuln.line_number)
        ai_supported = self._check_ai_supported(vuln)
        
        return VulnerabilityRecord(
            id=vuln.id,
            name=vuln.name,
            description=vuln.description,
            severity=vuln.severity.value,
            file_path=vuln.file_path,
            line_number=vuln.line_number,
            scanner_name=vuln.scanner_name,
            code_snippet=code_snippet,
            cwe_id=vuln.cwe_id,
            ai_remediation_supported=ai_supported
        )

    def _get_code_snippet(self, file_path: str, line_number: int, context: int = 2) -> Optional[str]:
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                start = max(0, line_number - 1 - context)
                end = min(len(lines), line_number + context)
                return "".join(lines[start:end])
        except Exception:
            return None

    def _check_ai_supported(self, vuln: Vulnerability) -> bool:
        # Heuristic: Support common easy-to-fix patterns
        supported_kw = ["sql", "injection", "xss", "cross-site", "hardcoded", "password", "eval", "assert"]
        name_lower = vuln.name.lower()
        desc_lower = vuln.description.lower()
        
        for kw in supported_kw:
            if kw in name_lower or kw in desc_lower:
                return True
        return False
