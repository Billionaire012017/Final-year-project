import json
import subprocess
import uuid
from typing import List
from scan_engine.models import Vulnerability, Severity
from scan_engine.scanners.base import BaseScanner

class SemgrepScanner(BaseScanner):
    def __init__(self):
        super().__init__("semgrep")

    def _map_severity(self, semgrep_severity: str) -> Severity:
        # Semgrep severities: INFO, WARNING, ERROR
        severity_map = {
            "INFO": Severity.LOW,
            "WARNING": Severity.MEDIUM,
            "ERROR": Severity.HIGH, 
        }
        return severity_map.get(semgrep_severity.upper(), Severity.UNKNOWN)

    def scan(self, target_path: str) -> List[Vulnerability]:
        try:
            # Run semgrep scan with JSON output
            # --quiet to reduce noise, --json for output
            # We assume default config or "p/security-audit" or "auto"
            # Using 'auto' config for generic usage
            cmd = ["semgrep", "scan", "--config=auto", "--json", "--quiet", target_path]
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8' # Ensure utf-8 encoding
            )

            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                return []

            vulnerabilities = []
            results = output_data.get("results", [])

            for issue in results:
                extra = issue.get("extra", {})
                vuln = Vulnerability(
                    id=str(uuid.uuid4()),
                    name=issue.get("check_id", "Unknown"),
                    description=extra.get("message", ""),
                    severity=self._map_severity(extra.get("severity", "UNKNOWN")),
                    file_path=issue.get("path", ""),
                    line_number=issue.get("start", {}).get("line", 0),
                    scanner_name=self.name,
                    cwe_id=str(extra.get("metadata", {}).get("cwe", [""])[0]),
                    fix_recommendation=extra.get("fix", None)
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            print(f"Error running Semgrep: {e}")
            return []
