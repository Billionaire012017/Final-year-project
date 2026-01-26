import json
import subprocess
import uuid
from typing import List
from scan_engine.models import Vulnerability, Severity
from scan_engine.scanners.base import BaseScanner

class BanditScanner(BaseScanner):
    def __init__(self):
        super().__init__("bandit")

    def _map_severity(self, bandit_severity: str) -> Severity:
        severity_map = {
            "LOW": Severity.LOW,
            "MEDIUM": Severity.MEDIUM,
            "HIGH": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL,
        }
        return severity_map.get(bandit_severity.upper(), Severity.UNKNOWN)

    def scan(self, target_path: str) -> List[Vulnerability]:
        try:
            # Run bandit scan with JSON output
            result = subprocess.run(
                ["bandit", "-r", target_path, "-f", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Bandit returns exit code 1 if issues are found, which is 'success' for us
            # But if it crashes (e.g. not found), it might handle differently.
            # We trust stdout has the JSON.
            
            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If no output or invalid json, return empty or handle error
                # For now, let's assume valid run or empty
                return []

            vulnerabilities = []
            results = output_data.get("results", [])

            for issue in results:
                vuln = Vulnerability(
                    id=str(uuid.uuid4()),
                    name=issue.get("test_id", "Unknown") + ": " + issue.get("test_name", "Unknown"),
                    description=issue.get("issue_text", ""),
                    severity=self._map_severity(issue.get("issue_severity", "UNKNOWN")),
                    file_path=issue.get("filename", ""),
                    line_number=issue.get("line_number", 0),
                    scanner_name=self.name,
                    cwe_id=str(issue.get("issue_cwe", {}).get("id", "")),
                    fix_recommendation=f"More info: {issue.get('more_info', '')}"
                )
                vulnerabilities.append(vuln)
                
            return vulnerabilities

        except Exception as e:
            # log error
            print(f"Error running Bandit: {e}")
            return []
