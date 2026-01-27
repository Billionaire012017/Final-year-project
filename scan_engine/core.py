import uuid
from typing import List
from datetime import datetime
from scan_engine.models import ScanResult, ScanStatus, Vulnerability
from scan_engine.scanners.bandit_scanner import BanditScanner
from scan_engine.scanners.semgrep_scanner import SemgrepScanner
from scan_engine.intel.db import create_db_and_tables, get_session
from scan_engine.intel.enrichment import EnrichmentService
from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityHistory
from scan_engine.patching.models import PatchSuggestion
from scan_engine.patching.feedback import FeedbackRecord
from scan_engine.alerts import AlertService, AlertRecord
from scan_engine.audit import AuditService, SystemAudit

class ScanEngine:
    def __init__(self):
        self.scanners = [
            BanditScanner(),
        ]
        
        # Check if semgrep is available
        import shutil
        if shutil.which("semgrep"):
            self.scanners.append(SemgrepScanner())
        create_db_and_tables()
        self.enricher = EnrichmentService()
        self.alert_service = AlertService()
        self.audit_service = AuditService()

    def run_scan(self, target_path: str, scan_type: str = "manual") -> ScanRecord:
        scan_id = str(uuid.uuid4())
        session = get_session()
        
        # Create persistent scan record
        scan_record = ScanRecord(
            id=scan_id,
            target=target_path,
            status="RUNNING",
            timestamp=datetime.utcnow()
        )
        session.add(scan_record)
        session.commit()
        
        self.audit_service.log_event("SCAN", f"Started diagnostic scan on target: {target_path}", resource_id=scan_id)
        
        all_vulnerabilities: List[Vulnerability] = []
        
        for scanner in self.scanners:
            try:
                findings = scanner.scan(target_path)
                all_vulnerabilities.extend(findings)
            except Exception as e:
                print(f"Error executing {scanner.name}: {e}")

        severity_map = {}
        findings_saved = 0
        
        for vuln in all_vulnerabilities:
            try:
                # Deduplication logic: (file_path, line_number, name)
                # Create a unique hash for this vulnerability instance
                import hashlib
                dedup_key = hashlib.md5(f"{vuln.file_path}:{vuln.line_number}:{vuln.name}".encode()).hexdigest()
                
                # Check for existing record
                exists = session.get(VulnerabilityRecord, dedup_key)
                if exists:
                    continue

                # Enrich and convert to Record
                record = self.enricher.enrich_vulnerability(vuln)
                record.id = dedup_key # Override with dedup key
                record.scan_id = scan_id
                
                # Severity tracking
                sev = record.severity.upper()
                severity_map[sev] = severity_map.get(sev, 0) + 1
                
                if sev in ["CRITICAL", "HIGH"]:
                     self.alert_service.trigger_alert(sev, f"Detected {sev} vulnerability: {record.vulnerability_type} in {record.file_path}")

                session.add(record)
                findings_saved += 1
            except Exception as e:
                print(f"Error saving vulnerability {vuln.id}: {e}")
        
        # Update scan record results
        import json
        scan_record.status = "SUCCESS"
        scan_record.findings_count = findings_saved
        scan_record.severity_breakdown = json.dumps(severity_map)
        
        session.add(scan_record)
        session.commit()
        session.close()

        self.audit_service.log_event("SCAN", f"Diagnostic scan sequence terminated. Findings: {findings_saved}", resource_id=scan_id)
        
        return scan_record
