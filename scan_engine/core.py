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
            SemgrepScanner()
        ]
        create_db_and_tables()
        self.enricher = EnrichmentService()
        self.alert_service = AlertService()
        self.audit_service = AuditService()

    def run_scan(self, target_path: str, scan_type: str = "manual") -> ScanResult:
        scan_id = str(uuid.uuid4())
        
        self.audit_service.log_event("SCAN_START", f"Started scan on {target_path}")
        
        all_vulnerabilities: List[Vulnerability] = []
        
        print(f"Starting scan {scan_id} on {target_path} (Type: {scan_type})")

        for scanner in self.scanners:
            print(f"Running {scanner.name}...")
            try:
                findings = scanner.scan(target_path)
                print(f"  - Found {len(findings)} issues.")
                all_vulnerabilities.extend(findings)
            except Exception as e:
                print(f"  - Error executing {scanner.name}: {e}")

        # Save to DB
        session = get_session()
        for vuln in all_vulnerabilities:
            try:
                # Enrich and convert to Record
                record = self.enricher.enrich_vulnerability(vuln)
                
                # Check CRITICAL Alert
                if record.severity == "CRITICAL" or record.severity == "HIGH":
                     self.alert_service.trigger_alert(record.severity, f"Detected {record.severity} vulnerability: {record.name} in {record.file_path}")

                # Check if already exists (optional, simply merging or ignoring for now)
                exists = session.get(VulnerabilityRecord, record.id)
                if not exists:
                    session.add(record)
            except Exception as e:
                print(f"Error saving vulnerability {vuln.id}: {e}")
        
        session.commit()
        session.close()

        self.audit_service.log_event("SCAN_COMPLETE", f"Completed scan with {len(all_vulnerabilities)} findings")

        # Determine status
        status = ScanStatus.SUCCESS
        
        result = ScanResult(
            scan_id=scan_id,
            timestamp=datetime.utcnow(),
            status=status,
            vulnerabilities=all_vulnerabilities,
            metadata={
                "target_path": target_path,
                "scan_type": scan_type,
                "scanner_count": len(self.scanners)
            }
        )
        
        return result
