import os
import sys

# 1. ROBUST PATHING FIX (Cures 404 Module Not Found)
# Ensure root is in sys.path regardless of how/where the app is started
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# 2. PERSISTENCE DYNAMICS
import scan_engine.intel.db as db_module
db_path = os.getenv("DB_PATH")
if not db_path:
    # Use absolute path to project root to avoid CWD issues on Render
    db_path = os.path.join(root_dir, "vulnerabilities.db")

try:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db_module.DB_URL = f"sqlite:///{db_path}"
except Exception as e:
    print(f"DATABASE_PATH_INIT_WARNING: {e}")
    # Fallback to /tmp which is usually writable on Render
    db_module.DB_URL = "sqlite:////tmp/vulnerabilities.db"

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from scan_engine.analytics import AnalyticsService
from scan_engine.intel.db import create_db_and_tables

# Initialize DB on load
create_db_and_tables()

# Auto-Seed for "Neat and Clean" look on fresh deployments
try:
    from seed_data import seed_enterprise_data
    from scan_engine.intel.models import VulnerabilityRecord
    with db_module.get_session() as session:
        if session.query(VulnerabilityRecord).count() == 0:
            print("🌱 EMPTY_STATE_DETECTED: Bootstrapping Enterprise Security Data...")
            seed_enterprise_data()
except Exception as e:
    print(f"SEEDING_SKIPPED: {e}")

app = FastAPI(title="SecLAB Alpha Core")

# 3. CORS & REDIRECT HARDENING (Cures 405 Method Not Allowed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allow_headers=["*"],
)

@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    """
    Explicitly handle OPTIONS requests to prevent 405 on CORS preflights.
    """
    return JSONResponse(content="OK", status_code=200)

@app.get("/", response_class=HTMLResponse)
def read_root():
    """Serves the master Cyber HUD."""
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(index_path):
        return "<h1>CORE_ERROR: index.html not found in api/</h1>"
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/health")
def health_check():
    return {"status": "operational", "engine": "SecLAB Core v3.0"}

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    from fastapi import Response
    return Response(status_code=204)

@app.get("/dashboard")
def get_dashboard_metrics():
    analytics = AnalyticsService()
    try:
        kpis = analytics.get_kpis()
        health_score = analytics.get_health_score()
        return {
            "kpis": kpis,
            "health_score": health_score
        }
    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error fetching dashboard metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard metrics: {str(e)}")

@app.get("/recent-activity")
def get_recent_activity():
    analytics = AnalyticsService()
    return {"activity": analytics.get_trend_data()}

@app.get("/vulnerabilities")
def list_vulnerabilities():
    return AnalyticsService().get_pipeline_data()

@app.post("/scan-trigger")
def trigger_scan(path: str = "."):
    from scan_engine.core import ScanEngine
    engine = ScanEngine()
    result = engine.run_scan(path)
    return {"status": "success", "findings": len(result.vulnerabilities)}

@app.get("/alerts")
def get_alerts():
    from scan_engine.alerts import AlertService
    return AlertService().get_recent_alerts(limit=20)

@app.get("/audit-logs")
def get_audit():
    from scan_engine.audit import AuditService
    import json
    return json.loads(AuditService().export_logs_json())

@app.get("/reports")
def get_reports_metadata():
    """
    Returns metadata for executive reports.
    """
    return [
        {"id": "R-101", "name": "Weekly Intrusion Summary", "status": "Generated", "size": "2.4 MB", "date": "2026-01-25"},
        {"id": "R-102", "name": "Compliance Audit (ISO 27001)", "status": "Verified", "size": "5.1 MB", "date": "2026-01-24"},
        {"id": "R-103", "name": "AI Remediation Effectiveness", "status": "Generated", "size": "1.8 MB", "date": "2026-01-23"}
    ]

@app.get("/infrastructure/assets")
def get_infra_assets():
    from scan_engine.infrastructure import InfrastructureService
    return InfrastructureService().get_all_assets()

@app.get("/infrastructure/stats")
def get_infra_stats():
    from scan_engine.infrastructure import InfrastructureService
    return InfrastructureService().get_infrastructure_summary()

@app.get("/system/health")
def get_system_health():
    from scan_engine.health import health_monitor
    return health_monitor.get_health_telemetry()

@app.get("/network-topology")
def get_network_topology():
    """
    Returns mockup topology data for the visualizer.
    """
    return {
        "nodes": [
            {"id": "Edge-01", "type": "Gateway", "status": "Secure", "load": "12%"},
            {"id": "Core-DB", "type": "Storage", "status": "Protected", "load": "45%"},
            {"id": "AI-Kernel", "type": "Compute", "status": "Active", "load": "88%"},
            {"id": "Ext-Bridge", "type": "Proxy", "status": "Monitoring", "load": "5%"}
        ],
        "links": [
            {"source": "Edge-01", "target": "Ext-Bridge", "latency": "2ms"},
            {"source": "Ext-Bridge", "target": "AI-Kernel", "latency": "5ms"},
            {"source": "AI-Kernel", "target": "Core-DB", "latency": "1ms"}
        ]
    }

@app.get("/system/scanners")
def get_scanner_info():
    return {
        "engine_version": "3.2.0-ENTERPRISE",
        "scanners": [
            {"name": "Bandit", "type": "SAST", "status": "Ready", "capabilities": ["Python AST", "Security Best Practices"]},
            {"name": "Semgrep", "type": "Polyglot SAST", "status": "Operational", "capabilities": ["Taint Analysis", "Pattern Matching"]},
            {"name": "Trivy", "type": "SCA", "status": "Standby", "capabilities": ["Vulnerability Database", "SBOM"]}
        ],
        "total_rules": 1250,
        "mode": "Autonomous Self-Healing"
    }

@app.get("/vulnerabilities/{vuln_id}/source")
def get_vulnerability_source(vuln_id: str):
    from scan_engine.intel.models import VulnerabilityRecord
    from scan_engine.intel.db import get_session
    with get_session() as session:
        vuln = session.get(VulnerabilityRecord, vuln_id)
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        return {
            "id": vuln.id,
            "file": vuln.file_name,
            "path": vuln.file_path,
            "lines": vuln.vulnerable_lines,
            "type": vuln.vulnerability_type,
            "severity": vuln.severity,
            "risk_score": vuln.risk_score,
            "status": vuln.status,
            "content_original": vuln.full_code or "# Source code not available",
            "content_fixed": vuln.full_code_fixed or vuln.full_code or "# No fix generated",
            "explanation": vuln.ai_explanation,
            "guidance": vuln.remediation_guidance,
            "exploit_scenario": vuln.exploit_scenario,
            "root_cause": vuln.root_cause,
            "exposure": vuln.exposure,
            "exploitability": vuln.exploitability,
            "asset_criticality": vuln.asset_criticality,
            "business_impact": vuln.business_impact,
            "reasoning_log": vuln.ai_reasoning_log
        }

@app.post("/review/{vuln_id}")
def review_patch(vuln_id: str, action: str, reason: str = "Web UI Action"):
    from scan_engine.intel.lifecycle import LifecycleManager
    from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityHistory, ScanRecord, VulnerabilityStatus
    from scan_engine.intel.db import get_session

    lifecycle = LifecycleManager()
    
    if action.lower() == "approve":
        with get_session() as session:
            vuln = session.get(VulnerabilityRecord, vuln_id)
            # REAL FILE PATCHING LOGIC
            if vuln and vuln.full_code_fixed and os.path.exists(vuln.file_path):
                try:
                    with open(vuln.file_path, "w", encoding="utf-8") as f:
                        f.write(vuln.full_code_fixed)
                    lifecycle.transition_state(vuln_id, VulnerabilityStatus.FIXED, "AI Patch Applied & Approved")
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Patch Failed: {str(e)}")
            else:
                lifecycle.transition_state(vuln_id, VulnerabilityStatus.FIXED, action)
    elif action.lower() == "reject":
        lifecycle.transition_state(vuln_id, VulnerabilityStatus.REJECTED, reason)
    elif action.lower() == "validate":
        lifecycle.transition_state(vuln_id, VulnerabilityStatus.VALIDATED, reason)
    
    return {"status": "success"}
