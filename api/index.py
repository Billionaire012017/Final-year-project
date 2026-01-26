import os
import sys

# CRITICAL: Fix for module imports on Render/Replit
# Add parent directory to sys.path so 'scan_engine' is found even if run from 'api/'
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.append(root_dir)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from scan_engine.analytics import AnalyticsService
from scan_engine.intel.db import create_db_and_tables

# PERSISTENCE FIX: Allow custom DB path via environment variable
# Recommened for Render: /etc/data/vulnerabilities.db
db_path = os.getenv("DB_PATH")
if db_path:
    # Update the core DB path if provided
    import scan_engine.intel.db as db_module
    db_module.DB_URL = f"sqlite:///{db_path}"

# Initialize DB on load
create_db_and_tables()

app = FastAPI()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For production, restrict this to your vercel domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def read_root():
    """
    Serves the premium dashboard UI.
    """
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(index_path):
        return "<h1>Frontend Source Not Found</h1><p>Please ensure public/index.html exists.</p>"
    
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/dashboard")
def get_dashboard_metrics():
    """
    Returns dashboard KPIs and health score.
    """
    analytics = AnalyticsService()
    try:
        kpis = analytics.get_kpis()
        health = analytics.get_health_score()
        return {
            "kpis": kpis,
            "health_score": health
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/recent-activity")
def get_recent_activity():
    """
    Returns recent activity log.
    """
    analytics = AnalyticsService()
    try:
        trends = analytics.get_trend_data()
        return {"activity": trends}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vulnerabilities")
def list_vulnerabilities():
    """
    Returns full list of vulnerabilities.
    """
    analytics = AnalyticsService()
    return analytics.get_pipeline_data()

@app.post("/scan-trigger")
def trigger_scan(path: str = "."):
    """
    Triggers a fresh scan.
    """
    from scan_engine.core import ScanEngine
    engine = ScanEngine()
    result = engine.run_scan(path)
    return {"status": "success", "found": len(result.vulnerabilities)}

@app.get("/alerts")
def get_alerts():
    from scan_engine.alerts import AlertService
    return AlertService().get_recent_alerts(limit=20)

@app.get("/audit-logs")
def get_audit():
    from scan_engine.audit import AuditService
    import json
    return json.loads(AuditService().export_logs_json())

@app.get("/vulnerabilities/{vuln_id}/source")
def get_source_code(vuln_id: str):
    """
    Returns the source file content and the line number of the error.
    """
    from scan_engine.intel.models import VulnerabilityRecord
    from scan_engine.intel.db import get_session
    session = get_session()
    vuln = session.get(VulnerabilityRecord, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    try:
        if os.path.exists(vuln.file_path):
            with open(vuln.file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {
                "content": content,
                "line": vuln.line_number,
                "file": vuln.file_path,
                "description": vuln.description
            }
        else:
             # Fallback for demo if local file not found on server
             return {
                "content": f"# File {vuln.file_path} not found on server.\n# This is a placeholder for the error line.\ndef example():\n    pass",
                "line": 1,
                "file": vuln.file_path,
                "description": vuln.description
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vulnerabilities/{vuln_id}/history")
def get_vuln_history(vuln_id: str):
    from scan_engine.intel.models import VulnerabilityHistory
    from scan_engine.intel.db import get_session
    session = get_session()
    history = session.query(VulnerabilityHistory).filter(VulnerabilityHistory.vulnerability_id == vuln_id).all()
    return history

@app.get("/system/scanners")
def get_scanner_info():
    """
    Returns data for the 'Scan Engine Core' tab.
    """
    return {
        "engine_version": "2.4.0-CyberHUD",
        "scanners": [
            {"name": "Bandit", "type": "SAST", "status": "Ready", "capabilities": ["Python AST", "Security Best Practices"]},
            {"name": "Semgrep", "type": "Polygolt SAST", "status": "Standby", "capabilities": ["Pattern Matching", "Data Flow"]}
        ],
        "total_rules": 450,
        "mode": "Autonomous Self-Healing"
    }

@app.get("/config")
def get_config():
    return {
        "roles": ["ADMIN", "DEVELOPER", "VIEWER"],
        "retention_policy": "Forever",
        "log_level": "DEBUG"
    }

@app.post("/patch/{vuln_id}")
def generate_patch(vuln_id: str):
    from scan_engine.patching.generator import PatchGenerator
    generator = PatchGenerator()
    try:
        suggestion = generator.generate_patch(vuln_id)
        return suggestion
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/review/{vuln_id}")
def review_patch(vuln_id: str, action: str, reason: str = "Approved via Web UI"):
    from scan_engine.intel.lifecycle import LifecycleManager
    from scan_engine.intel.models import VulnerabilityState
    from scan_engine.patching.feedback import FeedbackService
    from scan_engine.patching.models import PatchSuggestion
    from scan_engine.intel.db import get_session

    session = get_session()
    lifecycle = LifecycleManager()
    feedback_service = FeedbackService()
    
    patch = session.query(PatchSuggestion).filter(PatchSuggestion.vulnerability_id == vuln_id).first()
    if not patch:
         raise HTTPException(status_code=404, detail="Patch not found")

    if action.lower() == "approve":
        lifecycle.transition_state(vuln_id, VulnerabilityState.FIXED, action)
        feedback_service.record_feedback(patch.id, "APPROVE", reason)
    else:
        lifecycle.transition_state(vuln_id, VulnerabilityState.REJECTED, reason)
        feedback_service.record_feedback(patch.id, "REJECT", reason)
    
    return {"status": "success"}

# Note: Scanning via API requires implementing file upload or git cloning.
