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
if db_path:
    # Ensure directory exists for persistent disk
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        db_module.DB_URL = f"sqlite:///{db_path}"
    except:
        pass # Fallback to local if disk not writable

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from scan_engine.analytics import AnalyticsService
from scan_engine.intel.db import create_db_and_tables

# Initialize DB on load
create_db_and_tables()

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

@app.get("/dashboard")
def get_dashboard_metrics():
    analytics = AnalyticsService()
    try:
        return {
            "kpis": analytics.get_kpis(),
            "health_score": analytics.get_health_score()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

@app.get("/system/scanners")
def get_scanner_info():
    return {
        "engine_version": "3.0.0-PRO",
        "scanners": [
            {"name": "Bandit", "type": "SAST", "status": "Ready", "capabilities": ["Python AST", "Security Best Practices"]},
            {"name": "Semgrep", "type": "Polyglot", "status": "Standby", "capabilities": ["Taint Analysis", "Pattern Matching"]}
        ]
    }

@app.get("/vulnerabilities/{vuln_id}/source")
def get_source_code(vuln_id: str):
    from scan_engine.intel.models import VulnerabilityRecord
    from scan_engine.intel.db import get_session
    session = get_session()
    vuln = session.get(VulnerabilityRecord, vuln_id)
    if not vuln: raise HTTPException(status_code=404, detail="Vuln not found")
    
    try:
        if os.path.exists(vuln.file_path):
            with open(vuln.file_path, "r", encoding="utf-8") as f:
                return {"content": f.read(), "line": vuln.line_number, "file": vuln.file_path, "description": vuln.description}
        return {"content": f"# [ERR] File {vuln.file_path} moved or deleted.", "line": 1, "file": vuln.file_path, "description": vuln.description}
    except: raise HTTPException(status_code=500, detail="IO Error")

@app.post("/review/{vuln_id}")
def review_patch(vuln_id: str, action: str, reason: str = "Web UI Action"):
    from scan_engine.intel.lifecycle import LifecycleManager
    from scan_engine.intel.models import VulnerabilityState
    from scan_engine.patching.feedback import FeedbackService
    from scan_engine.patching.models import PatchSuggestion
    from scan_engine.intel.db import get_session

    session = get_session()
    lifecycle = LifecycleManager()
    feedback_service = FeedbackService()
    
    patch = session.query(PatchSuggestion).filter(PatchSuggestion.vulnerability_id == vuln_id).first()
    
    if action.lower() == "approve":
        lifecycle.transition_state(vuln_id, VulnerabilityState.FIXED, action)
        if patch: feedback_service.record_feedback(patch.id, "APPROVE", reason)
    else:
        lifecycle.transition_state(vuln_id, VulnerabilityState.REJECTED, reason)
        if patch: feedback_service.record_feedback(patch.id, "REJECT", reason)
    
    return {"status": "success"}
