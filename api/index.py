from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from scan_engine.analytics import AnalyticsService
from scan_engine.intel.db import create_db_and_tables
import os

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
