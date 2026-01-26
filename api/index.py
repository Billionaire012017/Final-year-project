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

# Note: Scanning via API requires implementing file upload or git cloning.
# For Vercel demo purposes, we expose the analytics and status first.
