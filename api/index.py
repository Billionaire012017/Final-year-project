from fastapi import FastAPI, HTTPException
from scan_engine.analytics import AnalyticsService
from scan_engine.intel.db import create_db_and_tables

# Initialize DB on load (for Vercel persistence, requires Postgres later)
create_db_and_tables()

app = FastAPI()

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "Vulnerability Scan Engine",
        "version": "1.0.0",
        "docs_url": "/docs"
    }

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
