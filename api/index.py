import os
import sys
import datetime
import random
import ast
import regex as re
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "vulnerabilities.db")
TEST_DATA_DIR = os.path.join(PROJECT_ROOT, "test_data")

# --- DATABASE SETUP ---
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    total_files_scanned = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    overall_risk_score = Column(Float, default=100.0)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(String, primary_key=True)
    scan_session_id = Column(Integer, ForeignKey("scan_sessions.id"))
    file_name = Column(String)
    line_number = Column(Integer)
    vulnerability_type = Column(String)
    severity = Column(String) # CRITICAL, HIGH, MEDIUM
    code_snippet = Column(Text)
    suggested_fix = Column(Text, nullable=True)
    diff = Column(Text, nullable=True)
    status = Column(String, default="DETECTED") # DETECTED, PATCHED, VALIDATED, FIXED
    confidence_score = Column(Float, default=0.0)
    risk_score = Column(Float, default=10.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id"))
    rating = Column(Integer)
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- FASTAPI APP ---
app = FastAPI(title="SecLAB Centralized Pipeline")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MODELS ---
class FeedbackRequest(BaseModel):
    rating: int
    comment: str

# --- SCANNERS ---
def scan_file_content(content, filename):
    vulns = []
    lines = content.split('\n')
    for i, line in enumerate(lines):
        line_num = i + 1
        stripped = line.strip()
        
        v_type = None
        severity = "LOW"
        risk = 2.0
        
        # Rule 1: Eval
        if "eval(" in stripped:
            v_type = "Unsafe Eval Execution"
            severity = "CRITICAL"
            risk = 10.0
        
        # Rule 2: Exec
        elif "exec(" in stripped:
            v_type = "Remote Code Execution (exec)"
            severity = "CRITICAL"
            risk = 9.5

        # Rule 3: SQL Injection (Basic pattern)
        elif "SELECT" in stripped and ("+" in stripped or "%" in stripped):
            v_type = "SQL Injection Risk"
            severity = "HIGH"
            risk = 8.0
            
        if v_type:
            vulns.append({
                "id": f"VULN-{random.randint(10000, 99999)}",
                "file_name": filename,
                "line_number": line_num,
                "vulnerability_type": v_type,
                "severity": severity,
                "code_snippet": stripped,
                "risk_score": risk,
                "status": "DETECTED"
            })
    return vulns

# --- ENDPOINTS ---

@app.get("/", response_class=HTMLResponse)
def read_root():
    path = os.path.join(BASE_DIR, "index.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

@app.post("/scan")
def execute_scan():
    db = SessionLocal()
    
    # Create new session
    session = ScanSession(total_files_scanned=0, total_vulnerabilities=0, overall_risk_score=0)
    db.add(session)
    db.commit()
    db.refresh(session)
    
    detected_vulns = []
    files_scanned = 0
    
    if os.path.exists(TEST_DATA_DIR):
        for root, dirs, files in os.walk(TEST_DATA_DIR):
            for file in files:
                if file.endswith((".py", ".js")):
                    files_scanned += 1
                    filepath = os.path.join(root, file)
                    with open(filepath, 'r') as f:
                        content = f.read()
                    
                    found = scan_file_content(content, file)
                    for v in found:
                        db_vuln = Vulnerability(**v, scan_session_id=session.id)
                        db.add(db_vuln)
                        detected_vulns.append(db_vuln)
    
    # Update Session Stats
    total_risk = sum(v.risk_score for v in detected_vulns)
    session.total_files_scanned = files_scanned
    session.total_vulnerabilities = len(detected_vulns)
    session.overall_risk_score = total_risk
    
    db.commit()
    db.refresh(session)
    
    # Extract values before closing
    sid = session.id
    count = len(detected_vulns)
    
    db.close()
    
    return {"status": "Complete", "session_id": sid, "detected": count}

@app.get("/vulnerabilities")
def get_vulnerabilities():
    db = SessionLocal()
    # Get latest session vulns or all
    vulns = db.query(Vulnerability).all()
    # Eager load or just return list of dicts to avoid detach error
    res = [v.__dict__ for v in vulns]  
    # Remove SA internal state
    for r in res:
        r.pop('_sa_instance_state', None)
    db.close()
    return res

@app.post("/patch/{id}")
def generate_patch(id: str):
    db = SessionLocal()
    vuln = db.query(Vulnerability).filter(Vulnerability.id == id).first()
    if not vuln:
        db.close()
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    # AI Simulation
    original = vuln.code_snippet
    fixed = original
    
    if "eval" in original:
        fixed = original.replace("eval", "ast.literal_eval")
        vuln.suggested_fix = "Use ast.literal_eval() for safe parsing."
    elif "exec" in original:
        fixed = "# exec() removed for security\n# Use specific module functions instead."
        vuln.suggested_fix = "Remove dynamic execution."
    elif "SELECT" in original:
        fixed = 'cursor.execute("SELECT * FROM users WHERE id = ?", (id,))'
        vuln.suggested_fix = "Use parameterized queries."
        
    diff = f"--- Original\n+++ Patched\n- {original}\n+ {fixed}"
    
    vuln.diff = diff
    vuln.status = "PATCHED"
    vuln.confidence_score = round(random.uniform(0.85, 0.98), 2)
    vuln.risk_score = vuln.risk_score # Risk persists until validation
    
    db.commit()
    db.refresh(vuln)
    db.close()
    return vuln

@app.post("/validate/{id}")
def validate_patch(id: str):
    db = SessionLocal()
    vuln = db.query(Vulnerability).filter(Vulnerability.id == id).first()
    if not vuln or vuln.status != "PATCHED":
        db.close()
        raise HTTPException(status_code=400, detail="Invalid state for validation")
        
    vuln.status = "VALIDATED"
    vuln.risk_score = 0.0 # Validated fix eliminates risk
    
    # Update Session Risk
    session = db.query(ScanSession).filter(ScanSession.id == vuln.scan_session_id).first()
    if session:
        # Recalculate total risk for that session
        all_vulns = db.query(Vulnerability).filter(Vulnerability.scan_session_id == session.id).all()
        session.overall_risk_score = sum(v.risk_score for v in all_vulns)
    
    db.commit()
    db.close()
    return {"status": "Validated", "new_risk_score": 0.0}

@app.get("/dashboard")
def get_dashboard_metrics():
    db = SessionLocal()
    # Get latest session
    session = db.query(ScanSession).order_by(ScanSession.created_at.desc()).first()
    
    if not session:
        db.close()
        return {"total": 0, "patched": 0, "validated": 0, "risk_score": 0}
        
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_session_id == session.id).all()
    total = len(vulns)
    patched = sum(1 for v in vulns if v.status == "PATCHED")
    validated = sum(1 for v in vulns if v.status == "VALIDATED" or v.status == "FIXED")
    risk_score = session.overall_risk_score
    scan_time = session.created_at
    
    db.close()
    return {
        "total": total,
        "patched": patched,
        "validated": validated,
        "risk_score": risk_score,
        "scan_time": scan_time
    }

@app.get("/system-core")
def get_system_core():
    db = SessionLocal()
    total_vulns = db.query(Vulnerability).count()
    validated = db.query(Vulnerability).filter(Vulnerability.status == "VALIDATED").count()
    patched = db.query(Vulnerability).filter(Vulnerability.status == "PATCHED").count()
    
    accuracy = 0
    if (validated + patched) > 0:
        accuracy = (validated / (validated + patched)) * 100
        
    db.close()
    return {
        "total_scans": db.query(ScanSession).count(),
        "total_detected": total_vulns,
        "total_patched": patched,
        "total_validated": validated,
        "engine_accuracy": round(accuracy, 1),
        "health_status": "OPTIMAL" if accuracy > 80 or total_vulns == 0 else "DEGRADED"
    }

@app.get("/compliance")
def get_compliance():
    db = SessionLocal()
    # Group by types
    vulns = db.query(Vulnerability).all()
    breakdown = {}
    for v in vulns:
        breakdown[v.vulnerability_type] = breakdown.get(v.vulnerability_type, 0) + 1
        
    validated_history = db.query(Vulnerability).filter(Vulnerability.status == "VALIDATED").order_by(Vulnerability.created_at.desc()).limit(10).all()
    
    db.close()
    return {
        "total_fixed": sum(1 for v in vulns if v.status == "VALIDATED"),
        "breakdown": breakdown,
        "history": [{"id": v.id, "type": v.vulnerability_type, "date": v.created_at} for v in validated_history]
    }

@app.post("/feedback/{id}")
def submit_feedback(id: str, feedback: FeedbackRequest):
    db = SessionLocal()
    fb = Feedback(vulnerability_id=id, rating=feedback.rating, comment=feedback.comment)
    db.add(fb)
    db.commit()
    db.close()
    return {"status": "Feedback Recorded"}

@app.get("/feedback")
def get_feedback():
    db = SessionLocal()
    feedbacks = db.query(Feedback).all()
    count = len(feedbacks)
    avg_rating = sum(f.rating for f in feedbacks) / count if count > 0 else 0
    
    comments = [{"vulnerability": f.vulnerability_id, "rating": f.rating, "comment": f.comment} for f in feedbacks[-5:]]
    db.close()
    return {
        "total_feedback": count,
        "average_rating": round(avg_rating, 1),
        "recent_comments": comments
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
