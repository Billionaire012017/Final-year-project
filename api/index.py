import os
import sys
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
import requests
from bs4 import BeautifulSoup
import uuid
import datetime
import random
import ast
import regex as re

# --- GLOBAL LOGS & SESSIONS ---
terminal_sessions = {}

def append_log(session_id, msg):
    if session_id not in terminal_sessions:
        terminal_sessions[session_id] = {"logs": [], "status": "RUNNING"}
    
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    lvl = "[INFO]"
    msg_lower = msg.lower()
    if any(x in msg_lower for x in ["eval", "detected", "error", "critical", "warning"]):
        lvl = "[WARNING]"
    if "critical" in msg_lower or "[error]" in msg_lower:
        lvl = "[ERROR]"
    if any(x in msg_lower for x in ["completed", "success"]):
        lvl = "[SUCCESS]"
        
    log_entry = f"{lvl} [{timestamp}] {msg}"
    terminal_sessions[session_id]["logs"].append(log_entry)

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

# --- PREDEFINED WEBSITES ---
PREDEFINED_WEBSITES = [
    {"id": "juice_shop", "name": "OWASP Juice Shop (Official Demo)", "url": "https://demo.owasp-juice.shop/"},
    {"id": "altoro_mutual", "name": "Altoro Mutual Banking Demo (IBM Test Site)", "url": "http://demo.testfire.net/"},
    {"id": "acunetix_testphp", "name": "Acunetix Test PHP Application", "url": "http://testphp.vulnweb.com/"},
    {"id": "public_firing_range", "name": "Google Gruyere / Public Firing Range", "url": "https://public-firing-range.appspot.com/"},
    {"id": "xss_game", "name": "Google XSS Game", "url": "https://xss-game.appspot.com/"},
    {"id": "badstore", "name": "OWASP BadStore", "url": "http://badstore.net/"},
    {"id": "zero_bank", "name": "Zero Bank Demo Application", "url": "http://zero.webappsecurity.com/"},
    {"id": "vulnweb_api", "name": "VulnWeb REST API Demo", "url": "https://api.vulnweb.com/"},
    {"id": "hackthissite", "name": "HackThisSite Training Platform", "url": "https://www.hackthissite.org/"},
    {"id": "demo_login_app", "name": "Demo Login Test Application", "url": "https://the-internet.herokuapp.com/"}
]

# --- ENDPOINTS ---

@app.get("/", response_class=HTMLResponse)
def read_root():
    path = os.path.join(BASE_DIR, "index.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/available-websites")
def get_available_websites():
    return {"websites": PREDEFINED_WEBSITES}

@app.get("/terminal-stream")
def terminal_stream(session_id: str = "default"):
    session = terminal_sessions.get(session_id, {"logs": [], "status": "COMPLETED"})
    return session

@app.post("/scan")
def execute_scan(background_tasks: BackgroundTasks):
    session_id = str(uuid.uuid4())
    terminal_sessions[session_id] = {"logs": [], "status": "RUNNING"}
    background_tasks.add_task(run_filesystem_scan, session_id)
    return {"scan_id": session_id}

def run_filesystem_scan(session_id: str):
    append_log(session_id, "Starting filesystem scan...")
    db = SessionLocal()
    
    # Create new session
    scan_session = ScanSession(total_files_scanned=0, total_vulnerabilities=0, overall_risk_score=0)
    db.add(scan_session)
    db.commit()
    db.refresh(scan_session)
    
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
                        append_log(session_id, f"Vulnerability detected in {file}: {v['vulnerability_type']}")
                        # Check for existing duplicate (file + line + type)
                        existing = db.query(Vulnerability).filter(
                            Vulnerability.file_name == v["file_name"],
                            Vulnerability.line_number == v["line_number"],
                            Vulnerability.vulnerability_type == v["vulnerability_type"]
                        ).first()
                        
                        if existing:
                            existing.scan_session_id = scan_session.id
                            detected_vulns.append(existing)
                        else:
                            db_vuln = Vulnerability(**v, scan_session_id=scan_session.id)
                            db.add(db_vuln)
                            detected_vulns.append(db_vuln)
    
    append_log(session_id, f"Scan session {scan_session.id} finished. Found {len(detected_vulns)} issues.")
    
    # Update Session Stats
    total_risk = sum(v.risk_score for v in detected_vulns)
    scan_session.total_files_scanned = files_scanned
    scan_session.total_vulnerabilities = len(detected_vulns)
    scan_session.overall_risk_score = total_risk
    
    db.commit()
    db.close()
    terminal_sessions[session_id]["status"] = "COMPLETED"

@app.post("/scan-website/{website_id}")
def scan_predefined_website(website_id: str, background_tasks: BackgroundTasks):
    site = next((s for s in PREDEFINED_WEBSITES if s["id"] == website_id), None)
    if not site:
        raise HTTPException(status_code=404, detail="Website not found in registry")
    
    session_id = str(uuid.uuid4())
    terminal_sessions[session_id] = {"logs": [], "status": "RUNNING"}
    background_tasks.add_task(scan_website_task, site["url"], session_id, site["name"])
    return {"scan_id": session_id}

@app.post("/scan-website")
def scan_website_manual(payload: dict, background_tasks: BackgroundTasks):
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    session_id = str(uuid.uuid4())
    terminal_sessions[session_id] = {"logs": [], "status": "RUNNING"}
    background_tasks.add_task(scan_website_task, url, session_id, url)
    return {"scan_id": session_id}

@app.post("/executive-scan")
def executive_scan(background_tasks: BackgroundTasks):
    session_id = "executive-" + str(uuid.uuid4())[:8]
    terminal_sessions[session_id] = {"logs": [], "status": "RUNNING"}
    
    # We'll run them in sequence in one background task
    background_tasks.add_task(run_executive_scan_task, session_id)
    return {"scan_id": session_id}

def run_executive_scan_task(session_id: str):
    append_log(session_id, "Initializing Executive Multi-Website Audit...")
    for site in PREDEFINED_WEBSITES:
        append_log(session_id, f"--- Starting audit for {site['name']} ---")
        try:
            scan_website_core(site["url"], session_id, site["name"])
        except Exception as e:
            append_log(session_id, f"[WARNING] Could not connect to {site['name']}: {str(e)}")
    
    append_log(session_id, "Executive Scan Completed.")
    terminal_sessions[session_id]["status"] = "COMPLETED"

def scan_website_task(url: str, session_id: str, app_name: str):
    try:
        scan_website_core(url, session_id, app_name)
        append_log(session_id, "Scan Completed.")
        terminal_sessions[session_id]["status"] = "COMPLETED"
    except Exception as e:
        append_log(session_id, f"[ERROR] Scan failed: {str(e)}")
        terminal_sessions[session_id]["status"] = "COMPLETED"

def scan_website_core(url: str, session_id: str, app_name: str):
    append_log(session_id, f"Connecting to {app_name}...")
    append_log(session_id, "Fetching HTML...")
    db = SessionLocal()
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        append_log(session_id, "Parsing scripts...")
        
        detected_vulns = []
        
        # 1. Scan Inline Scripts
        scripts = soup.find_all('script')
        for i, script in enumerate(scripts):
            content = script.string if script.string else ""
            if not content: continue
            
            lines = content.split('\n')
            for line_num, line in enumerate(lines):
                stripped = line.strip()
                v_type = None
                risk = 0.0
                
                if "eval(" in stripped:
                    v_type = "Unsafe Eval Execution"
                    risk = 10.0
                elif "innerHTML" in stripped and "=" in stripped:
                    v_type = "Potential XSS via innerHTML"
                    risk = 7.0
                elif "document.write(" in stripped:
                    v_type = "Unsafe document.write usage"
                    risk = 6.0
                
                if v_type:
                    append_log(session_id, f"[ERROR] {app_name} | Line {line_num+1} | {v_type}")
                    # Deduplication
                    existing = db.query(Vulnerability).filter(
                        Vulnerability.file_name == app_name,
                        Vulnerability.line_number == line_num + 1,
                        Vulnerability.vulnerability_type == v_type
                    ).first()
                    
                    if not existing:
                        v_id = f"WEB-{random.randint(10000, 99999)}"
                        db_vuln = Vulnerability(
                            id=v_id,
                            file_name=app_name,
                            line_number=line_num + 1,
                            vulnerability_type=v_type,
                            severity="HIGH" if risk > 7 else "MEDIUM",
                            code_snippet=stripped[:200],
                            risk_score=risk,
                            status="DETECTED"
                        )
                        db.add(db_vuln)
                        detected_vulns.append(db_vuln)

        # 2. Scan Forms
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                if inp.get('type') == 'text' or not inp.get('type'):
                    v_type = "Unsanitized Web Form Input"
                    existing = db.query(Vulnerability).filter(
                        Vulnerability.file_name == app_name,
                        Vulnerability.vulnerability_type == v_type,
                        Vulnerability.code_snippet.contains(str(inp)[:50])
                    ).first()
                    
                    if not existing:
                        append_log(session_id, f"[ERROR] {app_name} | Potential unsanitized input {inp.get('name', 'unnamed')}")
                        db_vuln = Vulnerability(
                            id=f"WEB-{random.randint(10000, 99999)}",
                            file_name=app_name,
                            line_number=0,
                            vulnerability_type=v_type,
                            severity="LOW",
                            code_snippet=str(inp)[:200],
                            risk_score=3.0,
                            status="DETECTED"
                        )
                        db.add(db_vuln)
                        detected_vulns.append(db_vuln)

        if not detected_vulns:
            append_log(session_id, "[INFO] No critical pattern found.")

        db.commit()
        db.close()
    except Exception as e:
        db.close()
        raise e

@app.get("/terminal-output")
def get_terminal_output_legacy():
    # Merge all logs for total history or just return default
    all_logs = []
    for s in terminal_sessions.values():
        all_logs.extend(s["logs"])
    return {"logs": all_logs[-50:]}

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
    
    # Count scans
    total_scans = db.query(ScanSession).count()
    
    # Count vulnerabilities by status
    total_vulns = db.query(Vulnerability).count()
    validated = db.query(Vulnerability).filter(Vulnerability.status == "VALIDATED").count()
    patched = db.query(Vulnerability).filter(Vulnerability.status == "PATCHED").count()
    detected = db.query(Vulnerability).filter(Vulnerability.status == "DETECTED").count()
    
    # Calculate accuracy (validated / total patched)
    accuracy = 0
    if (validated + patched) > 0:
        accuracy = (validated / (validated + patched)) * 100
    
    # Get current risk score from latest session
    latest_session = db.query(ScanSession).order_by(ScanSession.created_at.desc()).first()
    current_risk = latest_session.overall_risk_score if latest_session else 0
    
    db.close()
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "patched_count": patched,
        "validated_count": validated,
        "engine_accuracy": round(accuracy, 1),
        "current_risk_score": round(current_risk, 1)
    }

@app.get("/compliance")
def get_compliance():
    db = SessionLocal()
    
    # Get all vulnerabilities
    vulns = db.query(Vulnerability).all()
    
    # Count open vs closed
    open_count = sum(1 for v in vulns if v.status in ["DETECTED", "PATCHED"])
    closed_count = sum(1 for v in vulns if v.status == "VALIDATED")
    
    # Group by vulnerability type
    fix_breakdown_by_type = {}
    for v in vulns:
        if v.status == "VALIDATED":
            vtype = v.vulnerability_type
            fix_breakdown_by_type[vtype] = fix_breakdown_by_type.get(vtype, 0) + 1
    
    # Get fix history (last 10 validated vulnerabilities)
    validated_vulns = db.query(Vulnerability).filter(
        Vulnerability.status == "VALIDATED"
    ).order_by(Vulnerability.created_at.desc()).limit(10).all()
    
    history = []
    for v in validated_vulns:
        history.append({
            "date": v.created_at.strftime("%Y-%m-%d %H:%M") if v.created_at else "Unknown",
            "vulnerability_type": v.vulnerability_type,
            "file_name": v.file_name
        })
    
    db.close()
    return {
        "total_fixed": closed_count,
        "fix_breakdown_by_type": fix_breakdown_by_type,
        "open_count": open_count,
        "closed_count": closed_count,
        "history": history
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
    feedbacks = db.query(Feedback).order_by(Feedback.created_at.desc()).all()
    count = len(feedbacks)
    avg_rating = sum(f.rating for f in feedbacks) / count if count > 0 else 0
    
    comments = []
    for f in feedbacks:
        comments.append({
            "vulnerability_id": f.vulnerability_id,
            "rating": f.rating,
            "comment": f.comment,
            "created_at": f.created_at.strftime("%Y-%m-%d %H:%M") if f.created_at else "Unknown"
        })
    
    db.close()
    return {
        "average_rating": round(avg_rating, 1),
        "total_feedback": count,
        "comments": comments
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
