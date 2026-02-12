import os
import sys
import datetime
import random
import ast
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

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

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(String, primary_key=True)
    file_name = Column(String)
    line_number = Column(Integer)
    vulnerability_type = Column(String) # eval, exec, sql_injection
    severity = Column(String) # CRITICAL, HIGH, MEDIUM
    code_snippet = Column(Text)
    status = Column(String) # DETECTED, PATCHED, VALIDATED, FIXED
    confidence_score = Column(Float)
    risk_score = Column(Float)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    patch_diff = Column(Text, nullable=True) # Store diff here for simplicity

Base.metadata.create_all(bind=engine)

# --- FASTAPI APP ---
app = FastAPI(title="SecLAB Real-Time Remediation Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- UTILITIES ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def scan_file(filepath):
    vulns = []
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        line_num = i + 1
        content = line.strip()
        
        v_type = None
        severity = "LOW"
        
        if "eval(" in content:
            v_type = "Unsafe Eval"
            severity = "CRITICAL"
        elif "exec(" in content:
            v_type = "Unsafe Exec"
            severity = "CRITICAL"
        elif "SELECT" in content and ("+" in content or "%s" in content):
            v_type = "SQL Injection"
            severity = "HIGH"
            
        if v_type:
            vulns.append({
                "id": f"VULN-{random.randint(1000, 9999)}",
                "file_name": os.path.basename(filepath),
                "line_number": line_num,
                "vulnerability_type": v_type,
                "severity": severity,
                "code_snippet": content,
                "status": "DETECTED",
                "confidence_score": 0.0,
                "risk_score": 10.0 if severity == "CRITICAL" else (8.0 if severity == "HIGH" else 5.0)
            })
    return vulns

# --- ENDPOINTS ---

@app.get("/", response_class=HTMLResponse)
def read_root():
    path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Core System Active</h1>"

@app.post("/scan")
def trigger_scan():
    db = SessionLocal()
    # Clear old scan for this demo
    db.query(Vulnerability).delete()
    
    detected = []
    if os.path.exists(TEST_DATA_DIR):
        for root, dirs, files in os.walk(TEST_DATA_DIR):
            for file in files:
                if file.endswith(".py"):
                    results = scan_file(os.path.join(root, file))
                    for res in results:
                        db_item = Vulnerability(**res)
                        db.add(db_item)
                        detected.append(res)
    
    db.commit()
    db.close()
    return {"status": "Scan Complete", "detected": len(detected)}

@app.get("/vulnerabilities")
def get_vulnerabilities():
    db = SessionLocal()
    vulns = db.query(Vulnerability).all()
    db.close()
    return vulns

@app.post("/patch/{id}")
def generate_patch(id: str):
    db = SessionLocal()
    vuln = db.query(Vulnerability).filter(Vulnerability.id == id).first()
    if not vuln or vuln.status != "DETECTED":
        db.close()
        raise HTTPException(status_code=400, detail="Invalid vulnerability or status")
    
    # Simulate Diff Generation
    original = vuln.code_snippet
    patched_code = original
    if "eval" in original:
        patched_code = original.replace("eval", "ast.literal_eval")
    elif "exec" in original:
        patched_code = "# REPLACED UNSAFE EXEC\n# exec(...)"
    elif "SELECT" in original:
        patched_code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        
    diff = f"--- Original\n+++ Patched\n- {original}\n+ {patched_code}"
    
    vuln.status = "PATCHED"
    vuln.patch_diff = diff
    vuln.confidence_score = round(random.uniform(0.85, 0.99), 2)
    # Risk remains high until validation
    
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
        raise HTTPException(status_code=400, detail="Invalid vulnerability or status")
        
    vuln.status = "VALIDATED"
    vuln.risk_score = max(0.0, vuln.risk_score * 0.1) # Reduce risk by 90%
    
    db.commit()
    db.refresh(vuln)
    db.close()
    return vuln

@app.get("/dashboard")
def get_dashboard():
    db = SessionLocal()
    total = db.query(Vulnerability).count()
    detected = db.query(Vulnerability).filter(Vulnerability.status == "DETECTED").count()
    patched = db.query(Vulnerability).filter(Vulnerability.status == "PATCHED").count()
    validated = db.query(Vulnerability).filter(Vulnerability.status == "VALIDATED").count()
    
    vulns = db.query(Vulnerability).all()
    avg_risk = sum(v.risk_score for v in vulns) / total if total > 0 else 0
    
    db.close()
    return {
        "total_vulnerabilities": total,
        "detected_count": detected,
        "patched_count": patched,
        "validated_count": validated,
        "fixed_count": validated, # Treating Validated as Fixed for this flow
        "overall_risk_score": round(avg_risk, 1)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
