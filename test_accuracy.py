import os
import sys
import uuid
import datetime
from sqlalchemy.orm import Session
from server import SessionLocal, Vulnerability, ScanSession, scan_file_content, run_patch_pipeline

def run_accuracy_test():
    print("[INIT] STARTING PIPELINE ACCURACY VERIFICATION (Target: 97%)")
    db = SessionLocal()
    
    # 1. Create a Scan Session
    session = ScanSession(total_files_scanned=4, total_vulnerabilities=0, overall_risk_score=0)
    db.add(session)
    db.commit()
    db.refresh(session)
    
    # 2. Define Test Samples
    samples = [
        ("EVAL_INJECTION", "x = eval(user_input)", "ast.literal_eval"),
        ("EXEC_INJECTION", "exec(cmd_data)", "Restricted execution"),
        ("SQL_INJECTION", "query = 'SELECT * FROM users WHERE id = ' + uid", "parameterized"),
        ("DOM_XSS", "element.innerHTML = html_content", "textContent")
    ]
    
    total = len(samples)
    detected = 0
    fixed = 0
    
    vuln_ids = []
    
    print("\n[PHASE 1: DETECTION]")
    for i, (v_type, code, expected_keyword) in enumerate(samples):
        print(f"Testing sample {i+1}: {code}")
        found = scan_file_content(code, f"test_{i}.py")
        if found and found[0]["vulnerability_type"] == v_type:
            print(f"  [PASS] Detected {v_type}")
            detected += 1
            v = found[0]
            v_id = f"TEST-ACC-{i}-{uuid.uuid4().hex[:6]}"
            db_v = Vulnerability(
                id=v_id,
                scan_session_id=session.id,
                file_name=v["file_name"],
                line_number=v["line_number"],
                vulnerability_type=v["vulnerability_type"],
                severity=v["severity"],
                code_snippet=v["code_snippet"],
                risk_score=v["risk_score"],
                target_url="TEST_ACCURACY",
                suggested_fix=v["suggested_fix"],
                diff=v["diff"],
                status="DETECTED"
            )
            db.add(db_v)
            vuln_ids.append(v_id)
        else:
            print(f"  [FAIL] FAILED to detect {v_type}")
            
    db.commit()
    
    print("\n[PHASE 2: REMEDIATION & VALIDATION]")
    for v_id in vuln_ids:
        # Run the patch pipeline logic (simulate the thread)
        job = {"vuln_id": v_id, "status": "QUEUED"}
        print(f"Processing {v_id}...")
        run_patch_pipeline(job)
        
        # Check result
        db.expire_all()
        v = db.query(Vulnerability).filter(Vulnerability.id == v_id).first()
        if v.status == "FIXED":
            print(f"  [PASS] FIXED: {v.vulnerability_type}")
            fixed += 1
        else:
            print(f"  [FAIL] FAILED: {v.vulnerability_type} (Status: {v.status})")
            
    accuracy = (fixed / total) * 100
    print(f"\n[RESULT] FINAL RESULT: {fixed}/{total} patches successful.")
    print(f"ACCURACY RATE: {accuracy:.2f}%")
    
    if accuracy >= 97:
        print("[SUCCESS] Pipeline meets accuracy requirements!")
    else:
        print("[WARNING] Accuracy below target 97%.")

if __name__ == "__main__":
    run_accuracy_test()