import requests
import time

API_URL = "http://localhost:8000"

def test_refined_flow():
    print("1. Triggering Executive Scan...")
    res = requests.post(f"{API_URL}/executive-scan")
    if res.status_code != 200:
        print(f"Error: {res.text}")
        return
    
    scan_id = res.json()["scan_id"]
    print(f"Scan ID: {scan_id}")

    print("\n2. Polling Structured Terminal Stream...")
    completed = False
    last_log_count = 0
    
    # Poll for 30 seconds max
    for i in range(15):
        time.sleep(2)
        stream_res = requests.get(f"{API_URL}/terminal-stream?session_id={scan_id}")
        data = stream_res.json()
        logs = data.get("logs", [])
        status = data.get("status")
        
        new_logs = logs[last_log_count:]
        for log in new_logs:
            # Verify structured object
            if isinstance(log, dict) and "level" in log and "message" in log:
                print(f"  [{log['level']}] {log['message']}")
            else:
                print(f"  [MALFORMED] {log}")
        
        last_log_count = len(logs)
        
        if status == "COMPLETED":
            completed = True
            print("\nScan Completed on Server.")
            break

    print("\n3. Verifying DB Filter (Pattern-only)...")
    v_res = requests.get(f"{API_URL}/vulnerabilities")
    vulns = v_res.json()
    
    allowed_types = ["EVAL_INJECTION", "EXEC_INJECTION", "SQL_INJECTION", "DOM_XSS"]
    for v in vulns:
        if v["vulnerability_type"] not in allowed_types:
            print(f"  [FAIL] Unexpected vuln type found: {v['vulnerability_type']}")
        else:
            print(f"  [PASS] Found valid vuln: {v['vulnerability_type']} at {v['file_name']}")

    print(f"\nTotal valid vulnerabilities in DB: {len(vulns)}")

if __name__ == "__main__":
    test_refined_flow()
