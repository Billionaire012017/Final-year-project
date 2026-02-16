import requests
import time

API_URL = "http://localhost:8000"

def test_executive_flow():
    print("1. Triggering Executive Scan...")
    res = requests.post(f"{API_URL}/executive-scan")
    if res.status_code != 200:
        print(f"Error: {res.text}")
        return
    
    scan_id = res.json()["scan_id"]
    print(f"Scan ID: {scan_id}")

    print("\n2. Polling Terminal Stream...")
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
            print(f"  {log}")
        
        last_log_count = len(logs)
        
        if status == "COMPLETED":
            completed = True
            print("\nScan Completed on Server.")
            break
        else:
            print(f"... Polling ({status}) ...")

    if not completed:
        print("\nScan timed out or still running.")

    print("\n3. Verifying Results in DB...")
    v_res = requests.get(f"{API_URL}/vulnerabilities")
    vulns = v_res.json()
    print(f"Total vulnerabilities in DB: {len(vulns)}")
    
    # Sample some sites
    sites_found = set(v.get("file_name") for v in vulns)
    print(f"Unique sites with vulns: {sites_found}")

if __name__ == "__main__":
    test_executive_flow()
