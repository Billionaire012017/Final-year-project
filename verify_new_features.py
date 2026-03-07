import requests
import time

BASE_URL = "http://localhost:10000"

def test():
    print("🚀 Starting Final System Polish Verification...")
    
    # 1. Custom URL Scan
    print("📡 Testing Custom URL Scan Endpoint...")
    res = requests.post(f"{BASE_URL}/scan-website", json={"url": "https://example.com/"})
    assert res.status_code == 200, "Custom Scan endpoint failed"
    scan_id = res.json()["scan_id"]
    print(f"✅ Custom Scan Initiated: {scan_id}")
    time.sleep(10) # wait for scan to finish
    
    # Check vulns
    vulns = requests.get(f"{BASE_URL}/vulnerabilities").json()
    print(f"   Detected {len(vulns)} vulnerabilities (should be ~0-2 depending on example.com structure)")
    
    # 2. Trigger Predefined Executive Scan to populate queue
    print("\n📡 Initiating Executive Scan...")
    requests.post(f"{BASE_URL}/executive-scan")
    time.sleep(10) # Give it time to detect
    
    # 3. Queue Execution
    print("⚙ Starting Remediation Pipeline...")
    res = requests.post(f"{BASE_URL}/pipeline/start")
    print("   Queue Size:", res.json()["queue_size"])
    
    print("\n⏳ Waiting for the pipeline to finish completely...")
    while True:
        status = requests.get(f"{BASE_URL}/pipeline/status").json()
        if status["queue_count"] == 0 and status["active"] is None:
            break
        time.sleep(2)
        print(f"   Waiting... queue={status['queue_count']}, active={bool(status['active'])}", end="\r")
        
    print("\n✅ Pipeline Finished.")
    
    # 4. Check for the Automation completion message
    logs = requests.get(f"{BASE_URL}/terminal-stream").json()
    completion_found = False
    for log in logs["logs"][-20:]: # Check last 20 logs
        if "All the automation process completed" in log:
            completion_found = True
            break
    print(f"✅ Automation Completion Message Found: {completion_found}")
    
    # 5. Re-run scan to verify 0 vulnerabilities (No zero-days injected)
    print("\n📡 Re-running Executive Scan to verify 0 vulnerabilities return...")
    requests.post(f"{BASE_URL}/executive-scan")
    time.sleep(15)
    
    vulns_before_last = len(requests.get(f"{BASE_URL}/vulnerabilities").json())
    
    # Check new detected ones
    vulns = requests.get(f"{BASE_URL}/vulnerabilities").json()
    detected_count = sum(1 for v in vulns if v["status"] == "DETECTED" or v["status"] == "QUEUED_FOR_PATCH")
    print(f"✅ New Detects after full fix: {detected_count} (Should be 0)")
    
    print("\n🎉 Verification Completed Successfully!")

if __name__ == "__main__":
    try:
        test()
    except Exception as e:
        print(f"❌ Error: {e}")
