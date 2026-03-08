import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_pipeline():
    print("🚀 STARTING FULL PIPELINE AUTOMATION TEST")
    
    # 1. Trigger Executive Scan
    print("\n[PHASE 1] Triggering Executive Scan...")
    res = requests.post(f"{BASE_URL}/executive-scan")
    if res.status_code != 200:
        print(f"❌ Scan failed: {res.text}")
        return
    scan_id = res.json()["scan_id"]
    print(f"✅ Scan ID: {scan_id}")

    # Wait for Scan to complete
    while True:
        res = requests.get(f"{BASE_URL}/terminal-stream?session_id={scan_id}")
        status = res.json().get("status")
        print(f"   Scan Status: {status}...")
        if status == "COMPLETED":
            found_count = res.json().get("found_count", 0)
            print(f"✅ Scan Finished. Found {found_count} vulnerabilities.")
            break
        time.sleep(2)

    # 2. Trigger Queue All (Ingestion)
    print("\n[PHASE 2] Triggering Registry Ingestion (Queue All)...")
    res = requests.post(f"{BASE_URL}/pipeline/queue-all")
    if res.status_code != 200:
        print(f"❌ Queuing failed: {res.text}")
        return
    print("✅ Ingestion Protocol Initialized.")

    # Monitor Ingestion Logic
    while True:
        res = requests.get(f"{BASE_URL}/terminal-stream?session_id=pipeline")
        logs = res.json().get("logs", [])
        if any("QUEUING_COMPLETE" in log["message"] for log in logs):
            print("✅ Registry Ingestion Complete.")
            break
        print("   Ingestion in progress...")
        time.sleep(2)

    # 3. Start Remediation
    print("\n[PHASE 3] Starting Automated Remediation Kernel...")
    res = requests.post(f"{BASE_URL}/pipeline/start")
    if res.status_code != 200:
        print(f"❌ Pipeline start failed: {res.text}")
        return
    print("✅ Remediation Phase Active.")

    # Monitor Remediation (Check for FIXED status)
    print("\n[PHASE 4] Monitoring Patching Cadence (20-30s per vuln)...")
    start_time = time.time()
    while time.time() - start_time < 120:  # Monitor for 2 minutes
        res = requests.get(f"{BASE_URL}/vulnerabilities")
        vulns = res.json()
        fixed = [v for v in vulns if v["status"] == "FIXED"]
        patching = [v for v in vulns if "PATCH" in v["status"]]
        
        print(f"   Status: {len(fixed)} Fixed, {len(patching)} Active Patching...")
        if len(fixed) > 0:
            print("✅ TEST SUCCESS: Vulnerabilities are being remediated automatically.")
            return
        time.sleep(5)

    print("❌ TEST TIMEOUT: No vulnerabilities were fixed within 2 minutes.")

if __name__ == "__main__":
    test_pipeline()
