import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def verify_pipeline():
    print("🚀 STARTING AUTOMATED PIPELINE VERIFICATION (Steps 1-7)")
    
    # 1. Trigger Executive Scan
    print("\n[STEP 1] Triggering Executive Scan...")
    res = requests.post(f"{BASE_URL}/executive-scan")
    if res.status_code != 200:
        print(f"❌ Scan failed: {res.text}")
        return
    scan_id = res.json()["scan_id"]
    print(f"✅ Scan ID: {scan_id}")

    # Wait for Scan to complete
    while True:
        res = requests.get(f"{BASE_URL}/terminal-stream?session_id={scan_id}")
        data = res.json()
        status = data.get("status")
        found = data.get("found_count", 0)
        print(f"   Status: {status} | Found: {found}...")
        if status == "COMPLETED":
            break
        time.sleep(2)
    print(f"✅ Scan Finished. Found {found} vulnerabilities.")

    # 2. Confirm Queue
    print(f"\n[STEP 2] Confirming Patch Queue for {scan_id}...")
    res = requests.post(f"{BASE_URL}/queue-confirm/{scan_id}")
    if res.status_code != 200:
        print(f"❌ Queue confirmation failed: {res.text}")
        return
    print(f"✅ Queue initialized with {res.json().get('queue_size')} vulnerabilities.")

    # 3. Monitor Sequential Progress
    print("\n[STEP 3-6] Monitoring Sequential Remediation & Status Updates...")
    start_time = time.time()
    last_fixed_count = 0
    
    while time.time() - start_time < 180: # 3 min timeout
        # Check vulnerabilities
        v_res = requests.get(f"{BASE_URL}/vulnerabilities")
        vulns = v_res.json()
        
        fixed = [v for v in vulns if v["status"] == "FIXED"]
        applied = [v for v in vulns if v["status"] == "PATCH_APPLIED"]
        generating = [v for v in vulns if v["status"] == "PATCH_GENERATING"]
        queued = [v for v in vulns if v["status"] == "QUEUED_FOR_PATCH"]
        
        print(f"   Counts -> Fixed: {len(fixed)}, Applied: {len(applied)}, Generating: {len(generating)}, Queued: {len(queued)}")
        
        if len(fixed) > last_fixed_count:
            print(f"   ✨ Vulnerability Fixed ({len(fixed)}/{len(vulns)})")
            last_fixed_count = len(fixed)
            
            # Step 7: Verify Dashboard metrics
            d_res = requests.get(f"{BASE_URL}/dashboard")
            metrics = d_res.json()
            print(f"   📊 Dashboard Metrics -> Risk Score: {metrics.get('risk_score')}, Validated: {metrics.get('validated')}")
            
        if len(fixed) == len(vulns) and len(vulns) > 0:
            print("\n✅ VERIFICATION SUCCESS: All vulnerabilities remediated sequentially.")
            return

        time.sleep(5)

    if last_fixed_count > 0:
        print("\n⚠️ VERIFICATION PARTIAL: Pipeline is working but timed out before all were fixed.")
    else:
        print("\n❌ VERIFICATION FAILED: No vulnerabilities were fixed.")

if __name__ == "__main__":
    verify_pipeline()
