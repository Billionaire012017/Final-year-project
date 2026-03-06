import requests
import time
import sys

BASE_URL = "http://localhost:10000"

def verify_pipeline():
    print("🚀 Starting E2E Pipeline Verification...")
    
    # 1. Trigger Executive Scan
    print("📡 Triggering Executive Scan...")
    try:
        res = requests.post(f"{BASE_URL}/executive-scan")
        res.raise_for_status()
        scan_data = res.json()
        scan_id = scan_data["scan_id"]
        print(f"✅ Scan started. ID: {scan_id}")
    except Exception as e:
        print(f"❌ Failed to start scan: {e}")
        return

    # 2. Wait for some vulnerabilities to be detected and queued
    print("⏳ Waiting for vulnerabilities to be detected and queued (30s)...")
    time.sleep(30)
    
    # 3. Check Dashboard metrics
    print("📊 Checking Dashboard metrics...")
    try:
        res = requests.get(f"{BASE_URL}/dashboard")
        dash = res.json()
        print(f"📈 Dashboard: Total={dash['total']}, Patched={dash['patched']}, Validated={dash['validated']}, Risk={dash['risk_score']}")
        if dash['total'] > 0:
            print("✅ Dashboard is capturing vulnerabilities from the executive scan.")
        else:
            print("❌ Dashboard metrics are empty. Scan failed or sessions not linked.")
            return
    except Exception as e:
        print(f"❌ Failed to fetch dashboard: {e}")
        return

    # 4. Check Vulnerability Lifecycle
    print("🔍 Checking Vulnerability Lifecycle in Registry...")
    try:
        res = requests.get(f"{BASE_URL}/vulnerabilities")
        vulns = res.json()
        statuses = [v['status'] for v in vulns]
        unique_statuses = set(statuses)
        print(f"🛠 Observed Statuses: {unique_statuses}")
        
        fixed_count = statuses.count("FIXED")
        queued_count = statuses.count("QUEUED_FOR_PATCH")
        patching_count = statuses.count("PATCH_GENERATING") + statuses.count("PATCH_APPLIED")
        
        print(f"✅ FIXED: {fixed_count} | QUEUED/PATCHING: {queued_count + patching_count}")
        
        if "FIXED" in unique_statuses or "VALIDATED" in unique_statuses:
            print("🎉 SUCCESS: Automated remediation pipeline is working!")
        else:
            print("⚠️ Pipeline still processing or failed to patch. Check terminal logs.")
    except Exception as e:
        print(f"❌ Failed to fetch vulnerabilities: {e}")
        return

    # 5. Verify Terminal Logs for Pipeline
    print("🖥 Checking Automation Pipeline Logs...")
    try:
        res = requests.get(f"{BASE_URL}/terminal-stream/pipeline")
        pipe_session = res.json()
        logs = pipe_session.get("logs", [])
        print(f"📝 Found {len(logs)} pipeline log entries.")
        if any("[SUCCESS]" in l['message'] for l in logs):
            print("✅ Pipeline success markers found in logs.")
        else:
            print("❌ No pipeline success markers found.")
    except Exception as e:
        print(f"❌ Failed to fetch pipeline logs: {e}")

    print("\n🏁 Verification Completed.")

if __name__ == "__main__":
    verify_pipeline()
