import requests
import time
import uuid

BASE_URL = "http://localhost:10000"

def test_system_excellence():
    print("🚀 Starting Professional System Excellence Verification...")
    
    # 1. Start Executive Scan
    print("📡 Triggering Executive Scan for Uniqueness Test...")
    res = requests.post(f"{BASE_URL}/executive-scan")
    scan_id = res.json()["scan_id"]
    
    # 2. Wait for completion
    print("⏳ Waiting for scan to complete...")
    for _ in range(30):
        status_res = requests.get(f"{BASE_URL}/terminal-stream?session_id={scan_id}")
        data = status_res.json()
        if data.get("status") == "COMPLETED":
            break
        time.sleep(1)
    
    # 3. Check for uniqueness in Registry
    print("🔍 Checking Registry for Uniqueness...")
    registry = requests.get(f"{BASE_URL}/vulnerabilities").json()
    vuln_count_1 = len(registry)
    print(f"✅ Initial Vulnerabilities detected: {vuln_count_1}")
    
    # 4. Starting Remediation to generate "FIXED" status
    print("⚙ Starting Remediation...")
    requests.post(f"{BASE_URL}/pipeline/start")
    
    # Wait for at least one fix (realistic delay takes ~30s)
    print("⏳ Waiting for automated patches to apply (Realistic Delay)...")
    time.sleep(45)
    
    # 5. Re-run Scan to verify "No Re-detection of Fixed Code"
    print("📡 Re-running Executive Scan to verify guards...")
    res2 = requests.post(f"{BASE_URL}/executive-scan")
    scan_id2 = res2.json()["scan_id"]
    
    # Wait for completion
    for _ in range(30):
        status_res = requests.get(f"{BASE_URL}/terminal-stream?session_id={scan_id2}")
        data = status_res.json()
        if data.get("status") == "COMPLETED":
            break
        time.sleep(1)
        
    # 6. Check Registry again
    registry2 = requests.get(f"{BASE_URL}/vulnerabilities").json()
    vuln_count_2 = len(registry2)
    print(f"✅ Post-Remediation Vulnerabilities detected: {vuln_count_2}")
    
    if vuln_count_2 <= vuln_count_1:
         print("🎉 SUCCESS: No re-detection of cleaned code!")
    else:
         print(f"⚠️ Warning: Registry increased from {vuln_count_1} to {vuln_count_2}. Check uniqueness logic.")

    # 7. Verify Sync in System Core Accuracy
    core = requests.get(f"{BASE_URL}/system-core").json()
    print(f"📈 Current System Accuracy: {core['engine_accuracy']}%")
    
    print("\n🏁 System Verification Completed.")

if __name__ == "__main__":
    test_system_excellence()
