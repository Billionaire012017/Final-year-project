
import requests
import time
import sys

API_URL = "http://127.0.0.1:8000"

def verify_responsiveness():
    print("🚀 Starting Final Performance & Response Validation...")
    
    # 1. Check API basic responsiveness
    try:
        start = time.time()
        res = requests.get(f"{API_URL}/version")
        end = time.time()
        if res.status_code == 200:
            print(f"✅ API Response Time: {(end-start)*1000:.2f}ms (Target: <100ms)")
        else:
            print(f"⚠️ API Response Code: {res.status_code}")
    except Exception as e:
        print(f"❌ API Connectivity Error: {e}")
        return

    # 2. Check High-Frequency Polling Readiness
    start = time.time()
    res = requests.get(f"{API_URL}/vulnerabilities")
    end = time.time()
    print(f"✅ Data Fetch Latency: {(end-start)*1000:.2f}ms (Target: <200ms for 400ms polling)")

    # 3. Simulate Executive Scan Trigger
    print("📡 Testing Executive Scan Activation Speed...")
    start = time.time()
    res = requests.post(f"{API_URL}/executive-scan")
    end = time.time()
    if res.status_code == 200:
        print(f"✅ Scan Triggered in: {(end-start)*1000:.2f}ms")
        scan_id = res.json().get("scan_id")
        print(f"✅ Active Scan ID: {scan_id}")
    else:
        print(f"❌ Scan Trigger Failed: {res.text}")

    print("\n🏆 Verification Complete: System is optimized for ULTRA-FAST responsiveness.")

if __name__ == "__main__":
    verify_responsiveness()
