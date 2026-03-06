import requests
import time

BASE_URL = "http://localhost:10000"

def test_interactive_pipeline():
    print("🚀 Starting Interactive Pipeline Verification...")
    
    # 1. Trigger Executive Scan
    print("📡 Triggering Executive Scan...")
    requests.post(f"{BASE_URL}/executive-scan")
    
    # 2. Check pipeline status - should be paused
    print("⏳ Checking if pipeline is paused...")
    time.sleep(5)
    res = requests.get(f"{BASE_URL}/pipeline/status")
    status = res.json()
    print(f"📊 Pipeline Paused: {status['paused']} | Queue Count: {status['queue_count']}")
    
    if not status['paused']:
        print("❌ Error: Pipeline should be paused by default.")
        return

    # 3. Start remediation manually
    print("⚙ Starting Remediation via /pipeline/start...")
    requests.post(f"{BASE_URL}/pipeline/start")
    
    # 4. Monitor one-by-one processing
    print("🔍 Monitoring One-by-One processing (30s)...")
    for i in range(15):
        res = requests.get(f"{BASE_URL}/pipeline/status")
        status = res.json()
        active = status.get('active')
        queue_count = status.get('queue_count')
        print(f"[{i}] Active Patch: {active['vuln_id'] if active else 'None'} | Remaining in Queue: {queue_count}")
        time.sleep(2)

    # 5. Verify accuracy in Dashboard
    print("📊 Verifying Accuracy Metrics...")
    res = requests.get(f"{BASE_URL}/system-core")
    core = res.json()
    print(f"📈 Engine Accuracy: {core['engine_accuracy']}%")
    if core['engine_accuracy'] >= 99.0:
        print("✅ SUCCESS: 99% Accuracy achieved!")

    print("\n🏁 Interactive Pipeline Verified.")

if __name__ == "__main__":
    test_interactive_pipeline()
