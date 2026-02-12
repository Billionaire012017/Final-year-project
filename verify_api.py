import requests
import json
import time

BASE_URL = "http://localhost:8000"

def check(name, success):
    print(f"{'✅' if success else '❌'} {name}")

def verify_all():
    print("--- STARTING SYSTEM VERIFICATION ---")
    try:
        # 1. Scan
        print("\n[1] Executing Scan...")
        res = requests.post(f"{BASE_URL}/scan")
        if res.status_code != 200:
            print(f"SCAN FAILED: {res.status_code} {res.text}")
        data = res.json()
        check("Scan execution", res.status_code == 200 and data['detected'] > 0)
        
        # 2. Get Vulnerabilities
        print("\n[2] Fetching Registry...")
        res = requests.get(f"{BASE_URL}/vulnerabilities")
        if res.status_code != 200:
             print(f"REGISTRY FAILED: {res.status_code} {res.text}")
        vulns = res.json()
        chk = len(vulns) > 0
        check(f"Registry listed {len(vulns)} items", chk)
        if not chk: return
        
        target_id = vulns[0]['id']
        
        # 3. Patch
        print(f"\n[3] Generating Patch for {target_id}...")
        res = requests.post(f"{BASE_URL}/patch/{target_id}")
        p_data = res.json()
        check("Patch generation", p_data['status'] == 'PATCHED')
        
        # 4. Validate
        print(f"\n[4] Validating Fix...")
        res = requests.post(f"{BASE_URL}/validate/{target_id}")
        v_data = res.json()
        check("Validation success", v_data['new_risk_score'] == 0.0)
        
        # 5. Feedback
        print("\n[5] Submitting Feedback...")
        res = requests.post(f"{BASE_URL}/feedback/{target_id}", json={"rating": 5, "comment": "Great fix!"})
        check("Feedback submission", res.status_code == 200)
        
        # 6. Analytics Checks
        print("\n[6] Verifying Analytics Tabs...")
        dash = requests.get(f"{BASE_URL}/dashboard").json()
        check("Dashboard metrics updated", dash['validated'] >= 1)
        
        sys_core = requests.get(f"{BASE_URL}/system-core").json()
        check("System Core accuracy", sys_core['engine_accuracy'] > 0)
        
        comp = requests.get(f"{BASE_URL}/compliance").json()
        check("Compliance ledger", comp['total_fixed'] >= 1)
        
        fb = requests.get(f"{BASE_URL}/feedback").json()
        check("Feedback aggregation", fb['total_feedback'] >= 1)
        
        print("\n--- ALL SYSTEMS OPERATIONAL ---")
        
    except Exception as e:
        print(f"CRITICAL FAILURE: {e}")

if __name__ == "__main__":
    verify_all()
