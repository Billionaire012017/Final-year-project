import requests
import time
import sys

BASE_URL = "http://localhost:8000"

def log(msg, success=True):
    icon = "✅" if success else "❌"
    print(f"{icon} {msg}")

def check_backend():
    try:
        # 1. Check Root
        res = requests.get(BASE_URL)
        if res.status_code == 200 and "SecLAB" in res.text:
            log("Root HTML served successfully")
        else:
            log(f"Root check failed: {res.status_code}", False)
            return

        # 2. Trigger Scan
        res = requests.post(f"{BASE_URL}/scan")
        data = res.json()
        if res.status_code == 200 and data['detected'] > 0:
            log(f"Scan successful. Detected {data['detected']} vulnerabilities")
        else:
            log(f"Scan failed: {res.text}", False)
            return

        # 3. Get Vulnerabilities
        res = requests.get(f"{BASE_URL}/vulnerabilities")
        vulns = res.json()
        if len(vulns) > 0:
            log(f"Retrieved {len(vulns)} vulnerabilities")
            target = vulns[0]['id']
        else:
            log("No vulnerabilities found to patch", False)
            return

        # 4. Generate Patch
        res = requests.post(f"{BASE_URL}/patch/{target}")
        patch = res.json()
        if patch['status'] == 'PATCHED':
            log(f"Patch generated for {target}")
        else:
            log(f"Patch generation failed: {res.text}", False)
            return

        # 5. Validate Patch
        res = requests.post(f"{BASE_URL}/validate/{target}")
        validated = res.json()
        if validated['status'] == 'VALIDATED':
            log(f"Patch validated for {target}")
        else:
            log(f"Validation failed: {res.text}", False)
            return

        # 6. Check Dashboard
        res = requests.get(f"{BASE_URL}/dashboard")
        dash = res.json()
        if dash['validated_count'] >= 1:
            log("Dashboard metrics updated correctly")
        else:
            log("Dashboard metrics mismatch", False)

        print("\nAll Systems Operational.")

    except Exception as e:
        log(f"Verification crashed: {e}", False)

if __name__ == "__main__":
    check_backend()
