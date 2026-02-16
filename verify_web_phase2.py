import requests
import time

API_URL = "http://localhost:8000"

def test_workflow():
    print("1. Fetching Available Websites...")
    res = requests.get(f"{API_URL}/available-websites")
    print(f"Status: {res.status_code}")
    websites = res.json().get("websites", [])
    print(f"Found {len(websites)} websites.")
    
    if not websites:
        print("Error: No websites found.")
        return

    target = websites[2] # acunetix_testphp
    print(f"\n2. Scanning Predefined Website: {target['name']} ({target['id']})")
    scan_res = requests.post(f"{API_URL}/scan-website/{target['id']}")
    print(f"Status: {scan_res.status_code}")
    data = scan_res.json()
    print(f"Summary: {data.get('scan_summary')}")
    print(f"Vulnerabilities found: {len(data.get('vulnerabilities', []))}")

    print("\n3. Checking Terminal Stream...")
    log_res = requests.get(f"{API_URL}/terminal-stream")
    logs = log_res.json().get("logs", [])
    print(f"Recent logs ({len(logs)} total):")
    for log in logs[-5:]:
        print(f"  {log}")

if __name__ == "__main__":
    test_workflow()
