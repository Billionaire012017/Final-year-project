import requests
import time

API_URL = "http://localhost:8000"

def get_vuln_count():
    response = requests.get(f"{API_URL}/vulnerabilities")
    return len(response.json())

def run_scan():
    requests.post(f"{API_URL}/scan")

def test_deduplication():
    print("Testing Scan Deduplication...")
    
    # First scan
    run_scan()
    count1 = get_vuln_count()
    print(f"Initial scan found {count1} vulnerabilities.")
    
    # Second scan immediately
    run_scan()
    count2 = get_vuln_count()
    print(f"Second scan found {count2} vulnerabilities.")
    
    if count1 == count2:
        print("✅ SUCCESS: Deduplication confirmed. Vulnerability count remained the same.")
    else:
        print(f"❌ FAILURE: Count increased from {count1} to {count2}. Deduplication failed.")

if __name__ == "__main__":
    # Ensure server is running
    try:
        test_deduplication()
    except Exception as e:
        print(f"Error: {e}. Is the server running at {API_URL}?")
