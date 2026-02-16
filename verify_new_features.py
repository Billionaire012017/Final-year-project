import requests
import json

API_URL = "http://localhost:8000"

def test_website_scan():
    print("Testing Website Scan...")
    # Using a known public URL that likely has script tags (example.com is too simple, maybe a local mockup or just test the endpoint)
    # I'll use example.com just to check connectivity and basic parsing
    payload = {"url": "https://example.com"}
    response = requests.post(f"{API_URL}/scan-website", json=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        vulns = response.json()
        print(f"Found {len(vulns)} vulnerabilities.")
        for v in vulns:
            print(f" - {v['vulnerability_type']} at {v['file_name']}")
    else:
        print(f"Error: {response.text}")

def test_terminal_output():
    print("Testing Terminal Output...")
    response = requests.get(f"{API_URL}/terminal-output")
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        logs = response.json().get("logs", [])
        print(f"Total log entries: {len(logs)}")
        for log in logs[-3:]:
            print(f" Log: {log}")
    else:
        print(f"Error: {response.text}")

if __name__ == "__main__":
    test_website_scan()
    test_terminal_output()
