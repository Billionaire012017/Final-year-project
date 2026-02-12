import requests
import json

print("Testing /scan endpoint...")
try:
    response = requests.post("http://localhost:8000/scan")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
    print(f"Response text: {response.text if 'response' in locals() else 'No response'}")
