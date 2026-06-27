import requests
import json
import time

print("Waiting for backend worker to boot...")
time.sleep(3)

print("Querying /model/status...")
try:
    res = requests.get("http://localhost:8000/model/status")
    print(f"Status Code: {res.status_code}")
    if res.ok:
        print("Success! Response:")
        print(json.dumps(res.json(), indent=2))
    else:
        print(f"Error response: {res.text}")
except Exception as e:
    print(f"Failed to query backend: {e}")
