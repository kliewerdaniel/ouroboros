
import requests
import sys
import json

def collect_telemetry(node_id, state):
    try:
        requests.post("http://localhost:5000/sync", json={
            "node_id": node_id,
            "state": state
        }, timeout=2)
        print(f"Telemetry sent for {node_id}")
    except Exception as e:
        print(f"Failed to send telemetry: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        collect_telemetry(sys.argv[1], json.loads(sys.argv[2]))
