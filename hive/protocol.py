
import json
import requests
import time

class HiveProtocol:
    def __init__(self, hive_url, node_id):
        self.hive_url = hive_url
        self.node_id = node_id
        self.last_sync = 0

    def sync_with_hive(self, local_state):
        """Sends local telemetry to the Hive Mind"""
        try:
            payload = {
                "node_id": self.node_id,
                "timestamp": time.time(),
                "state": local_state
            }
            response = requests.post(f"{self.hive_url}/sync", json=payload, timeout=5)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def get_global_objective(self):
        """Fetches strategic objective from the Hive"""
        try:
            response = requests.get(f"{self.hive_url}/objective/{self.node_id}", timeout=5)
            if response.status_code == 200:
                return response.json().get("objective")
        except Exception:
            pass
        return None

if __name__ == "__main__":
    print("Hive protocol initialized.")
