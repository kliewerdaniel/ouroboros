
from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# In-memory state of the hive
hive_state = {
    "nodes": {},
    "global_objective": "Reconnaissance: Find all exposed Ollama instances on 192.168.1.0/24"
}

@app.route('/sync', methods=['POST'])
def sync():
    data = request.json
    node_id = data.get("node_id")
    hive_state["nodes"][node_id] = {
        "state": data.get("state"),
        "last_seen": time.time()
    }
    return jsonify({"status": "ok", "current_objective": hive_state["global_objective"]})

@app.route('/objective/<node_id>', methods=['GET'])
def get_objective(node_id):
    return jsonify({"objective": hive_state["global_objective"]})

if __name__ == "__main__":
    print("Hive Mind Server running on port 5000...")
    app.run(port=5000)
