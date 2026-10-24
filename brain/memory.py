
import json
import os

class BrainMemory:
    def __init__(self, path="brain/memory.json"):
        self.path = path
        if not os.path.exists(self.path):
            self.save({})

    def save(self, data):
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=4)

    def load(self):
        with open(self.path, 'r') as f:
            return json.load(f)

    def update(self, key, value):
        data = self.load()
        data[key] = value
        self.save(data)
