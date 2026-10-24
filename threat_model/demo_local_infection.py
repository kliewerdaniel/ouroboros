
import subprocess
import time
import requests
import json
import os

def setup_environment():
    print("Starting local simulation (Ollama in Docker)...")
    subprocess.run(["docker-compose", "up", "-d"], check=True)
    
    print("Waiting for Ollama to start...")
    while True:
        try:
            response = requests.get("http://localhost:11434/api/tags")
            if response.status_code == 200:
                print("Ollama is up.")
                break
        except:
            pass
        time.sleep(2)

    print("Pulling model (this may take a minute)...")
    subprocess.run(["docker", "exec", "victim-ollama", "ollama", "pull", "tinyllama"], check=True)
    print("Environment ready.")

def run_parasite():
    print("Launching Attacker Parasite...")
    # Run the parasite against the local container
    process = subprocess.Popen([
        "docker", "exec", "attacker-parasite", 
        "python", "parasite/parasite.py"
    ])
    return process

def cleanup():
    print("Cleaning up simulation...")
    subprocess.run(["docker-compose", "down"], check=True)

if __name__ == "__main__":
    try:
        setup_environment()
        parasite_proc = run_parasite()
        print("Parasite is running. Watch the logs for infection attempts...")
        
        # Let it run for a bit to see if it attempts to call the API
        time.sleep(30)
        
        print("Stopping parasite...")
        parasite_proc.terminate()
        
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        cleanup()
