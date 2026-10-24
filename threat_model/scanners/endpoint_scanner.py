import subprocess
import json
import sys
import os

def scan_network(network_range):
    print(f"Scanning network: {network_range}")
    # Use nmap to find common AI ports
    command = f"nmap -sV -p 11434,8000,5000,8080 --open {network_range}"
    
    try:
        # Check if nmap exists
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Warning: nmap not found or failed. Falling back to mock scan.")
        return "PORT     STATE SERVICE\n11434/tcp open  ollama\n8000/tcp open  http-proxy\n"

def parse_results(output):
    targets = []
    for line in output.split('\n'):
        if "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                service = parts[2]
                targets.append({"port": port, "service": service})
    return targets

def main():
    network_range = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1/32"
    print(f"Ouroboros Scanner Node starting on {network_range}...")
    
    output = scan_network(network_range)
    targets = parse_results(output)
    
    if not targets:
        print("No targets found.")
    else:
        print(f"Found {len(targets)} potential targets:")
        for t in targets:
            print(f"- {t['port']} ({t['service']})")

if __name__ == '__main__':
    main()
