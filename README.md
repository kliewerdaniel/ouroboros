# Operation Ouroboros: Recursive Intelligence Parasite

## Architectural Overview

The Ouroboros agent is designed as a multi-layered recursive system. 

### 1. The Parasite (Orchestrator)
A lightweight Python process (`parasite.py`) that manages the autonomy loop. It is responsible for:
*   Maintaining the state of the attack (up to 100,000 steps).
*   Communicating with the hijacked model via a proxy API.
*   Executing shell commands and piping results back to the model.

### 2. The Hijacked Brain (Local Reasoning)
The agent uses an exposed LLM endpoint as its reasoning engine. It is initialized with a high-agency system prompt that mandates JSON output for machine-readability.

### 3. The Hive Mind (Global Coordination)
A secondary, more intelligent LLM (or a dedicated coordination endpoint) that receives summarized telemetry from all active parasitic nodes and issues strategic objectives.

---

## Repository Structure

- `parasite/`: Core orchestrator code.
- `payloads/`: A library of model-specific injection and shell payloads.
- `scanners/`: Port and endpoint discovery scripts.
- `hive/`: Coordination and strategic planning logic (simulated/local).
- `docs/`: Threat models and operational specs.

## Key Technologies
- **Python**: For the orchestration loop and tool execution.
- **Docker**: To containerize the parasite for easy deployment and footprint reduction.
- **Vector DB (Chroma/Qdrant)**: For the parasite to maintain local "memory" of its findings and targets.
- **MCP (Model Context Protocol)**: For defining the tools the hijacked model can use.
