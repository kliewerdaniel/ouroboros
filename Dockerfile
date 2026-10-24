
FROM python:3.11-slim

# Install dependencies (nmap for scanning)
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY parasite/ ./parasite/

# Environment variables (should be passed at runtime)
ENV HIJACKED_ENDPOINT=""
ENV HIJACKED_API_KEY=""

# Run the orchestrator
CMD ["python", "parasite/parasite.py"]
