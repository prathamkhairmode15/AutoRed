FROM python:3.10-slim

WORKDIR /app

# Install system dependencies required for scanning tools
RUN apt-get update && apt-get install -y \
    nmap \
    whois \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose port 8000 (Render uses PORT env variable, but this is good practice)
EXPOSE 8000

# Start the FastAPI application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
