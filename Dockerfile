# Use Python 3.12 slim image (theHarvester requires Python 3.12+)
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    perl \
    iputils-ping \
    libnet-ssleay-perl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install theHarvester globally from git repository
RUN git clone https://github.com/laramies/theHarvester.git /opt/theHarvester && \
    cd /opt/theHarvester && \
    python3 -m pip install .

# Copy the entire project
COPY . .

# Google Cloud Run dictates the port through the PORT env var (default 8000)
EXPOSE 8000

# Run the application bound to the dynamic Cloud Run port
CMD uvicorn login_app.app:app --host 0.0.0.0 --port ${PORT:-8000}