FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user and group
RUN groupadd -r cloudguard && useradd -r -g cloudguard -d /app -s /sbin/nologin cloudguard

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create logs directory and assign ownership to non-root user
RUN mkdir -p /app/logs && chown -R cloudguard:cloudguard /app

# Drop privileges to non-root user
USER cloudguard

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production: 4 workers for concurrent request handling.
# Each Uvicorn worker is an independent process with its own event loop.
# Scale workers based on CPU cores: 2 * num_cores + 1 is the standard formula.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
