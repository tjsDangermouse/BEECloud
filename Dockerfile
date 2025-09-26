# MELCloud Integration - Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /build

# Install system dependencies needed for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    FLASK_ENV=production

# Create non-root user
RUN groupadd -r melcloud && useradd -r -g melcloud melcloud

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Create directories with proper ownership
RUN mkdir -p /app/instance && \
    chown -R melcloud:melcloud /app

# Copy application files
COPY --chown=melcloud:melcloud app.py database.py melcloud_api.py auth.py schedule_engine.py ./
COPY --chown=melcloud:melcloud monitor_health.py ./
COPY --chown=melcloud:melcloud src/ ./src/
COPY --chown=melcloud:melcloud templates/ ./templates/
COPY --chown=melcloud:melcloud static/ ./static/
COPY --chown=melcloud:melcloud README.md CLAUDE.md ./

# Create Docker-specific configuration
COPY --chown=melcloud:melcloud <<EOF /app/docker_config.json
{
  "database": {
    "path": "instance/melcloud.db",
    "backup_enabled": true,
    "auto_recovery": true
  },
  "api": {
    "rate_limit_seconds": 60,
    "max_consecutive_errors": 3
  },
  "monitoring": {
    "health_check_enabled": true,
    "disk_space_threshold_mb": 100,
    "log_retention_days": 7
  },
  "server": {
    "host": "0.0.0.0",
    "port": 8000,
    "debug": false
  }
}
EOF

# Create startup script
COPY --chown=melcloud:melcloud <<'EOF' /app/docker-entrypoint.sh
#!/bin/bash
set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting MELCloud Integration Docker Container"

# Ensure directories exist
mkdir -p /app/instance

# Copy docker config to production config if it doesn't exist
if [ ! -f /app/production_config.json ]; then
    log "Creating production_config.json from Docker defaults"
    cp /app/docker_config.json /app/production_config.json
fi

# Check if database needs initialization
if [ ! -f /app/instance/melcloud.db ]; then
    log "Database not found, will be created on first run"
else
    log "Existing database found at /app/instance/melcloud.db"
fi

# Environment variable overrides
if [ -n "$MELCLOUD_PORT" ]; then
    log "Using port from environment: $MELCLOUD_PORT"
    export MELCLOUD_PORT
fi

# Note: Auto-fetch interval is now configured through the web UI settings

# Health check for readiness
log "Starting health monitoring in background"
(
    sleep 30  # Wait for app to start
    while true; do
        if curl -f http://localhost:8000/api/health >/dev/null 2>&1; then
            log "Health check passed"
        else
            log "Health check failed"
        fi
        sleep 60
    done
) &

# Start application (already running as melcloud user)
log "Starting MELCloud Integration"
python app.py "$@"
EOF

# Runtime setup complete

# Make startup script executable
RUN chmod +x /app/docker-entrypoint.sh

# Switch to non-root user
USER melcloud

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Add labels for metadata
LABEL org.opencontainers.image.title="MELCloud Integration" \
      org.opencontainers.image.description="MELCloud heat pump monitoring and data collection service" \
      org.opencontainers.image.vendor="MELCloud Integration Project" \
      org.opencontainers.image.source="https://github.com/simonwoollams/MELCloud_Integration" \
      org.opencontainers.image.documentation="https://github.com/simonwoollams/MELCloud_Integration/blob/main/README.md"

# Set entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD []
