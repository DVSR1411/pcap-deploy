FROM python:3.14-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Apply latest Debian security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Upgrade Python packaging tools
RUN pip install --no-cache-dir --upgrade \
    pip \
    setuptools \
    wheel \
    jaraco.context

# Copy dependency file first
COPY requirements-deploy.txt requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app_deploy.py app.py
COPY elastic.py .
COPY aggregations.py .
COPY helpers.py .
COPY report_pdf.py .

# Create non-root user
RUN useradd -m appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 5000

# Runtime environment variables
ENV FLASK_APP=app.py \
    FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    ES_HOST=http://192.168.10.200:9200

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:5000/api/health || exit 1

# Start application
CMD ["python", "app.py"]