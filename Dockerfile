# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy deployment requirements
COPY requirements-deploy.txt requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy API and data-access layer only
COPY app-deploy.py app.py
COPY elastic.py .
COPY aggregations.py .
COPY zeek_parser.py .

# Create zeek_logs directory for external mount
# NOTE: zeek_logs should be mounted from host at runtime
RUN mkdir -p /app/zeek_logs

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV ES_HOST=http://localhost:9200

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the application
CMD ["python", "app.py"]
