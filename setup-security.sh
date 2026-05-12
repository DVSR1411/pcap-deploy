#!/bin/bash
echo "========================================"
echo "Elasticsearch 8.13.0 Security Setup"
echo "========================================"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found!"
    echo "Please create .env from .env.example first:"
    echo "cp .env.example .env"
    exit 1
fi

# Load ELASTIC_PASSWORD from .env
source .env

echo "Step 1: Starting Elasticsearch only..."
podman-compose up -d elasticsearch

echo "Step 2: Waiting for Elasticsearch to be ready..."
sleep 30

echo "Step 3: Initializing security index..."
podman exec elasticsearch curl -s -u elastic:${ELASTIC_PASSWORD} -X POST "http://localhost:9200/_security/user/temp_init_user" -H "Content-Type: application/json" -d '{"password":"temp123","roles":["superuser"]}' >/dev/null 2>&1
echo "Security index initialized."

echo "Step 4: Deleting old token (if exists)..."
podman exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-service-tokens delete elastic/kibana kibana-token 2>/dev/null || true

echo ""
echo "Step 5: Creating new Kibana service account token..."
TOKEN_OUTPUT=$(podman exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-service-tokens create elastic/kibana kibana-token)

echo "$TOKEN_OUTPUT"

# Extract token (everything after "= ")
KIBANA_TOKEN=$(echo "$TOKEN_OUTPUT" | grep -oP 'SERVICE_TOKEN.*=\s*\K.*' | tr -d '\n\r')

if [ -z "$KIBANA_TOKEN" ]; then
    echo ""
    echo "Error: Failed to extract token!"
    echo "Please add it manually to .env file"
    exit 1
fi

echo ""
echo "Step 6: Adding token to .env file..."

# Check if KIBANA_TOKEN already exists in .env
if grep -q "^KIBANA_TOKEN=" .env; then
    # Replace existing token
    sed -i "s|^KIBANA_TOKEN=.*|KIBANA_TOKEN=$KIBANA_TOKEN|" .env
    echo "✓ Updated KIBANA_TOKEN in .env"
else
    # Add new token
    echo "KIBANA_TOKEN=$KIBANA_TOKEN" >> .env
    echo "✓ Added KIBANA_TOKEN to .env"
fi

echo ""
echo "Step 7: Starting Kibana with new token..."
podman-compose up -d --no-recreate kibana

echo ""
echo "Step 8: Building pcap-api image..."
podman-compose up -d --no-recreate pcap-api

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Elasticsearch: http://localhost:9200"
echo "Kibana: http://localhost:5601"
echo "API: http://localhost:5000"
echo ""
echo "Login with:"
echo "Username: elastic"
echo "Password: (from your .env file)"
echo ""
echo "Kibana will be ready in about 30-60 seconds..."
echo "API image is ready to start with: podman-compose up pcap-api"
echo ""
