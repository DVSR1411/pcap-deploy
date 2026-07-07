#!/bin/bash

# ─────────────────────────────────────────────
#  Container Startup & Health Check Script
# ─────────────────────────────────────────────

PCAP_CONTAINER="pcap-api"
STARTUP_WAIT=15
PCAP_RESTART_WAIT=10
HEALTH_CHECK_RETRIES=3
HEALTH_CHECK_INTERVAL=10

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')] $*${NC}"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✔  $*${NC}"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠  $*${NC}"; }
err()  { echo -e "${RED}[$(date '+%H:%M:%S')] ✘  $*${NC}"; }

# ─────────────────────────────────────────────
# Step 1: Start all containers
# ─────────────────────────────────────────────
log "Starting application. Please wait..."
docker restart $(docker ps -a -q) > /dev/null 2>&1
ok "Application started successfully."

# ─────────────────────────────────────────────
# Step 2: Wait for services to stabilise
# ─────────────────────────────────────────────
log "Services are initialising. Please wait..."
sleep "$STARTUP_WAIT"

# ─────────────────────────────────────────────
# Step 3: Restart core service
# ─────────────────────────────────────────────
log "Starting core services. Please wait..."
docker restart "$PCAP_CONTAINER" > /dev/null 2>&1
sleep "$PCAP_RESTART_WAIT"

# ─────────────────────────────────────────────
# Step 4: Health check
# ─────────────────────────────────────────────
check_health() {
  docker inspect -f '{{.State.Health.Status}}' "$PCAP_CONTAINER" 2>/dev/null || echo "none"
}

log "Checking health of all services. Please wait..."

ATTEMPT=0
while [[ $ATTEMPT -lt $HEALTH_CHECK_RETRIES ]]; do
  ATTEMPT=$(( ATTEMPT + 1 ))
  sleep "$HEALTH_CHECK_INTERVAL"

  HEALTH=$(check_health)

  if [[ "$HEALTH" == "healthy" ]]; then
    ok "All services are healthy. Application is ready!"
    exit 0
  elif [[ "$HEALTH" == "none" ]]; then
    ok "All services are running. Application is ready!"
    exit 0
  elif [[ "$HEALTH" == "unhealthy" || "$HEALTH" == "starting" ]]; then
    if [[ $ATTEMPT -lt $HEALTH_CHECK_RETRIES ]]; then
      warn "Services not ready yet. Restarting... (${ATTEMPT}/${HEALTH_CHECK_RETRIES})"
      docker restart "$PCAP_CONTAINER" > /dev/null 2>&1
      log "Waiting for services to recover. Please wait..."
      sleep "$PCAP_RESTART_WAIT"
    fi
  fi
done

err "Services failed to start. Please check your configuration."
exit 1
