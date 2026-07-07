#!/bin/bash
echo "========================================"
echo "   Ceph RADOS Cluster Setup"
echo "========================================"
echo ""

if [ ! -f .env ]; then
    echo "Error: .env file not found!"
    echo "Please create .env from .env.example first:"
    echo "  cp .env.example .env"
    exit 1
fi

set -a
source .env
set +a

echo "Step 1: Fixing Ceph permissions..."
sudo mkdir -p /etc/ceph /var/lib/ceph/bootstrap-osd /var/lib/ceph/bootstrap-rgw
sudo chmod -R 777 /etc/ceph /var/lib/ceph
sudo chown -R $(whoami):$(whoami) /etc/ceph /var/lib/ceph
echo "Permissions set."

echo ""
echo "Step 2: Cleaning up old Ceph containers and volumes..."
docker rm -f ceph-mon ceph-mgr ceph-osd ceph-rgw 2>/dev/null || true
docker volume rm ceph_ceph-etc ceph_ceph-lib 2>/dev/null || true
docker network rm ceph-net 2>/dev/null || true
# Remove any network already using the same subnet
CONFLICT=$(docker network ls -q | xargs -I{} docker network inspect {} --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null | grep "${CEPH_PUBLIC_NETWORK}" | awk '{print $1}')
if [ -n "$CONFLICT" ]; then
    echo "Removing conflicting network: $CONFLICT"
    docker network rm "$CONFLICT" 2>/dev/null || true
fi
docker network create --driver bridge --subnet ${CEPH_PUBLIC_NETWORK} ceph-net
echo "Cleanup done."

echo ""
echo "Step 3: Starting Ceph MON, MGR, OSD..."
docker compose -f docker-compose-ceph.yml up -d ceph-mon ceph-mgr ceph-osd

echo ""
echo "Step 4: Waiting for MON to initialize..."
sleep 30

echo ""
echo "Step 5: Generating bootstrap-osd keyring..."
docker exec ceph-mon ceph auth get client.bootstrap-osd -o /var/lib/ceph/bootstrap-osd/ceph.keyring
echo "Keyring generated."

echo ""
echo "Step 6: Fixing insecure global_id warning..."
docker exec ceph-mon ceph config set mon auth_allow_insecure_global_id_reclaim false

echo ""
echo "Step 7: Restarting OSD to pick up keyring..."
docker restart ceph-osd
sleep 15

echo ""
echo "Step 8: Configuring single-node replication..."
docker exec ceph-mon ceph config set global osd_pool_default_size 1
docker exec ceph-mon ceph config set global osd_pool_default_min_size 1

echo ""
echo "Step 9: Creating RADOS pool 'mypool'..."
docker exec ceph-mon ceph osd pool create mypool 4
echo "Pool created."

echo ""
echo "Step 10: Setting up RGW realm, zonegroup and zone..."
docker exec ceph-mon radosgw-admin realm create --rgw-realm=default --default
docker exec ceph-mon radosgw-admin zonegroup create --rgw-zonegroup=default --master --default
docker exec ceph-mon radosgw-admin zone create --rgw-zonegroup=default --rgw-zone=default --master --default
docker exec ceph-mon radosgw-admin period update --commit
echo "RGW realm/zone configured."

echo ""
echo "Step 11: Creating RGW admin user..."
docker exec ceph-mon radosgw-admin user create \
    --uid="$RGW_USER" \
    --display-name="$RGW_DISPLAY_NAME" \
    --access-key="$RGW_ACCESS_KEY" \
    --secret-key="$RGW_SECRET_KEY"
echo "RGW user created."

echo ""
echo "Step 12: Generating bootstrap-rgw keyring..."
docker exec ceph-mon ceph auth get client.bootstrap-rgw -o /var/lib/ceph/bootstrap-rgw/ceph.keyring
echo "RGW keyring generated."

echo ""
echo "Step 13: Starting RGW..."
docker compose -f docker-compose-ceph.yml up -d ceph-rgw
sleep 30
echo "RGW started."

echo ""
echo "Step 14: Enabling Ceph Dashboard..."
docker exec ceph-mon ceph mgr module enable dashboard
docker exec ceph-mon ceph config set mgr mgr/dashboard/ssl false
docker exec ceph-mon ceph config set mgr mgr/dashboard/server_port 7000
docker exec ceph-mon bash -c "echo '$DASHBOARD_PASSWORD' > /tmp/dashboard-pass"
docker exec ceph-mon ceph dashboard ac-user-create "$DASHBOARD_USER" -i /tmp/dashboard-pass administrator
echo "Dashboard enabled."

echo ""
echo "Step 15: Restarting MGR to apply dashboard config..."
docker restart ceph-mgr
sleep 10

echo ""
echo "Step 16: Checking dashboard URL..."
docker exec ceph-mon ceph mgr services

echo ""
echo "Step 17: Testing RGW endpoint..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${RGW_PORT} || true)
echo "RGW HTTP response: $HTTP_CODE (200 or 403 = OK)"

echo ""
echo "Step 18: Creating S3 bucket and saving to .env..."
BUCKET_HASH=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 16)
BUCKET_NAME="pcap-${BUCKET_HASH}"
sed -i '/^CEPH_BUCKET=/d' .env
echo "CEPH_BUCKET=${BUCKET_NAME}" >> .env

# Wait for RGW to be ready
echo "Waiting for RGW to be ready..."
for i in $(seq 1 24); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${RGW_PORT} || true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "403" ]; then
        echo "RGW is ready (HTTP $HTTP_CODE)."
        break
    fi
    echo "  Waiting... ($i/24)"
    sleep 5
done

# Set up myenv virtualenv with boto3
if [ ! -d myenv ]; then
    sudo apt-get install -y python3-venv -qq
    python3 -m venv myenv
fi
myenv/bin/pip install --quiet boto3

myenv/bin/python3 - <<EOF
import boto3
s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:${RGW_PORT}",
    aws_access_key_id="${RGW_ACCESS_KEY}",
    aws_secret_access_key="${RGW_SECRET_KEY}",
    region_name="us-east-1",
)
s3.create_bucket(Bucket="${BUCKET_NAME}")
print("Bucket created:", "${BUCKET_NAME}")
EOF
echo "Bucket '${BUCKET_NAME}' created and saved to .env."

echo ""
echo "Step 19: Running RADOS read/write test..."
docker exec ceph-mon bash -c "echo 'ceph rados is working' > /tmp/test.txt && rados -p mypool put testobj /tmp/test.txt"
RESULT=$(docker exec ceph-mon bash -c "rados -p mypool get testobj /tmp/out.txt && cat /tmp/out.txt")
echo "RADOS test result: $RESULT"

echo ""
echo "========================================"
echo "        CEPH SETUP COMPLETE"
echo "========================================"
echo ""
echo "=== Ceph Dashboard ==="
echo "  URL:      http://localhost:${DASHBOARD_PORT}"
echo "  Username: ${DASHBOARD_USER}"
echo "  Password: ${DASHBOARD_PASSWORD}"
echo ""
echo "=== Ceph RGW (S3) ==="
echo "  Endpoint:   http://localhost:${RGW_PORT}"
echo "  Access Key: ${RGW_ACCESS_KEY}"
echo "  Secret Key: ${RGW_SECRET_KEY}"
echo "  Bucket:     ${BUCKET_NAME}"
echo ""