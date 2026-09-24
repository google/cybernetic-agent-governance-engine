#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

# ─── Allow Inbound Traffic on ClickHouse Ports in COS iptables ────────────────
echo "Configuring host firewall for ClickHouse..."
iptables -I INPUT 1 -p tcp -m multiport --dports 8123,9000 -j ACCEPT

# ─── Mount Persistent SSD ──────────────────────────────────────────────────────
echo "Mounting ClickHouse data disk..."
mkdir -p /mnt/disks/clickhouse-data
DISK_DEV="/dev/disk/by-id/google-clickhouse-data"

if ! blkid "$DISK_DEV"; then
  echo "Formatting new disk..."
  mkfs.ext4 -m 0 -F -E lazy_itable_init=0,lazy_journal_init=0,discard "$DISK_DEV"
fi

mount -o discard,defaults "$DISK_DEV" /mnt/disks/clickhouse-data || true
chmod a+w /mnt/disks/clickhouse-data

# ─── Configure ClickHouse to Listen on All Interfaces ─────────────────────────
mkdir -p /mnt/disks/clickhouse-data/config.d
cat <<'EOF' > /mnt/disks/clickhouse-data/config.d/listen.xml
<clickhouse>
    <listen_host>0.0.0.0</listen_host>
</clickhouse>
EOF

# ─── Pull and Launch ClickHouse Server (Docker on COS) ─────────────────────────
echo "Pulling ClickHouse image..."
PULL_SUCCESS=0
for i in $(seq 1 15); do
  if docker pull clickhouse/clickhouse-server:26.4-distroless; then
    echo "Docker pull succeeded on attempt $i"
    PULL_SUCCESS=1
    break
  fi
  echo "Docker pull attempt $i failed, retrying in 3s..."
  sleep 3
done

if [ "$PULL_SUCCESS" -ne 1 ]; then
  echo "Failed to pull ClickHouse image after 15 attempts"
  exit 1
fi

echo "Starting ClickHouse server..."
docker rm -f cage-clickhouse || true
docker run -d \
  --name cage-clickhouse \
  --restart always \
  --net=host \
  --ulimit nofile=262144:262144 \
  -v /mnt/disks/clickhouse-data:/var/lib/clickhouse \
  -v /mnt/disks/clickhouse-data/config.d:/etc/clickhouse-server/config.d \
  -e CLICKHOUSE_DB=langfuse \
  -e CLICKHOUSE_USER=default \
  -e CLICKHOUSE_PASSWORD="${clickhouse_password}" \
  clickhouse/clickhouse-server:26.4-distroless

echo "ClickHouse container launched. Waiting for health check..."
SUCCESS=0
for i in $(seq 1 45); do
  if curl -sf http://127.0.0.1:8123/ping >/dev/null; then
    echo "ClickHouse health check: PASSED (attempt $i)"
    SUCCESS=1
    break
  fi
  echo "Attempt $i: waiting for ClickHouse..."
  sleep 2
done

if [ "$SUCCESS" -ne 1 ]; then
  echo "ClickHouse health check: FAILED after 90s"
  docker logs cage-clickhouse || true
  exit 1
fi

INTERNAL_IP=$(hostname -i | awk '{print $1}')
echo "Testing internal IP $INTERNAL_IP..."
curl -s "http://$${INTERNAL_IP}:8123/ping" || true

# Check for and clear any dirty schema_migrations left from prior failed migrations
DIRTY_CHECK=$(curl -s -u "default:${clickhouse_password}" "http://127.0.0.1:8123/" --data-binary "SELECT count() FROM langfuse.schema_migrations WHERE dirty = 1" 2>/dev/null || true)
if echo "$${DIRTY_CHECK}" | grep -E '^[1-9][0-9]*$' >/dev/null; then
  echo "Detected dirty schema_migrations ($${DIRTY_CHECK}) in langfuse database. Resetting database for clean migration..."
  curl -s -u "default:${clickhouse_password}" "http://127.0.0.1:8123/" --data-binary "DROP DATABASE IF EXISTS langfuse" || true
  curl -s -u "default:${clickhouse_password}" "http://127.0.0.1:8123/" --data-binary "CREATE DATABASE IF NOT EXISTS langfuse" || true
fi

echo "ClickHouse startup completely ready."

