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

# ─── Mount Persistent SSD ──────────────────────────────────────────────────────
echo "Mounting ClickHouse data disk..."
mkdir -p /mnt/disks/clickhouse-data
DISK_DEV="/dev/disk/by-id/google-clickhouse-data"

if ! blkid "$DISK_DEV"; then
  echo "Formatting new disk..."
  mkfs.ext4 -m 0 -F -E lazy_itable_init=0,lazy_journal_init=0,discard "$DISK_DEV"
fi

mount -o discard,defaults "$DISK_DEV" /mnt/disks/clickhouse-data
chmod a+w /mnt/disks/clickhouse-data

# ─── Launch ClickHouse Server (Docker on COS) ──────────────────────────────────
echo "Starting ClickHouse server..."
docker run -d \
  --name cage-clickhouse \
  --restart always \
  --net=host \
  --ulimit nofile=262144:262144 \
  -v /mnt/disks/clickhouse-data:/var/lib/clickhouse \
  -e CLICKHOUSE_DB=langfuse \
  -e CLICKHOUSE_USER=default \
  -e CLICKHOUSE_PASSWORD="${clickhouse_password}" \
  clickhouse/clickhouse-server:24.3-alpine

echo "ClickHouse startup complete. Waiting for health check..."
sleep 10

# Verify ClickHouse is responding
if curl -s http://localhost:8123/ping | grep -q "Ok"; then
  echo "ClickHouse health check: PASSED"
else
  echo "ClickHouse health check: FAILED"
  exit 1
fi
