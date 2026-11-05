#!/usr/bin/env bash
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

# Send an identified request to the Docker Compose gateway.
#
# In enforcing deployments (GKE + Linkerd), the gateway believes l5d-client-id
# only on a non-loopback connection from the pod's own IP, where the Linkerd
# inbound proxy runs; loopback peers (127.0.0.1 / ::1) are never treated as the
# proxy (POAM-2026-167, src/gateway/server/workload_identity.py).
#
# Compose has no Linkerd proxy, and a request from the host reaches the gateway
# from outside its container (which the gateway refuses with 403). This script
# sends the request from inside the gateway container over the dev-only loopback
# channel (LT-1), which requires BOTH a non-enforcing dev posture (CAGE_ENV in
# dev/development) AND CAGE_ALLOW_DEV_LOOPBACK_IDENTITY=true in the gateway
# container (unconditionally refused when is_enforcing() is True).
#
# Usage: scripts/compose_gateway_call.sh PATH [JSON_BODY]
#   POSTs JSON_BODY to PATH if given, otherwise GETs PATH, and prints the
#   response body. Exits 22 on an HTTP error status, as curl -f does.
#   GATEWAY_CALL_IDENTITY sets the identity. The default is the advisor's,
#   which .env.example trusts.

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || "$1" != /* ]]; then
  echo "usage: $0 PATH [JSON_BODY]   (PATH starts with /)" >&2
  exit 2
fi

identity="${GATEWAY_CALL_IDENTITY:-cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec docker compose exec -T gateway python - "$identity" "$@" <<'PY'
import os
import sys
import urllib.error
import urllib.request

cage_env = os.environ.get("CAGE_ENV", "").strip().lower()
allow_dev_loopback = os.environ.get("CAGE_ALLOW_DEV_LOOPBACK_IDENTITY", "").strip().lower()
if cage_env not in {"dev", "development"} or allow_dev_loopback not in {"1", "true", "yes", "on"}:
    sys.exit(
        "compose_gateway_call.sh requires CAGE_ENV=dev/development and "
        "CAGE_ALLOW_DEV_LOOPBACK_IDENTITY=true in the gateway container (LT-1 / POAM-2026-167)"
    )

identity, path = sys.argv[1], sys.argv[2]
body = sys.argv[3].encode() if len(sys.argv) > 3 else None
request = urllib.request.Request(
    "http://127.0.0.1:8080" + path,
    data=body,
    method="GET" if body is None else "POST",
    headers={
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "l5d-client-id": identity,
    },
)
try:
    with urllib.request.urlopen(request, timeout=60) as response:
        print(response.read().decode())
except urllib.error.HTTPError as error:
    print(f"HTTP {error.code}: {error.read().decode()}", file=sys.stderr)
    sys.exit(22)
PY
