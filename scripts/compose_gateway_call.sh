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
# The gateway believes l5d-client-id only on a connection from inside its own
# pod, where the Linkerd proxy that sets it runs (POAM-2026-167,
# src/gateway/server/workload_identity.py). Compose has no proxy, and a request
# from the host reaches the gateway from outside its container, so the gateway
# refuses one that carries the header. This script sends the request from
# inside the gateway container instead, with the identity the proxy would set.
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
import sys
import urllib.error
import urllib.request

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
