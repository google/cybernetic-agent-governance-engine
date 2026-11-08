#!/bin/sh
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

set -eu

# Terminate the Linkerd proxy sidecar on exit so the Kubernetes Job reaches
# Completed/Error cleanly instead of hanging with linkerd-proxy still running.
trap 'curl -sf -X POST http://127.0.0.1:4191/shutdown >/dev/null 2>&1 || true' EXIT

if [ "${LULA_SKIP_LINKERD_WAIT:-false}" != "true" ]; then
  ready_tries=0
  until curl -sf http://127.0.0.1:4191/ready >/dev/null 2>&1; do
    ready_tries=$((ready_tries + 1))
    if [ "$ready_tries" -ge 30 ]; then
      echo "ERROR: linkerd-proxy /ready did not succeed within 30s" >&2
      exit 1
    fi
    sleep 1
  done
fi

SPEC_DIR="${LULA_SPECS_DIR:-/etc/cage/lula}"
OUT_DIR="${LULA_OUT_DIR:-/tmp}"
LULA_BIN="${LULA_BIN:-/usr/local/bin/lula}"

total=0
passed=0
failed=0
failed_list=""

for spec in "${SPEC_DIR}"/lula-validation-*.yaml; do
  if [ ! -e "$spec" ]; then
    continue
  fi
  total=$((total + 1))
  name=$(basename "$spec" .yaml)
  out_file="${OUT_DIR}/${name}.yaml"
  rm -f "$out_file"

  if "$LULA_BIN" validate -f "$spec" -o "$out_file" && \
     [ -s "$out_file" ] && \
     grep -q 'observations:' "$out_file" && \
     ! grep -Eq 'state:[[:space:]]*not-satisfied|lula-validation-error' "$out_file"; then
    passed=$((passed + 1))
    echo "PASS: ${name}"
  else
    failed=$((failed + 1))
    if [ -z "$failed_list" ]; then
      failed_list="$name"
    else
      failed_list="${failed_list},${name}"
    fi
    echo "FAIL: ${name}" >&2
  fi
done

if [ "$total" -eq 0 ]; then
  echo "ERROR: zero Lula validation manifests found in ${SPEC_DIR}; failing closed." >&2
  exit 1
fi

ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
if [ "$failed" -eq 0 ]; then
  summary="lula_audit PASS: ${passed}/${total} active validations satisfied"
else
  summary=$(printf 'lula_audit FAIL: %s/%s satisfied (%s failed: %s)' "$passed" "$total" "$failed" "$failed_list" | cut -c1-480)
fi

# Omit source/namespace/pod_name: compliance-bridge derives producer identity
# strictly from the verified Linkerd mesh SVID (F-85 / R-3).
payload=$(jq -nc \
  --arg ts "$ts" \
  --arg summary "$summary" \
  '{event_type: "lula_audit", timestamp_utc: $ts, summary: $summary, control_hint: "A.5.3"}')

idem_raw="lula-audit-${HOSTNAME:-run}-${ts}"
idem_key=$(printf '%s' "$idem_raw" | tr -cd 'A-Za-z0-9_.:-' | cut -c1-120)

post_ok=0
if resp=$(curl -sf -X POST "${COMPLIANCE_BRIDGE_EVENTS_URL}" \
     -H "Content-Type: application/json" \
     -H "Idempotency-Key: ${idem_key}" \
     -d "$payload") && \
   record_hash=$(printf '%s' "$resp" | jq -er 'select(.status == "INGESTED" and (.record_hash | type == "string" and length == 64)) | .record_hash'); then
  post_ok=1
  echo "Sealed lula_audit assessment-results via /v1/infra/events: status=INGESTED record_hash=${record_hash} (${passed}/${total} satisfied, ${failed} not-satisfied)"
else
  echo "ERROR: failed to POST lula_audit event to ${COMPLIANCE_BRIDGE_EVENTS_URL}" >&2
fi

if [ "$failed" -gt 0 ] || [ "$post_ok" -ne 1 ]; then
  exit 1
fi
