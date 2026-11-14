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
insufficient_traffic=0
startup_grace=0
satisfied_list=""
failed_list=""
insufficient_traffic_list=""
startup_grace_list=""

for spec in "${SPEC_DIR}"/lula-validation-*.yaml; do
  if [ ! -e "$spec" ]; then
    continue
  fi
  total=$((total + 1))
  name=$(basename "$spec" .yaml)
  out_file="${OUT_DIR}/${name}.yaml"
  rm -f "$out_file"

  if "$LULA_BIN" validate -f "$spec" -o "$out_file"; then
    lula_rc=0
  else
    lula_rc=$?
  fi

  if [ "$lula_rc" -eq 0 ] && \
     [ -s "$out_file" ] && \
     grep -q 'observations:' "$out_file" && \
     ! grep -Eq 'state:[[:space:]]*not-satisfied|lula-validation-error' "$out_file"; then
    requires_remark=0
    case "$name" in
      lula-validation-a52|lula-validation-a53|lula-validation-a92)
        requires_remark=1
        ;;
    esac
    if [ "$requires_remark" -eq 1 ] || grep -q 'lula\.assessment_remark:' "$out_file"; then
      if grep -Eq 'lula\.assessment_remark:[[:space:]]*assessment_status=satisfied([[:space:];]|$)' "$out_file" && \
         ! grep -Eq 'lula\.assessment_remark:[[:space:]]*assessment_status=startup_grace([[:space:];]|$)' "$out_file"; then
        passed=$((passed + 1))
        if [ -z "$satisfied_list" ]; then
          satisfied_list="$name"
        else
          satisfied_list="${satisfied_list},${name}"
        fi
        echo "PASS: ${name}"
      elif grep -Eq 'lula\.assessment_remark:[[:space:]]*assessment_status=startup_grace([[:space:];]|$)' "$out_file"; then
        passed=$((passed + 1))
        startup_grace=$((startup_grace + 1))
        if [ -z "$satisfied_list" ]; then
          satisfied_list="$name"
        else
          satisfied_list="${satisfied_list},${name}"
        fi
        if [ -z "$startup_grace_list" ]; then
          startup_grace_list="$name"
        else
          startup_grace_list="${startup_grace_list},${name}"
        fi
        echo "PASS (assessment_status=startup_grace): ${name}"
      else
        failed=$((failed + 1))
        if [ -z "$failed_list" ]; then
          failed_list="$name"
        else
          failed_list="${failed_list},${name}"
        fi
        echo "FAIL: ${name} (missing or unrecognized lula.assessment_remark)" >&2
      fi
    else
      passed=$((passed + 1))
      if [ -z "$satisfied_list" ]; then
        satisfied_list="$name"
      else
        satisfied_list="${satisfied_list},${name}"
      fi
      echo "PASS: ${name}"
    fi
  elif [ "$lula_rc" -eq 0 ] && \
       [ -s "$out_file" ] && \
       grep -q 'observations:' "$out_file" && \
       ! grep -q 'lula-validation-error' "$out_file" && \
       grep -Eq 'state:[[:space:]]*not-satisfied' "$out_file" && \
       grep -Eq 'lula\.assessment_remark:[[:space:]]*assessment_status=insufficient_traffic([[:space:];]|$)' "$out_file" && \
       ! grep -Eq 'lula\.assessment_remark:[[:space:]]*assessment_status=(threshold_violation|stale_evidence|missing_metrics_response)([[:space:];]|$)' "$out_file"; then
    insufficient_traffic=$((insufficient_traffic + 1))
    if [ -z "$insufficient_traffic_list" ]; then
      insufficient_traffic_list="$name"
    else
      insufficient_traffic_list="${insufficient_traffic_list},${name}"
    fi
    echo "INSUFFICIENT_TRAFFIC: ${name} (not-satisfied: total_traces=0)"
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
if [ "$failed" -eq 0 ] && [ "$insufficient_traffic" -eq 0 ]; then
  if [ "$startup_grace" -gt 0 ]; then
    summary=$(printf 'lula_audit PASS: %s/%s active validations satisfied (%s startup_grace: %s)' "$passed" "$total" "$startup_grace" "$startup_grace_list" | cut -c1-480)
    sealed_counts="${passed}/${total} satisfied, 0 not-satisfied, ${startup_grace} startup_grace [${startup_grace_list}]"
  else
    summary="lula_audit PASS: ${passed}/${total} active validations satisfied"
    sealed_counts="${passed}/${total} satisfied, 0 not-satisfied"
  fi
elif [ "$failed" -eq 0 ]; then
  summary=$(printf 'lula_audit INSUFFICIENT_TRAFFIC: %s/%s satisfied (%s not-satisfied [insufficient_traffic]: %s)' "$passed" "$total" "$insufficient_traffic" "$insufficient_traffic_list" | cut -c1-480)
  sealed_counts="${passed}/${total} satisfied, 0 failed, ${insufficient_traffic} not-satisfied [insufficient_traffic]"
elif [ "$insufficient_traffic" -eq 0 ]; then
  summary=$(printf 'lula_audit FAIL: %s/%s satisfied (%s failed: %s)' "$passed" "$total" "$failed" "$failed_list" | cut -c1-480)
  sealed_counts="${passed}/${total} satisfied, ${failed} not-satisfied"
else
  total_not_sat=$((failed + insufficient_traffic))
  summary=$(printf 'lula_audit FAIL: %s/%s satisfied (%s failed: %s; %s insufficient_traffic: %s)' "$passed" "$total" "$failed" "$failed_list" "$insufficient_traffic" "$insufficient_traffic_list" | cut -c1-480)
  sealed_counts="${passed}/${total} satisfied, ${total_not_sat} not-satisfied"
fi

# Omit source/namespace/pod_name: compliance-bridge derives producer identity
# strictly from the verified Linkerd mesh SVID (F-85 / R-3).
payload=$(jq -nc \
  --arg ts "$ts" \
  --arg summary "$summary" \
  --argjson evaluated_count "$total" \
  --argjson satisfied_count "$passed" \
  --argjson failed_count "$failed" \
  --argjson insufficient_traffic_count "$insufficient_traffic" \
  --argjson startup_grace_count "$startup_grace" \
  --arg failed_csv "$failed_list" \
  --arg insufficient_csv "$insufficient_traffic_list" \
  --arg startup_grace_csv "$startup_grace_list" \
  '{
    event_type: "lula_audit",
    timestamp_utc: $ts,
    summary: $summary,
    control_hint: "A.5.3",
    evaluated_count: $evaluated_count,
    satisfied_count: $satisfied_count,
    failed_count: $failed_count,
    insufficient_traffic_count: $insufficient_traffic_count,
    startup_grace_count: $startup_grace_count,
    failed_controls: (if $failed_csv == "" then [] else ($failed_csv | split(",")) end),
    insufficient_traffic_controls: (if $insufficient_csv == "" then [] else ($insufficient_csv | split(",")) end),
    startup_grace_controls: (if $startup_grace_csv == "" then [] else ($startup_grace_csv | split(",")) end)
  }')

idem_raw="lula-audit-${HOSTNAME:-run}-${ts}"
idem_key=$(printf '%s' "$idem_raw" | tr -cd 'A-Za-z0-9_.:-' | cut -c1-120)

post_ok=0
if resp=$(curl -sf -X POST "${COMPLIANCE_BRIDGE_EVENTS_URL}" \
     -H "Content-Type: application/json" \
     -H "Idempotency-Key: ${idem_key}" \
     -d "$payload") && \
   record_hash=$(printf '%s' "$resp" | jq -er 'select(.status == "INGESTED" and (.record_hash | type == "string" and length == 64)) | .record_hash'); then
  post_ok=1
  echo "Sealed lula_audit assessment-results via /v1/infra/events: status=INGESTED record_hash=${record_hash} (${sealed_counts})"
  jq -nc \
    --arg record_hash "$record_hash" \
    --arg summary "$summary" \
    --argjson evaluated_count "$total" \
    --argjson satisfied_count "$passed" \
    --argjson failed_count "$failed" \
    --argjson insufficient_traffic_count "$insufficient_traffic" \
    --argjson startup_grace_count "$startup_grace" \
    --arg sat_csv "$satisfied_list" \
    --arg sg_csv "$startup_grace_list" \
    '{
      cage_lula_audit_receipt_v1: {
        status: "INGESTED",
        record_hash: $record_hash,
        summary: $summary,
        evaluated_count: $evaluated_count,
        satisfied_count: $satisfied_count,
        failed_count: $failed_count,
        insufficient_traffic_count: $insufficient_traffic_count,
        startup_grace_count: $startup_grace_count,
        satisfied_controls: (if $sat_csv == "" then [] else ($sat_csv | split(",")) end),
        startup_grace_controls: (if $sg_csv == "" then [] else ($sg_csv | split(",")) end)
      }
    }'
else
  echo "ERROR: failed to POST lula_audit event to ${COMPLIANCE_BRIDGE_EVENTS_URL}" >&2
fi

if [ "$failed" -gt 0 ] || [ "$post_ok" -ne 1 ]; then
  exit 1
fi
