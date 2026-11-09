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

# ─── Staging Lifecycle Manager (Gate W Release-Validation Harness) ────────────
#
# Purpose: Provision, validate, read back, rebuild, and destroy the ephemeral
#          staging environment in a single fail-closed automated cycle
#          (POAM-024 / POAM-2026-131 / POAM-2026-159 / POAM-2026-164).
#
# Phases:
#   Phase 0 (Optional): Fresh-project bootstrap (--fresh-project)
#   Phase 1: Provision + post-apply zero-drift read-back (terraform plan -detailed-exitcode)
#   Phase 2: Dynamic workload readiness, CronJob/lula-audit active, restartCount == 0
#   Phase 3: Host lula validate + explicit planned list + in-cluster Job/lula-gate-w + WORM custody ack
#   Phase 4: Regional posture suites (US_FED, EU_ECB, APAC_MAS) + live data residency + live Langfuse posture
#   Phase 5: Pre-teardown live sweeps (live_external, integration, partner conformance) +
#            Cloud Monitoring GMP timeSeries.list + WORM /v1/evidence/verify + AS-6 corroboration hook
#   Phase 6: Stages 4–6 (--import-state, clean rebuild + zero-drift, final teardown, --fresh-project zero-survivor check)
#
# Usage:
#   ./scripts/staging_lifecycle.sh [OPTIONS]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TF_DIR="$REPO_ROOT/infra/targets/gcp-gke"
NAMESPACE="${K8S_NAMESPACE:-governance-stack}"

# ─── Load .env defaults without overwriting caller-exported variables ─────────
if [[ -f "$REPO_ROOT/.env" ]]; then
  while IFS='=' read -r _env_key _env_val || [[ -n "${_env_key:-}" ]]; do
    [[ -z "${_env_key//[[:space:]]/}" || "${_env_key#\#}" != "$_env_key" ]] && continue
    _env_key="${_env_key#export }"
    _env_key="${_env_key//[[:space:]]/}"
    if [[ "$_env_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && -z "${!_env_key+x}" ]]; then
      _env_val="${_env_val%\"}"
      _env_val="${_env_val#\"}"
      _env_val="${_env_val%\'}"
      _env_val="${_env_val#\'}"
      export "$_env_key=$_env_val"
    fi
  done < "$REPO_ROOT/.env"
fi

# ─── Color codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# ─── Parse arguments ──────────────────────────────────────────────────────────
SKIP_LULA=false
SKIP_POSTURE=false
SKIP_LIVE_SWEEP=false
SKIP_TELEMETRY=false
SKIP_REBUILD=false
NO_DESTROY=false
FRESH_PROJECT=false
ALLOW_LEGACY_LIEN_SURVIVOR=false
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:-}"
REGION="${GOOGLE_CLOUD_LOCATION:-us-central1}"
ZONE="${GOOGLE_CLOUD_ZONE:-${REGION}-a}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Provision, validate, read back, rebuild, and destroy the ephemeral GKE staging environment.

Options:
  --fresh-project[=<id>]   Bootstrap a clean or throwaway GCP project before
                           provisioning and verify post-destroy cleanliness
  --billing-account=<id>   Billing account ID to link when creating a fresh project
  --project=<id>           GCP project ID (default: \$GOOGLE_CLOUD_PROJECT)
  --skip-lula              Skip Phase 3 Lula validation
  --skip-posture           Skip Phase 4 region posture, residency, and Langfuse checks
  --skip-live-sweep        Skip Phase 5 live_external, integration, and conformance sweeps
  --skip-telemetry         Skip Phase 5 GMP timeSeries.list, /v1/evidence/verify, and AS-6 hook
  --skip-rebuild           Skip Phase 6 Stages 4–5 (--import-state + clean rebuild)
  --no-destroy             Skip Phase 6 teardown (still exits non-zero on gate failure)
  -h, --help               Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-lula)
      SKIP_LULA=true
      shift
      ;;
    --skip-posture)
      SKIP_POSTURE=true
      shift
      ;;
    --skip-live-sweep)
      SKIP_LIVE_SWEEP=true
      shift
      ;;
    --skip-telemetry)
      SKIP_TELEMETRY=true
      shift
      ;;
    --skip-rebuild)
      SKIP_REBUILD=true
      shift
      ;;
    --no-destroy)
      NO_DESTROY=true
      shift
      ;;
    --fresh-project) FRESH_PROJECT=true; shift ;;
    --allow-legacy-lien-survivor)
      ALLOW_LEGACY_LIEN_SURVIVOR=true; shift ;;
    --fresh-project=*)
      FRESH_PROJECT=true
      PROJECT_ID="${1#*=}"
      shift
      ;;
    --billing-account=*)
      BILLING_ACCOUNT_ID="${1#*=}"
      shift
      ;;
    --billing-account)
      BILLING_ACCOUNT_ID="${2:-}"
      shift 2
      ;;
    --project=*)
      PROJECT_ID="${1#*=}"
      shift
      ;;
    --project)
      PROJECT_ID="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown argument: $1${RESET}" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# ─── Helper functions ─────────────────────────────────────────────────────────
info() {
  echo -e "${CYAN}[INFO]${RESET} $*"
}

success() {
  echo -e "${GREEN}[SUCCESS]${RESET} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${RESET} $*"
}

error() {
  echo -e "${RED}[ERROR]${RESET} $*" >&2
}

if [[ -z "$PROJECT_ID" ]]; then
  PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
fi

if [[ -z "$PROJECT_ID" ]]; then
  error "No GCP project specified. Set GOOGLE_CLOUD_PROJECT, pass --project=<id>, or pass --fresh-project=<id>."
  exit 1
fi

export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
export GOOGLE_CLOUD_LOCATION="$REGION"
export TF_VAR_project_id="$PROJECT_ID"

DRIFT_FAILURES=0
READINESS_FAILED=false
LULA_FAILURES=0
POSTURE_FAILURES=0
SWEEP_FAILURES=0
TELEMETRY_FAILURES=0
REBUILD_FAILURES=0
PORT_FORWARD_ACTIVE=false

stop_staging_port_forward() {
  if [[ "$PORT_FORWARD_ACTIVE" == "true" && -x "$REPO_ROOT/scripts/port_forward_staging.sh" ]]; then
    "$REPO_ROOT/scripts/port_forward_staging.sh" --stop >/dev/null 2>&1 || true
    PORT_FORWARD_ACTIVE=false
  fi
}
trap stop_staging_port_forward EXIT

start_staging_port_forward() {
  if [[ "$PORT_FORWARD_ACTIVE" == "false" && -x "$REPO_ROOT/scripts/port_forward_staging.sh" ]]; then
    info "Starting staging port-forward tunnels..."
    if "$REPO_ROOT/scripts/port_forward_staging.sh" --force; then
      PORT_FORWARD_ACTIVE=true
    else
      warn "scripts/port_forward_staging.sh returned non-zero; relying on explicit service URLs / kubectl exec."
    fi
  fi
}

DIGESTS_FILE=""
TF_VAR_ARGS=()

resolve_digests_file() {
  local short_sha
  short_sha="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "")"
  DIGESTS_FILE=""
  if [[ -n "$short_sha" && -f "$TF_DIR/image_digests.${short_sha}.tfvars.json" ]]; then
    DIGESTS_FILE="$TF_DIR/image_digests.${short_sha}.tfvars.json"
  elif [[ -f "$TF_DIR/tests/fixtures/image_digests.tfvars" ]]; then
    DIGESTS_FILE="$TF_DIR/tests/fixtures/image_digests.tfvars"
  fi
}

build_tf_var_args() {
  resolve_digests_file
  TF_VAR_ARGS=(
    "-var-file=staging.tfvars"
    "-var=project_id=${PROJECT_ID}"
    "-var=region=${REGION}"
    "-var=cage_deployment_region=${CAGE_DEPLOYMENT_REGION:-US_FED}"
  )
  if [[ -n "$DIGESTS_FILE" ]]; then
    TF_VAR_ARGS+=("-var-file=${DIGESTS_FILE}")
  fi
}

run_zero_drift_plan() {
  local label="$1"
  build_tf_var_args
  info "Running post-apply zero-drift read-back (${label}): terraform plan -detailed-exitcode..."
  local plan_rc=0
  set +e
  terraform -chdir="$TF_DIR" plan -detailed-exitcode "${TF_VAR_ARGS[@]}"
  plan_rc=$?
  set -e
  if [[ $plan_rc -eq 0 ]]; then
    success "Zero-drift read-back passed (${label}): terraform plan exited 0 (no changes)."
    return 0
  elif [[ $plan_rc -eq 2 ]]; then
    error "Zero-drift read-back FAILED (${label}): terraform plan exited 2 (post-apply configuration drift detected)."
    return 1
  else
    error "Zero-drift read-back FAILED (${label}): terraform plan exited ${plan_rc} (plan error)."
    return 1
  fi
}

# Reusable fail-closed pytest runner requiring exit code 0 AND >= 1 passed test.
run_pytest_require_passed() {
  local label="$1"
  shift
  local tmp_out
  tmp_out="$(mktemp "${TMPDIR:-/tmp}/cage-pytest-XXXXXX")"
  local cmd_rc=0
  set +e
  "$@" 2>&1 | tee "$tmp_out"
  cmd_rc=${PIPESTATUS[0]}
  set -e

  if [[ $cmd_rc -ne 0 ]]; then
    error "${label}: pytest exited non-zero (rc=${cmd_rc})."
    rm -f "$tmp_out"
    return 1
  fi

  local passed_count=""
  if ! passed_count="$(python3 - "$tmp_out" <<'PY'
import re
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
clean = re.sub(r"\x1b\[[0-9;]*m", "", raw)
passed = 0
bad = False
for line in reversed(clean.splitlines()):
    m = re.search(r"\b(\d+)\s+passed\b", line)
    if m:
        passed = int(m.group(1))
        if re.search(r"\b[1-9]\d*\s+(?:failed|error|errors)\b", line):
            bad = True
        break
if bad or passed < 1:
    sys.exit(1)
print(passed)
PY
  )"; then
    error "${label}: vacuous pytest run (0 passed tests detected; all skipped, deselected, or unexecuted)."
    rm -f "$tmp_out"
    return 1
  fi

  rm -f "$tmp_out"
  success "${label}: ${passed_count} test(s) executed and passed."
  return 0
}

verify_worm_evidence_chain() {
  local label="$1"
  info "Verifying WORM custody chain (${label}) via GET /v1/evidence/verify?require_citable=true..."
  local verify_raw=""
  local fetch_rc=0
  set +e
  if [[ -n "${COMPLIANCE_BRIDGE_URL:-}" ]]; then
    verify_raw="$(python3 - "${COMPLIANCE_BRIDGE_URL}" <<'PY'
import sys
from urllib.parse import urlparse
from urllib.request import urlopen

base = sys.argv[1].rstrip("/")
url = f"{base}/v1/evidence/verify?require_citable=true"
if urlparse(url).scheme not in {"http", "https"}:
    raise SystemExit(f"Invalid COMPLIANCE_BRIDGE_URL scheme: {url!r}")
with urlopen(url, timeout=15) as resp:  # nosec B310
    if resp.status != 200:
        raise SystemExit(f"HTTP {resp.status} from {url}")
    sys.stdout.write(resp.read().decode("utf-8"))
PY
    )"
    fetch_rc=$?
  else
    verify_raw="$(kubectl exec -n "$NAMESPACE" deploy/compliance-bridge -- \
      python3 -c 'import sys, urllib.request; resp = urllib.request.urlopen("http://127.0.0.1:3001/v1/evidence/verify?require_citable=true", timeout=15); sys.exit(1) if resp.status != 200 else sys.stdout.write(resp.read().decode("utf-8"))')"
    fetch_rc=$?
  fi
  set -e

  if [[ $fetch_rc -ne 0 || -z "$verify_raw" ]]; then
    error "${label}: GET /v1/evidence/verify failed or returned empty payload (rc=${fetch_rc})."
    return 1
  fi

  local summary=""
  if ! summary="$(printf '%s' "$verify_raw" | python3 -c '
import json
import sys

def _count(val, field):
    if isinstance(val, bool):
        raise ValueError(f"{field} must be list or int, got bool")
    if isinstance(val, int):
        return val
    if isinstance(val, list):
        return len(val)
    raise ValueError(f"{field} must be list or int, got {type(val).__name__}")

try:
    data = json.load(sys.stdin)
except Exception as exc:
    print(f"invalid JSON from /v1/evidence/verify: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(data, dict):
    print("response from /v1/evidence/verify is not a JSON object", file=sys.stderr)
    sys.exit(1)

if data.get("ok") is not True or data.get("citable") is not True:
    print("archive not ok/citable (ok=%s, citable=%s)" % (data.get("ok"), data.get("citable")), file=sys.stderr)
    sys.exit(1)

verified = _count(data.get("verified", []), "verified")
failures = _count(data.get("failures", []), "failures")
gaps = max(
    _count(data.get("declared_gaps", []), "declared_gaps"),
    _count(data.get("gaps", []), "gaps"),
)
unsigned = max(
    _count(data.get("non_evidentiary", []), "non_evidentiary"),
    _count(data.get("unsigned", []), "unsigned"),
)

errors = []
if verified <= 0:
    errors.append(f"verified={verified} (expected > 0)")
if failures != 0:
    errors.append(f"failures={failures} (expected 0)")
if gaps != 0:
    errors.append(f"gaps={gaps} (expected 0)")
if unsigned != 0:
    errors.append(f"unsigned={unsigned} (expected 0)")

if errors:
    print("; ".join(errors), file=sys.stderr)
    sys.exit(1)

print(f"verified={verified}, failures={failures}, gaps={gaps}, unsigned={unsigned}")
'
  )"; then
    error "${label}: WORM evidence verification FAILED."
    return 1
  fi

  success "${label}: WORM evidence chain verified (${summary})."
  return 0
}

verify_gmp_timeseries() {
  info "Querying Cloud Monitoring API projects.timeSeries.list for prometheus.googleapis.com/cage_*..."
  local access_token
  access_token="$(gcloud auth print-access-token 2>/dev/null || true)"
  if [[ -z "$access_token" ]]; then
    error "Cloud Monitoring read-back FAILED: gcloud auth print-access-token returned empty token."
    return 1
  fi

  local interval_bounds start_time end_time
  interval_bounds="$(python3 -c '
from datetime import datetime, timedelta, timezone
now = datetime.now(timezone.utc)
start = now - timedelta(minutes=30)
print(start.strftime("%Y-%m-%dT%H:%M:%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ"))
')"
  start_time="${interval_bounds%% *}"
  end_time="${interval_bounds##* }"

  local ts_raw=""
  local curl_rc=0
  set +e
  ts_raw="$(curl -fsSL -G \
    "https://monitoring.googleapis.com/v3/projects/${PROJECT_ID}/timeSeries" \
    -H "Authorization: Bearer ${access_token}" \
    --data-urlencode 'filter=metric.type = starts_with("prometheus.googleapis.com/cage_")' \
    --data-urlencode "interval.startTime=${start_time}" \
    --data-urlencode "interval.endTime=${end_time}" 2>/dev/null)"
  curl_rc=$?
  set -e

  if [[ $curl_rc -ne 0 || -z "$ts_raw" ]]; then
    error "Cloud Monitoring read-back FAILED: projects.timeSeries.list HTTP request failed (rc=${curl_rc})."
    return 1
  fi

  local series_count=""
  if ! series_count="$(printf '%s' "$ts_raw" | python3 -c '
import json
import sys

try:
    payload = json.load(sys.stdin)
except Exception as exc:
    print(f"invalid JSON from Cloud Monitoring timeSeries.list: {exc}", file=sys.stderr)
    sys.exit(1)

series = payload.get("timeSeries") if isinstance(payload, dict) else None
if not isinstance(series, list) or len(series) == 0:
    print("0 timeSeries returned for prometheus.googleapis.com/cage_* over the last 30 minutes", file=sys.stderr)
    sys.exit(1)

print(len(series))
'
  )"; then
    error "Cloud Monitoring read-back FAILED: zero prometheus.googleapis.com/cage_* timeSeries observed."
    return 1
  fi

  success "Cloud Monitoring read-back passed: ${series_count} prometheus.googleapis.com/cage_* timeSeries active."
  return 0
}

has_gate_failures() {
  if [[ "$READINESS_FAILED" == "true" ]] || \
     [[ $DRIFT_FAILURES -gt 0 ]] || \
     [[ $LULA_FAILURES -gt 0 ]] || \
     [[ $POSTURE_FAILURES -gt 0 ]] || \
     [[ $SWEEP_FAILURES -gt 0 ]] || \
     [[ $TELEMETRY_FAILURES -gt 0 ]] || \
     [[ $REBUILD_FAILURES -gt 0 ]]; then
    return 0
  fi
  return 1
}

check_gate_failures() {
  if has_gate_failures; then
    error "Staging lifecycle gate FAILED (drift_failures=${DRIFT_FAILURES}, readiness_failed=${READINESS_FAILED}, lula_failures=${LULA_FAILURES}, posture_failures=${POSTURE_FAILURES}, sweep_failures=${SWEEP_FAILURES}, telemetry_failures=${TELEMETRY_FAILURES}, rebuild_failures=${REBUILD_FAILURES})."
    return 1
  fi
  return 0
}

# ─── Phase 0 (Optional): Fresh-Project Bootstrap ──────────────────────────────
if [[ "$FRESH_PROJECT" == "true" ]]; then
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║  Phase 0: Fresh-project bootstrap (${PROJECT_ID})                ║${RESET}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    info "Creating GCP project '$PROJECT_ID'..."
    gcloud projects create "$PROJECT_ID" --name="CAGE Ephemeral Staging" --quiet
  fi

  if [[ -n "$BILLING_ACCOUNT_ID" ]]; then
    info "Linking billing account '$BILLING_ACCOUNT_ID' to '$PROJECT_ID'..."
    gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT_ID" --quiet
  fi

  info "Running clean-project bootstrap script..."
  bash "$REPO_ROOT/scripts/bootstrap_gcp_project.sh" \
    --project="$PROJECT_ID" \
    --env="staging" \
    --region="$REGION"
fi

# PF5: Ensure control-plane authorized_networks is populated so staging compliance
# posture (enable_private_nodes=true) does not fail plan or lock out kubectl/helm.
if [[ -z "${TF_VAR_authorized_networks:-}" ]]; then
  EGRESS_IP="${DEPLOYER_EGRESS_IP:-}"
  if [[ -z "$EGRESS_IP" ]]; then
    EGRESS_IP="$(curl -fsSL --max-time 5 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
  fi
  if [[ -n "$EGRESS_IP" ]]; then
    export TF_VAR_authorized_networks="[{\"cidr\":\"${EGRESS_IP}/32\",\"display_name\":\"deployer-egress\"}]"
    info "Configured TF_VAR_authorized_networks for deployer egress (${EGRESS_IP}/32)"
  fi
fi

# ─── Phase 1: Provision + Zero-Drift Read-Back ────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 1: Provisioning staging + zero-drift read-back            ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

info "Deploying staging with full security posture..."
if ! "$REPO_ROOT/deploy_all.sh" --target gcp-gke --env staging --auto-approve; then
  error "Staging provision failed. Check Terraform output above."
  exit 1
fi

success "Staging environment provisioned successfully"

if ! run_zero_drift_plan "Phase 1"; then
  ((DRIFT_FAILURES++)) || true
  READINESS_FAILED=true
  error "Post-apply zero-drift check FAILED — skipping validation phases and proceeding to teardown."
fi

# ─── Phase 2: Dynamic Workload Readiness & restartCount == 0 (FAIL CLOSED) ───
if [[ "$DRIFT_FAILURES" -eq 0 ]]; then
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║  Phase 2: Dynamic workload readiness & zero-restart verification ║${RESET}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  info "Fetching kubectl credentials for cage-staging..."
  gcloud container clusters get-credentials cage-staging \
    --zone="$ZONE" \
    --project="$PROJECT_ID"

  info "Waiting for all pods in ${NAMESPACE} to be Ready (timeout: 5 minutes)..."
  if ! kubectl wait --for=condition=Ready pods --all \
    -n "$NAMESPACE" \
    --timeout=300s; then
    error "Timed out waiting for pods in ${NAMESPACE} to become Ready."
    kubectl get pods -n "$NAMESPACE" || true
    READINESS_FAILED=true
  fi

  info "Dynamically enumerating Deployment and StatefulSet workloads in ${NAMESPACE}..."
  workloads_json="$(kubectl get deploy,sts -n "$NAMESPACE" -o json 2>/dev/null || echo "")"
  discovered_workloads=""
  if ! discovered_workloads="$(printf '%s' "$workloads_json" | python3 -c '
import json
import sys

try:
    doc = json.load(sys.stdin)
except Exception as exc:
    print(f"Workload readiness check failed: invalid JSON from kubectl get deploy,sts: {exc}", file=sys.stderr)
    sys.exit(1)

items = doc.get("items") if isinstance(doc, dict) else None
if not isinstance(items, list) or len(items) == 0:
    print("Workload readiness check failed: zero Deployment/StatefulSet workloads found in namespace.", file=sys.stderr)
    sys.exit(1)

seen = set()
refs = []
errors = []
for item in items:
    if not isinstance(item, dict):
        continue
    kind = str(item.get("kind", "")).strip().lower()
    name = str((item.get("metadata") or {}).get("name", "")).strip()
    if kind not in {"deployment", "statefulset"} or not name:
        continue
    ref = f"{kind}/{name}"
    seen.add(ref)
    spec_replicas = (item.get("spec") or {}).get("replicas")
    desired = 1 if spec_replicas is None else int(spec_replicas)
    ready_raw = (item.get("status") or {}).get("readyReplicas", 0)
    ready = int(ready_raw or 0)
    is_core = ref in {"deployment/gateway", "deployment/compliance-bridge"}
    if is_core and desired < 1:
        errors.append(
            f"Workload readiness check failed: core workload {ref} has spec.replicas={desired} (expected >= 1)."
        )
    if desired > 0:
        refs.append(ref)
        if ready < 1 or ready < desired:
            errors.append(
                f"Workload readiness check failed: {ref} has readyReplicas={ready} (expected >= {desired})."
            )

for core in ("deployment/gateway", "deployment/compliance-bridge"):
    if core not in seen:
        errors.append(f"Workload readiness check failed: core workload {core} missing from namespace.")

if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(1)

for ref in refs:
    print(ref)
'
  )"; then
    READINESS_FAILED=true
  else
    while IFS= read -r workload_ref; do
      [[ -z "$workload_ref" ]] && continue
      if ! kubectl rollout status "$workload_ref" -n "$NAMESPACE" --timeout=120s >/dev/null; then
        error "Workload readiness check failed: rollout status failed for ${workload_ref}."
        READINESS_FAILED=true
      fi
    done <<< "$discovered_workloads"
  fi

  info "Verifying CronJob/lula-audit exists and is active (.spec.suspend != true)..."
  cronjob_json="$(kubectl get cronjob lula-audit -n "$NAMESPACE" -o json 2>/dev/null || echo "")"
  if ! printf '%s' "$cronjob_json" | python3 -c '
import json
import sys

try:
    doc = json.load(sys.stdin)
except Exception as exc:
    print(f"Workload readiness check failed: CronJob/lula-audit missing or unreadable ({exc}).", file=sys.stderr)
    sys.exit(1)

name = str((doc.get("metadata") or {}).get("name", ""))
suspend = (doc.get("spec") or {}).get("suspend", False)
if name != "lula-audit":
    print("Workload readiness check failed: CronJob/lula-audit not found.", file=sys.stderr)
    sys.exit(1)
if suspend is True:
    print("Workload readiness check failed: CronJob/lula-audit has .spec.suspend=true.", file=sys.stderr)
    sys.exit(1)
'; then
    READINESS_FAILED=true
  fi

  info "Verifying restartCount == 0 across all containers and initContainers in ${NAMESPACE}..."
  pods_json="$(kubectl get pods -n "$NAMESPACE" -o json 2>/dev/null || echo "")"
  if ! printf '%s' "$pods_json" | python3 -c '
import json
import sys

try:
    doc = json.load(sys.stdin)
except Exception as exc:
    print(f"Pod restart check failed: invalid JSON from kubectl get pods: {exc}", file=sys.stderr)
    sys.exit(1)

items = doc.get("items") if isinstance(doc, dict) else None
if not isinstance(items, list) or len(items) == 0:
    print("Pod restart check failed: zero pods returned in namespace.", file=sys.stderr)
    sys.exit(1)

errors = []
for pod in items:
    if not isinstance(pod, dict):
        continue
    pod_name = str((pod.get("metadata") or {}).get("name", "<unknown>"))
    status = pod.get("status") or {}
    phase = str(status.get("phase", ""))
    c_statuses = list(status.get("initContainerStatuses") or []) + list(status.get("containerStatuses") or [])
    if phase != "Succeeded" and len(c_statuses) == 0:
        errors.append(f"Pod restart check failed: pod/{pod_name} reported zero containerStatuses.")
    for cs in c_statuses:
        if not isinstance(cs, dict):
            continue
        cname = str(cs.get("name", "<unknown>"))
        restarts = int(cs.get("restartCount", 0) or 0)
        if restarts != 0:
            errors.append(
                f"Pod restart check failed: pod/{pod_name} container/{cname} has restartCount={restarts} (expected 0)."
            )

if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(1)
'; then
    READINESS_FAILED=true
  fi

  if [[ "$READINESS_FAILED" == "false" ]]; then
    success "Cluster, dynamic workloads, CronJob/lula-audit, and zero-restart checks passed"
  else
    error "Cluster readiness gate FAILED — skipping validation phases and proceeding to teardown."
  fi
fi

# ─── Phase 3: Host + In-Cluster Lula Validation (FAIL CLOSED) ────────────────
if [[ "$READINESS_FAILED" == "false" ]]; then
  if [[ "$SKIP_LULA" == "false" ]]; then
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║  Phase 3: Host + In-Cluster Job/lula-gate-w Lula validation      ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    info "Scanning compliance/lula/lula-validation-*.yaml..."
    shopt -s nullglob
    validation_files=("$REPO_ROOT"/compliance/lula/lula-validation-*.yaml)
    shopt -u nullglob

    verify_lula_assessment_file() {
      local file="$1"
      local label="$2"
      if [[ ! -s "$file" ]]; then
        error "Lula assessment results missing or empty for ${label}: ${file}"
        return 1
      fi
      if ! grep -Eq "observations:" "$file" || grep -Eq "observations:[[:space:]]*\[\]" "$file"; then
        error "Lula assessment results for ${label} contain 0 observations"
        return 1
      fi
      if ! grep -Eq "(relevant-evidence|Result:[[:space:]]*satisfied|state:[[:space:]]*satisfied)" "$file"; then
        error "Lula assessment results for ${label} contain 0 satisfied observations/findings"
        return 1
      fi
      if grep -Eq "(state:[[:space:]]*not-satisfied|Result:[[:space:]]*not-satisfied|lula-validation-error)" "$file"; then
        error "Lula assessment results for ${label} contain not-satisfied or lula-validation-error state"
        return 1
      fi
      return 0
    }

    planned_specs=()
    api_specs=()
    evaluated_count=0

    if [[ ${#validation_files[@]} -eq 0 ]]; then
      error "No Lula validation files found in compliance/lula/"
      ((LULA_FAILURES++)) || true
    else
      assessment_out="$REPO_ROOT/compliance/lula/assessment-results.yaml"
      for validation_file in "${validation_files[@]}"; do
        base_name="$(basename "$validation_file")"
        if grep -Eq '^#[[:space:]]*cage-status:[[:space:]]*planned([[:space:]]|$)' "$validation_file"; then
          planned_specs+=("$base_name")
          continue
        fi
        if grep -Eq '^[[:space:]]*type:[[:space:]]*api([[:space:]]|$)' "$validation_file"; then
          api_specs+=("$base_name")
          info "Deferring in-cluster API-domain Lula spec to Job/lula-gate-w: ${base_name}"
          continue
        fi
        info "Validating host Kubernetes-domain spec: ${base_name}"
        ((evaluated_count++)) || true
        rm -f "$assessment_out"
        if ! lula validate -f "$validation_file" -o "$assessment_out"; then
          error "Lula validation failed: ${base_name}"
          ((LULA_FAILURES++)) || true
        elif ! verify_lula_assessment_file "$assessment_out" "${base_name}"; then
          error "Lula validation verdict not-satisfied or 0 observations: ${base_name}"
          ((LULA_FAILURES++)) || true
        fi
      done

      info "Planned Lula specs skipped (${#planned_specs[@]}): ${planned_specs[*]:-none}"
      for planned_spec in "${planned_specs[@]}"; do
        info "  [planned] ${planned_spec}"
      done

      if [[ $evaluated_count -eq 0 ]]; then
        error "Zero active Kubernetes-domain Lula validation files were evaluated on host"
        ((LULA_FAILURES++)) || true
      fi
    fi

    info "Running in-cluster auditor Job/lula-gate-w from CronJob/lula-audit..."
    kubectl delete job lula-gate-w -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
    if ! kubectl create job lula-gate-w --from=cronjob/lula-audit -n "$NAMESPACE"; then
      error "Failed to create Job/lula-gate-w from CronJob/lula-audit"
      ((LULA_FAILURES++)) || true
    elif ! kubectl wait --for=condition=complete job/lula-gate-w -n "$NAMESPACE" --timeout=300s; then
      error "Job/lula-gate-w did not reach condition=complete within 300s"
      kubectl logs job/lula-gate-w -n "$NAMESPACE" --all-containers=true >&2 || true
      ((LULA_FAILURES++)) || true
    else
      job_pods_json="$(kubectl get pods -n "$NAMESPACE" -l job-name=lula-gate-w -o json 2>/dev/null || echo "")"
      if ! printf '%s' "$job_pods_json" | python3 -c '
import json
import sys

try:
    doc = json.load(sys.stdin)
except Exception as exc:
    print(f"Job/lula-gate-w pod status unreadable: {exc}", file=sys.stderr)
    sys.exit(1)

items = doc.get("items") if isinstance(doc, dict) else None
if not isinstance(items, list) or len(items) == 0:
    print("Job/lula-gate-w returned zero pods.", file=sys.stderr)
    sys.exit(1)

saw_auditor_exit_zero = False
errors = []
for pod in items:
    pod_name = str((pod.get("metadata") or {}).get("name", "<unknown>"))
    status_obj = pod.get("status") or {}
    for init_cs in status_obj.get("initContainerStatuses") or []:
        icname = str(init_cs.get("name", ""))
        iterm = (init_cs.get("state") or {}).get("terminated")
        if isinstance(iterm, dict) and int(iterm.get("exitCode", -1)) != 0:
            errors.append(
                f"Job/lula-gate-w pod/{pod_name} initContainer/{icname} exited {int(iterm.get('exitCode', -1))}"
            )
    statuses = status_obj.get("containerStatuses") or []
    for cs in statuses:
        cname = str(cs.get("name", ""))
        term = (cs.get("state") or {}).get("terminated")
        if isinstance(term, dict):
            rc = int(term.get("exitCode", -1))
            if rc != 0:
                errors.append(f"Job/lula-gate-w pod/{pod_name} container/{cname} exited {rc}")
            elif cname != "linkerd-proxy":
                saw_auditor_exit_zero = True

if not saw_auditor_exit_zero:
    errors.append("Job/lula-gate-w had no terminated auditor container with exitCode=0")

if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(1)
'; then
        error "Job/lula-gate-w container exit status check FAILED"
        ((LULA_FAILURES++)) || true
      fi

      job_logs="$(kubectl logs job/lula-gate-w -n "$NAMESPACE" --all-containers=true 2>&1 || echo "")"
      if ! printf '%s' "$job_logs" | python3 -c '
import re
import sys

logs = sys.stdin.read()
if not logs.strip():
    print("Job/lula-gate-w produced empty logs.", file=sys.stderr)
    sys.exit(1)

if "/v1/oscal/assessment-results" in logs:
    print("Job/lula-gate-w referenced metrics-derived /v1/oscal/assessment-results instead of Lula assessment-results.", file=sys.stderr)
    sys.exit(1)

if re.search(r"(?:state|Result)\s*:\s*not-satisfied|lula-validation-error", logs):
    print("Job/lula-gate-w Lula assessment-results reported not-satisfied or lula-validation-error.", file=sys.stderr)
    sys.exit(1)

if re.search(r"\bnot[-_]satisfied\s*[:=]\s*[1-9]\d*|\b[1-9]\d*\s+not[-_]satisfied\b", logs, re.IGNORECASE):
    print("Job/lula-gate-w reported non-zero not-satisfied controls.", file=sys.stderr)
    sys.exit(1)

if not re.search(r"\b(?:assessment-results|satisfied|observations)\b", logs):
    print("Job/lula-gate-w logs lack Lula assessment-results evaluation proof.", file=sys.stderr)
    sys.exit(1)

has_custody_ack = bool(
    re.search(r"\"status\"\s*:\s*\"INGESTED\"|\bstatus\s*[=:]\s*INGESTED\b", logs)
    or re.search(r"\"record_hash\"\s*:\s*\"[0-9a-f]{64}\"|\brecord_hash\s*[=:]\s*[0-9a-f]{64}\b", logs)
    or re.search(r"/v1/infra/events.*\b(?:200|201|202|INGESTED)\b|\bHTTP[/ ]1\.[01]\"?\s+(?:200|201|202)\b", logs)
)
if not has_custody_ack:
    print("Job/lula-gate-w logs lack /v1/infra/events custody receipt acknowledgment.", file=sys.stderr)
    sys.exit(1)
'; then
        error "Job/lula-gate-w log & /v1/infra/events receipt verification FAILED"
        ((LULA_FAILURES++)) || true
      elif ! verify_worm_evidence_chain "Phase 3 Job/lula-gate-w WORM custody"; then
        error "Job/lula-gate-w WORM custody verification FAILED"
        ((LULA_FAILURES++)) || true
      fi
    fi

    if [[ $LULA_FAILURES -eq 0 ]]; then
      success "Host (${evaluated_count} specs) and in-cluster Job/lula-gate-w Lula validation gates passed"
    else
      error "$LULA_FAILURES Lula validation check(s) failed"
      error "POAM-024 is NOT satisfied — security posture incomplete"
    fi
  else
    warn "Lula validation skipped (--skip-lula flag)"
  fi

  if [[ "$SKIP_POSTURE" == "false" || "$SKIP_LIVE_SWEEP" == "false" ]]; then
    start_staging_port_forward
  fi

  # ─── Phase 4: Region Posture, Live Residency & Live Langfuse (FAIL CLOSED) ─
  if [[ "$SKIP_POSTURE" == "false" ]]; then
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║  Phase 4: Region posture, live residency & Langfuse isolation    ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    info "Running US_FED posture tests..."
    if ! run_pytest_require_passed "US_FED posture tests" \
      env CAGE_DEPLOYMENT_REGION=US_FED uv run pytest "$REPO_ROOT/tests/" -m us_fed -v --tb=short; then
      ((POSTURE_FAILURES++)) || true
    fi

    info "Running EU_ECB posture tests..."
    if ! run_pytest_require_passed "EU_ECB posture tests" \
      env CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest "$REPO_ROOT/tests/" -m eu_ecb -v --tb=short; then
      ((POSTURE_FAILURES++)) || true
    fi

    info "Running APAC_MAS posture tests..."
    if ! run_pytest_require_passed "APAC_MAS posture tests" \
      env CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest "$REPO_ROOT/tests/" -m apac_mas -v --tb=short; then
      ((POSTURE_FAILURES++)) || true
    fi

    info "Running live data-residency verification (test_data_residency.py --run-integration)..."
    if ! run_pytest_require_passed "Live data-residency tests" \
      env -u CAGE_DEPLOYMENT_REGION uv run pytest "$REPO_ROOT/tests/infrastructure/test_data_residency.py" --run-integration -v --tb=short; then
      ((POSTURE_FAILURES++)) || true
    fi

    info "Running live Langfuse posture isolation check (--posture staging)..."
    if ! env \
      GOOGLE_CLOUD_PROJECT="$PROJECT_ID" \
      GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-$REGION}" \
      LANGFUSE_HOST="${LANGFUSE_HOST:-http://localhost:3000}" \
      LANGFUSE_COMPLIANCE_HOST="${LANGFUSE_COMPLIANCE_HOST:-http://localhost:3001}" \
      uv run python "$REPO_ROOT/scripts/verify_langfuse_posture.py" --posture staging; then
      error "Live Langfuse posture isolation check (--posture staging) FAILED"
      ((POSTURE_FAILURES++)) || true
    fi

    if [[ $POSTURE_FAILURES -eq 0 ]]; then
      success "Region posture, live data-residency, and Langfuse isolation validation complete"
    else
      error "$POSTURE_FAILURES posture check(s) failed"
    fi
  else
    warn "Region posture tests skipped (--skip-posture flag)"
  fi

  # ─── Phase 5: Pre-Teardown Live Sweep, GMP Telemetry & WORM Custody ─────────
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║  Phase 5: Live sweeps, GMP telemetry, WORM custody & AS-6 hook   ║${RESET}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  if [[ "$SKIP_LIVE_SWEEP" == "false" ]]; then
    info "Running full live_external sweep (-m live_external --run-live-external)..."
    if ! run_pytest_require_passed "Phase 5 live_external sweep" \
      uv run pytest "$REPO_ROOT/tests/" -m live_external --run-live-external -v --tb=short; then
      ((SWEEP_FAILURES++)) || true
    fi

    info "Running full integration sweep (-m integration --run-integration)..."
    if ! run_pytest_require_passed "Phase 5 integration sweep" \
      env -u CAGE_DEPLOYMENT_REGION uv run pytest "$REPO_ROOT/tests/" -m integration --run-integration -v --tb=short; then
      ((SWEEP_FAILURES++)) || true
    fi

    info "Running live partner conformance sweep (-m partner_integration --run-partner-integration)..."
    if ! run_pytest_require_passed "Phase 5 partner conformance sweep" \
      uv run pytest "$REPO_ROOT/tests/" -m partner_integration --run-partner-integration -p tests.fixtures.require_live -n 0 -v --tb=short; then
      ((SWEEP_FAILURES++)) || true
    fi
  else
    warn "Phase 5 live test sweeps skipped (--skip-live-sweep flag)"
  fi

  if [[ "$SKIP_TELEMETRY" == "false" ]]; then
    if ! verify_gmp_timeseries; then
      ((TELEMETRY_FAILURES++)) || true
    fi

    if ! verify_worm_evidence_chain "Phase 5 pre-teardown archive"; then
      ((TELEMETRY_FAILURES++)) || true
    fi

    AUDIT_CORROBORATION_SCRIPT="${CAGE_AUDIT_CORROBORATION_SCRIPT:-$REPO_ROOT/scripts/verify_audit_corroboration.py}"
    if [[ -f "$AUDIT_CORROBORATION_SCRIPT" ]]; then
      info "Running Cloud Audit Log corroboration hook (${AUDIT_CORROBORATION_SCRIPT})..."
      if ! uv run python "$AUDIT_CORROBORATION_SCRIPT" --project "$PROJECT_ID"; then
        error "Cloud Audit Log corroboration hook FAILED: ${AUDIT_CORROBORATION_SCRIPT}"
        ((TELEMETRY_FAILURES++)) || true
      else
        success "Cloud Audit Log corroboration hook passed"
      fi
    else
      # AS-6: Phase 5 Cloud Audit Log corroboration is mandatory alongside /v1/evidence/verify
      error "Required AS-6 Cloud Audit Log corroboration script missing: ${AUDIT_CORROBORATION_SCRIPT}"
      error "Ensure scripts/verify_audit_corroboration.py is present in REPO_ROOT"
      ((TELEMETRY_FAILURES++)) || true
    fi
  else
    warn "Phase 5 GMP telemetry & WORM verification skipped (--skip-telemetry flag)"
  fi

  info "Checking Binary Authorization enforcement..."
  if kubectl get deploy -n "$NAMESPACE" -o json | \
     jq -e '.items[].spec.template.metadata.annotations["image-policy.k8s.io/breakglass"]' > /dev/null 2>&1; then
    success "Binary Authorization annotations present on deployments"
  else
    warn "Binary Authorization annotations not detected (may be expected if disabled)"
  fi

  info "Checking Pod Security Standards admission..."
  if kubectl get ns "$NAMESPACE" -o json | \
     jq -e '.metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"' > /dev/null 2>&1; then
    success "Pod Security Standards set to 'restricted' on ${NAMESPACE} namespace"
  else
    warn "Pod Security Standards label not found on ${NAMESPACE} namespace"
  fi
fi

stop_staging_port_forward

# ─── Phase 6: Teardown, --import-state Rebuild & Survivor Verification ────────
if [[ "$NO_DESTROY" == "true" ]]; then
  echo ""
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${YELLOW}║  Staging environment left running (--no-destroy flag)             ║${RESET}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  check_gate_failures
  exit 0
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 6: Teardown, --import-state rebuild & survivor check       ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

PERSISTENT_KMS_STATE_ADDRS=(
  "google_kms_crypto_key_iam_policy.signing_key"
  "google_kms_crypto_key.gateway_seal"
  "google_kms_crypto_key.reconciler_snapshot"
  "google_kms_crypto_key.compliance_evidence"
  "google_kms_crypto_key.benchmark_signing"
  "google_kms_crypto_key.binauthz_attestor"
  "google_kms_key_ring.signing"
  "module.kms" "module.evidence_domain" "module.worm_bucket"
)

detach_persistent_kms_state() {
  # PF8: GCP KMS keyrings and keys cannot be deleted and carry lifecycle.prevent_destroy = true
  # in kms_signing.tf (and destroying a CryptoKey destroys cryptoKeyVersions/1, which is
  # pinned by perimeter.tf and kms_signing.tf). Detach them from Terraform state prior to
  # `terraform destroy`; scripts/bootstrap_gcp_project.sh --import-state re-imports them on
  # the rebuild or next lifecycle run.
  info "Detaching persistent KMS keyrings and signing keys from Terraform state before destroy (PF8)..."
  for kms_addr in "${PERSISTENT_KMS_STATE_ADDRS[@]}"; do
    terraform -chdir="$TF_DIR" state rm "$kms_addr" >/dev/null 2>&1 || true
  done
}

run_terraform_destroy() {
  local label="$1"
  build_tf_var_args
  local destroy_args=(
    # POAM-2026-130: enable_nist_compliance removed; staging.tfvars sets environment="staging"
    "-var-file=staging.tfvars"
    "-auto-approve"
    "-var=project_id=${PROJECT_ID}"
    "-var=region=${REGION}"
    "-var=cage_deployment_region=${CAGE_DEPLOYMENT_REGION:-US_FED}"
  )
  if [[ -n "$DIGESTS_FILE" ]]; then
    destroy_args+=("-var-file=${DIGESTS_FILE}")
  fi

  info "Destroying staging cluster (${label}, enable_deletion_protection=false)..."
  if ! terraform -chdir="$TF_DIR" destroy "${destroy_args[@]}"; then
    error "Staging teardown FAILED (${label}). Manual cleanup required in $TF_DIR"
    exit 1
  fi
  success "Staging environment destroyed successfully (${label})"
}

detach_persistent_kms_state
run_terraform_destroy "initial teardown"

if ! has_gate_failures && [[ "$SKIP_REBUILD" == "false" ]]; then
  info "Stage 4: Re-importing foundational resources via bootstrap_gcp_project.sh --import-state..."
  if ! bash "$REPO_ROOT/scripts/bootstrap_gcp_project.sh" \
    --project="$PROJECT_ID" \
    --env="staging" \
    --region="$REGION" \
    --tf-dir="$TF_DIR" \
    --import-state; then
    error "Stage 4 (--import-state) FAILED."
    ((REBUILD_FAILURES++)) || true
  else
    success "Stage 4 (--import-state) completed."
    info "Stage 5: Running clean rebuild from imported foundational state..."
    if ! env SKIP_BUILD=true BOOTSTRAP_IMPORT_STATE=true \
      "$REPO_ROOT/deploy_all.sh" --target gcp-gke --env staging --auto-approve; then
      error "Stage 5 clean rebuild FAILED."
      ((REBUILD_FAILURES++)) || true
    elif ! run_zero_drift_plan "Stage 5 rebuild"; then
      error "Stage 5 post-rebuild zero-drift verification FAILED."
      ((REBUILD_FAILURES++)) || true
    else
      success "Stage 5 clean rebuild and zero-drift read-back passed."
    fi

    info "Stage 6: Running final teardown after rebuild verification..."
    detach_persistent_kms_state
    run_terraform_destroy "post-rebuild final teardown"
  fi
elif [[ "$SKIP_REBUILD" == "true" ]]; then
  warn "Phase 6 Stages 4–5 (--import-state + clean rebuild) skipped (--skip-rebuild flag)"
else
  warn "Skipping Phase 6 rebuild cycle due to earlier gate failure(s); initial teardown complete."
fi

# PF9: In --fresh-project mode, verify that no workload resources or deletion liens
# survived `terraform destroy` (confirming POAM-2026-159 bucket teardown and clean
# project deletion readiness).
if [[ "$FRESH_PROJECT" == "true" ]]; then
  info "Verifying zero surviving workload resources or deletion liens in '$PROJECT_ID'..."
  SURVIVORS=0

  remaining_clusters="$(gcloud container clusters list --project="$PROJECT_ID" --format='value(name)' 2>/dev/null || true)"
  if [[ -n "$remaining_clusters" ]]; then
    error "Surviving GKE cluster(s) after destroy: $remaining_clusters"
    ((SURVIVORS++)) || true
  fi

  remaining_sql="$(gcloud sql instances list --project="$PROJECT_ID" --format='value(name)' 2>/dev/null || true)"
  if [[ -n "$remaining_sql" ]]; then
    error "Surviving Cloud SQL instance(s) after destroy: $remaining_sql"
    ((SURVIVORS++)) || true
  fi

  remaining_buckets="$(gcloud storage buckets list --project="$PROJECT_ID" --format='value(name)' 2>/dev/null | grep -Ev "^(${PROJECT_ID}-tfstate|${PROJECT_ID}_cloudbuild)$" || true)"
  has_retained_worm_buckets=false
  if printf '%s\n' "$remaining_buckets" | grep -Eq "^(${PROJECT_ID}-evidence-worm-staging|${PROJECT_ID}-audit-logs-worm-staging)$"; then
    info "PF9 persistent evidence-domain WORM bucket(s) retained by design (F-66 / F-94): $(printf '%s\n' "$remaining_buckets" | grep -E "^(${PROJECT_ID}-evidence-worm-staging|${PROJECT_ID}-audit-logs-worm-staging)$" | tr '\n' ' ')"
    remaining_buckets="$(printf '%s\n' "$remaining_buckets" | grep -Ev "^(${PROJECT_ID}-evidence-worm-staging|${PROJECT_ID}-audit-logs-worm-staging)$" || true)"
    has_retained_worm_buckets=true
  fi
  if [[ "$ALLOW_LEGACY_LIEN_SURVIVOR" == "true" && "$remaining_buckets" == *"langfuse-events-"* ]]; then
    info "PF9 explicit known survivor (F-95 Decision 6, 2033-09-27 retention lock): $(printf '%s\n' "$remaining_buckets" | grep -E '^langfuse-events-' || true)"
    remaining_buckets="$(printf '%s\n' "$remaining_buckets" | grep -Ev '^langfuse-events-' || true)"
  fi
  if [[ -n "$remaining_buckets" ]]; then
    error "Surviving workload GCS bucket(s) after destroy: $remaining_buckets"
    ((SURVIVORS++)) || true
  fi

  # Unexcused liens require explicit `gcloud alpha resource-manager liens delete` before project deletion.
  remaining_liens="$(gcloud alpha resource-manager liens list --project="$PROJECT_ID" --format='value(name,restrictions)' 2>/dev/null || true)"
  if [[ ( "$has_retained_worm_buckets" == "true" || "$ALLOW_LEGACY_LIEN_SURVIVOR" == "true" ) && "$remaining_liens" == *"storage.googleapis.com"* ]]; then
    info "PF9 explicit known storage retention lien survivor (F-66 / F-95): $remaining_liens"
    remaining_liens="$(printf '%s\n' "$remaining_liens" | grep -Ev 'storage\.googleapis\.com' || true)"
  fi
  if [[ -n "$remaining_liens" ]]; then
    error "Surviving project deletion lien(s) after destroy: $remaining_liens"
    ((SURVIVORS++)) || true
  fi

  if [[ $SURVIVORS -gt 0 ]]; then
    error "Fresh-project post-destroy cleanliness verification FAILED ($SURVIVORS survivor category(s))."
    exit 1
  fi
  success "Fresh-project post-destroy verification passed (zero workload survivors or deletion liens)"
fi

check_gate_failures

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║  ✅  Staging lifecycle Gate W complete                            ║${RESET}"
echo -e "${GREEN}║                                                                   ║${RESET}"
echo -e "${GREEN}║  POAM-024 / POAM-2026-131 / POAM-2026-159 / POAM-2026-164:        ║${RESET}"
echo -e "${GREEN}║    ✅  Zero post-apply Terraform drift                            ║${RESET}"
echo -e "${GREEN}║    ✅  All governance-stack workloads Ready with 0 restarts       ║${RESET}"
if [[ "$SKIP_LULA" == "false" ]]; then
  echo -e "${GREEN}║    ✅  Host + in-cluster Job/lula-gate-w Lula gates passed        ║${RESET}"
fi
if [[ "$SKIP_POSTURE" == "false" ]]; then
  echo -e "${GREEN}║    ✅  Regional posture, residency & Langfuse isolation passed    ║${RESET}"
fi
if [[ "$SKIP_LIVE_SWEEP" == "false" ]]; then
  echo -e "${GREEN}║    ✅  Live external, integration & partner conformance passed    ║${RESET}"
fi
if [[ "$SKIP_TELEMETRY" == "false" ]]; then
  echo -e "${GREEN}║    ✅  GMP, WORM /v1/evidence/verify & KMS audit logs passed      ║${RESET}"
fi
echo -e "${GREEN}║    ✅  Ephemeral staging cluster destroyed cleanly                ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
