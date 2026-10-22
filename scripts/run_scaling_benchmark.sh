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

# run_scaling_benchmark.sh — Fixed-replica committing load benchmark (A2)
#
# For N in 1, 2, 3 (or $REPLICA_COUNTS):
#   1. Scales deploy/gateway to N replicas and waits for rollout readiness.
#   2. Scrapes :9090/metrics across all gateway pods (or $METRICS_URL) before the run.
#   3. Runs Locust headlessly with GovernedTradeUser at fixed load.
#   4. Scrapes :9090/metrics after the run.
#   5. Emits a Markdown report covering throughput, p50/p95/p99 per endpoint,
#      event-loop lag p99, KMS RPCs per seal, evidence conflicts per seal,
#      HTTP 429s, and categorized scaling failures.

set -euo pipefail

NAMESPACE="${NAMESPACE:-governance-stack}"
REPLICA_COUNTS="${REPLICA_COUNTS:-1 2 3}"
MAX_USERS="${LOAD_TEST_MAX_USERS:-20}"
SPAWN_RATE="${LOAD_TEST_SPAWN_RATE:-5}"
RUN_TIME="${LOAD_TEST_RUN_TIME:-2m}"
GATEWAY_URL="${LOAD_TEST_GATEWAY_URL:-http://localhost:8080}"
METRICS_URL="${LOAD_TEST_METRICS_URL:-http://localhost:9090/metrics}"
SKIP_K8S_SCALE="${SKIP_K8S_SCALE:-false}"
OUTPUT_DIR="${SCALING_BENCHMARK_DIR:-${TMPDIR:-/tmp}/cage_scaling_benchmark}"
SUMMARY_MD="${SCALING_SUMMARY_MD:-${OUTPUT_DIR}/scaling_summary.md}"
USER_CLASS="${LOAD_TEST_USER_CLASS:-GovernedTradeUser}"

scrape_gateway_metrics() {
  local out_file="$1"
  : > "${out_file}"

  if [[ "${SKIP_K8S_SCALE}" != "true" ]] && command -v kubectl &>/dev/null; then
    local pod_ips
    pod_ips="$(kubectl get pods -n "${NAMESPACE}" -l app=gateway \
      -o jsonpath='{.items[*].status.podIP}' 2>/dev/null || true)"
    if [[ -n "${pod_ips}" ]]; then
      local ip
      for ip in ${pod_ips}; do
        if curl -fsS --max-time 5 "http://${ip}:9090/metrics" >> "${out_file}" 2>/dev/null; then
          printf '\n' >> "${out_file}"
        fi
      done
      if [[ -s "${out_file}" ]]; then
        return 0
      fi
    fi

    local pod_names
    pod_names="$(kubectl get pods -n "${NAMESPACE}" -l app=gateway \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
    if [[ -n "${pod_names}" ]]; then
      local pod
      for pod in ${pod_names}; do
        if kubectl get --raw "/api/v1/namespaces/${NAMESPACE}/pods/${pod}:9090/proxy/metrics" >> "${out_file}" 2>/dev/null; then
          printf '\n' >> "${out_file}"
        fi
      done
      if [[ -s "${out_file}" ]]; then
        return 0
      fi
    fi
  fi

  if curl -fsS --max-time 5 "${METRICS_URL}" >> "${out_file}" 2>/dev/null; then
    printf '\n' >> "${out_file}"
  fi
}

summarize_replica_run() {
  local replicas="$1"
  local stats_csv="$2"
  local failures_csv="$3"
  local pre_metrics="$4"
  local post_metrics="$5"

  uv run python - "${replicas}" "${stats_csv}" "${failures_csv}" "${pre_metrics}" "${post_metrics}" <<'PYEOF'
import csv
import math
import os
import re
import sys

replicas = sys.argv[1]
stats_csv = sys.argv[2]
failures_csv = sys.argv[3]
pre_path = sys.argv[4]
post_path = sys.argv[5]

SAMPLE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?|[+-]?Inf|NaN)"
)
LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"')


def parse_prom_file(path: str) -> list[tuple[str, dict[str, str], float]]:
    samples: list[tuple[str, dict[str, str], float]] = []
    if not os.path.exists(path):
        return samples
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = SAMPLE_RE.match(line)
            if not m:
                continue
            name, raw_labels, raw_val = m.groups()
            try:
                val = float(raw_val)
            except ValueError:
                continue
            if math.isnan(val):
                continue
            labels = dict(LABEL_RE.findall(raw_labels or ""))
            samples.append((name, labels, val))
    return samples


def sum_metric(
    samples: list[tuple[str, dict[str, str], float]],
    metric_name: str,
    label_filter: dict[str, str] | None = None,
) -> float:
    total = 0.0
    for name, labels, val in samples:
        if name != metric_name:
            continue
        if label_filter and any(labels.get(k) != v for k, v in label_filter.items()):
            continue
        total += val
    return total


def histogram_quantile(
    q: float,
    pre_samples: list[tuple[str, dict[str, str], float]],
    post_samples: list[tuple[str, dict[str, str], float]],
    bucket_metric: str,
) -> float:
    pre_buckets: dict[float, float] = {}
    post_buckets: dict[float, float] = {}
    for name, labels, val in pre_samples:
        if name == bucket_metric and "le" in labels:
            le = float("inf") if labels["le"] == "+Inf" else float(labels["le"])
            pre_buckets[le] = pre_buckets.get(le, 0.0) + val
    for name, labels, val in post_samples:
        if name == bucket_metric and "le" in labels:
            le = float("inf") if labels["le"] == "+Inf" else float(labels["le"])
            post_buckets[le] = post_buckets.get(le, 0.0) + val

    deltas: list[tuple[float, float]] = []
    for le in sorted(post_buckets):
        delta = max(0.0, post_buckets[le] - pre_buckets.get(le, 0.0))
        deltas.append((le, delta))

    if not deltas:
        return 0.0
    total = deltas[-1][1]
    if total <= 0.0:
        return 0.0

    rank = q * total
    prev_le = 0.0
    prev_count = 0.0
    for le, count in deltas:
        if math.isinf(le):
            return prev_le
        if count >= rank:
            bucket_count = count - prev_count
            if bucket_count <= 0.0:
                return le
            fraction = (rank - prev_count) / bucket_count
            return prev_le + (le - prev_le) * fraction
        prev_le = le
        prev_count = count
    return prev_le


pre_samples = parse_prom_file(pre_path)
post_samples = parse_prom_file(post_path)

kms_delta = max(
    0.0,
    sum_metric(post_samples, "cage_kms_rpc_total")
    - sum_metric(pre_samples, "cage_kms_rpc_total"),
)
conflicts_delta = max(
    0.0,
    sum_metric(post_samples, "cage_evidence_append_conflicts_total")
    - sum_metric(pre_samples, "cage_evidence_append_conflicts_total"),
)
seals_delta = max(
    0.0,
    sum_metric(post_samples, "cage_evidence_commit_duration_seconds_count")
    - sum_metric(pre_samples, "cage_evidence_commit_duration_seconds_count"),
)
rate_limit_prom_delta = max(
    0.0,
    sum_metric(post_samples, "mcp_rate_limit_hits_total")
    - sum_metric(pre_samples, "mcp_rate_limit_hits_total"),
)
loop_lag_p99_ms = (
    histogram_quantile(
        0.99,
        pre_samples,
        post_samples,
        "cage_event_loop_lag_seconds_bucket",
    )
    * 1000.0
)

rows_by_name: dict[str, dict[str, str]] = {}
if os.path.exists(stats_csv):
    with open(stats_csv, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("Name") or "").strip()
            if name:
                rows_by_name[name] = row


def row_float(row: dict[str, str] | None, *keys: str) -> float:
    if not row:
        return 0.0
    for k in keys:
        if k in row and row[k] not in ("", None):
            try:
                return float(row[k])
            except ValueError:
                pass
    return 0.0


agg = rows_by_name.get("Aggregated")
val_row = rows_by_name.get("POST /governance/validate-action")
exec_row = rows_by_name.get("POST /tools/execute")

exec_reqs = max(0.0, row_float(exec_row, "Request Count") - row_float(exec_row, "Failure Count"))
effective_seals = seals_delta if seals_delta > 0.0 else exec_reqs
kms_per_seal = (kms_delta / effective_seals) if effective_seals > 0.0 else 0.0
conflicts_per_seal = (conflicts_delta / effective_seals) if effective_seals > 0.0 else 0.0

failure_counts = {
    "rate_limit_429": 0,
    "cbf_epoch_contended": 0,
    "seal_failure_evidence_chain": 0,
    "mcp_session_404": 0,
}
if os.path.exists(failures_csv):
    with open(failures_csv, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("Name") or "").strip()
            err = (row.get("Error") or "").strip()
            occ = int(float(row.get("Occurrences") or 0))
            for cat in list(failure_counts):
                if name == cat or f"[{cat}]" in err or cat in err:
                    failure_counts[cat] += occ

total_429s = max(int(rate_limit_prom_delta), failure_counts["rate_limit_429"])

rps = row_float(agg, "Requests/s")
val_p50 = row_float(val_row, "50%", "Median response time")
val_p95 = row_float(val_row, "95%")
val_p99 = row_float(val_row, "99%")
exec_p50 = row_float(exec_row, "50%", "Median response time")
exec_p95 = row_float(exec_row, "95%")
exec_p99 = row_float(exec_row, "99%")

print(
    f"| {replicas} | {rps:.2f} | "
    f"{val_p50:.0f}/{val_p95:.0f}/{val_p99:.0f} | "
    f"{exec_p50:.0f}/{exec_p95:.0f}/{exec_p99:.0f} | "
    f"{loop_lag_p99_ms:.1f} | {kms_per_seal:.2f} | {conflicts_per_seal:.3f} | "
    f"{total_429s} | {failure_counts['cbf_epoch_contended']} | "
    f"{failure_counts['seal_failure_evidence_chain']} | {failure_counts['mcp_session_404']} |"
)
PYEOF
}

run_benchmark() {
  mkdir -p "${OUTPUT_DIR}"

  if ! command -v locust &>/dev/null; then
    echo "Installing locust via uv..."
    uv pip install locust
  fi

  cat > "${SUMMARY_MD}" <<EOF
# CAGE Gateway Horizontal Scaling Benchmark Summary

- **Gateway URL:** \`${GATEWAY_URL}\`
- **User class:** \`${USER_CLASS}\`
- **Virtual users:** \`${MAX_USERS}\` (spawn rate \`${SPAWN_RATE}/s\`, duration \`${RUN_TIME}\`)
- **Replica counts tested:** \`${REPLICA_COUNTS}\`

| Replicas | Throughput (req/s) | validate-action p50/p95/p99 (ms) | tools/execute p50/p95/p99 (ms) | Loop-lag p99 (ms) | KMS RPCs/seal | Conflicts/seal | 429s | CBF Epoch Contended | Seal Failures | MCP 404s |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
EOF

  local n
  for n in ${REPLICA_COUNTS}; do
    echo "=== Scaling deploy/gateway to ${n} replica(s) ==="
    if [[ "${SKIP_K8S_SCALE}" != "true" ]]; then
      kubectl scale deploy/gateway -n "${NAMESPACE}" --replicas="${n}"
      kubectl rollout status deploy/gateway -n "${NAMESPACE}" --timeout=180s
    fi

    local pre_metrics="${OUTPUT_DIR}/metrics_n${n}_pre.prom"
    local post_metrics="${OUTPUT_DIR}/metrics_n${n}_post.prom"
    local csv_prefix="${OUTPUT_DIR}/locust_n${n}"

    scrape_gateway_metrics "${pre_metrics}"

    echo "=== Running Locust (${USER_CLASS}) at N=${n} ==="
    locust -f tests/load/locustfile.py "${USER_CLASS}" \
      --host "${GATEWAY_URL}" \
      --headless \
      --users "${MAX_USERS}" \
      --spawn-rate "${SPAWN_RATE}" \
      --run-time "${RUN_TIME}" \
      --csv "${csv_prefix}" \
      --only-summary

    scrape_gateway_metrics "${post_metrics}"

    summarize_replica_run \
      "${n}" \
      "${csv_prefix}_stats.csv" \
      "${csv_prefix}_failures.csv" \
      "${pre_metrics}" \
      "${post_metrics}" >> "${SUMMARY_MD}"
  done

  echo ""
  cat "${SUMMARY_MD}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  run_benchmark "$@"
fi
