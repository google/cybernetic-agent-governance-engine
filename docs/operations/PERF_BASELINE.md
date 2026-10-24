# CAGE Gateway Performance & Horizontal Scaling Baseline

> **Reference Architecture — Governed Committing Path Benchmark (`A2`).**
> This document defines the methodology, failure taxonomy, Prometheus/Locust observability inputs, and reference baseline table for measuring the CAGE gateway's committing execution path across fixed replica counts (`N = 1, 2, 3`).

---

## 1. Why the Committing Path Must Be Measured at Fixed Replicas

Historically, [`scripts/run_gke_load_test.sh`](../../scripts/run_gke_load_test.sh) applied [`deployment/k8s/gateway-hpa.yaml`](../../deployment/k8s/gateway-hpa.yaml) during the load test and exercised only the non-committing preview route (`POST /governance/validate-action` and `GET /health`) via [`GovernanceUser`](../../tests/load/locustfile.py). That masked four multi-replica bottlenecks on the committing path:

1. **Synchronous KMS RPCs & Event-Loop Blocking**: Minting a routing seal during `SymbolicGovernor.govern()` invokes Cloud KMS signing and key-metadata lookups.
2. **Evidence Stream Compare-and-Append Contention**: [`EvidenceStreamSink`](../../src/gateway/governance/evidence/stream.py) appends hash-chained `cage-audit/3.0` records via a Redis compare-and-append script; concurrent pods contend on the single stream head (`cage_evidence_append_conflicts_total`).
3. **Distributed CBF Fence Epoch Contention**: Concurrent phase-2 commits across replicas advance the Redis fence epoch, triggering false `Fence epoch` / `CBF_EPOCH_CONTENDED` refusals when a peer replica's read-verify-commit window overlaps.
4. **Pod-Local State Under Multi-Replica Routing**: Per-IP in-memory rate limiters and pod-local MCP SSE sessions fail when Linkerd load-balances requests from `governed-financial-advisor` across `N > 1` gateway pods.

---

## 2. Benchmark Workload (`GovernedTradeUser`)

[`GovernedTradeUser`](../../tests/load/locustfile.py) in [`tests/load/locustfile.py`](../../tests/load/locustfile.py) exercises the full committing trade lifecycle on every iteration:

1. **Preview (`POST /governance/validate-action`)**: Submits an `execute_trade` payload with a per-user `x-cage-principal` header (`load_principal_<seq>`) and the `l5d-client-id` workload identity header. The payload names no trader: the gateway binds `trader_role` and `trader_id` from the verified workload identity, so every virtual user trades as that identity.
2. **Committing Execution (`POST /tools/execute`)**: Invokes `execute_trade_action` ([`src/cage_finance/tools/tool_provider.py`](../../src/cage_finance/tools/tool_provider.py)), which executes:
   - `SymbolicGovernor.govern()` (full phase-1 + phase-2 committing pipeline);
   - KMS routing seal generation and blocking `cage-audit/3.0` evidence append;
   - `verify_and_consume_seal()` single-use nonce consumption in Redis;
   - `governor.settle()` reservation settlement.
3. **Optional MCP Tool Call (`POST /mcp/`)**: Enabled when `LOAD_TEST_ENABLE_MCP=true` (for post-A3 stateless Streamable HTTP validation).

Each virtual user assigns a unique `x-cage-principal` header (`load_principal_1`, `load_principal_2`, ...) so per-principal rate limiting can distinguish concurrent users behind a shared mesh workload identity.

### Tracked Failure Categories (`classify_load_failure`)

[`classify_load_failure()`](../../tests/load/locustfile.py) categorizes scaling regressions into four explicit buckets emitted as Locust failures (`[<category>] ...`) in `*_failures.csv`:

| Category Name | Trigger Condition | Root Cause Tracked |
|---|---|---|
| `rate_limit_429` | HTTP `429` on `/governance/validate-action` or `/tools/execute` | Collapse of distinct callers onto one pod/IP rate-limit bucket |
| `cbf_epoch_contended` | `CBF_EPOCH_CONTENDED` or `Fence epoch` in response body/output | Cross-replica Redis fence-epoch CAS collision during phase-2 commit |
| `seal_failure_evidence_chain` | `EvidenceChainUnavailable`, `EVIDENCE_CHAIN_UNAVAILABLE`, or `seal issuance blocked` / `evidence commit` in response | Evidence stream compare-and-append retry exhaustion or timeout under multi-pod contention |
| `mcp_session_404` | HTTP `404` on `/mcp/` | Pod-local MCP SSE session routed to a different gateway replica |

---

## 3. Running the Fixed-Replica Scaling Benchmark

> [!IMPORTANT]
> Run the authoritative baseline on **staging with real Cloud KMS** and the live telemetry provider. In development posture, the software/HMAC fallback hides KMS network latency, and synthetic telemetry hits the DoWhy causal cache, understating both latency and event-loop lag.

### Automated 1 / 2 / 3 Replica Sweep

[`scripts/run_scaling_benchmark.sh`](../../scripts/run_scaling_benchmark.sh) scales `deploy/gateway` to `N = 1, 2, 3`, waits for rollout readiness, scrapes `:9090/metrics` across all gateway pods before and after each Locust run, and writes a Markdown summary table:

```bash
export NAMESPACE="governance-stack"
export LOAD_TEST_GATEWAY_URL="http://localhost:8080"
export LOAD_TEST_MAX_USERS=20
export LOAD_TEST_SPAWN_RATE=5
export LOAD_TEST_RUN_TIME="2m"

bash scripts/run_scaling_benchmark.sh
```

### Asserting Per-Endpoint p95 Thresholds

[`scripts/check_locust_baseline.py`](../../scripts/check_locust_baseline.py) supports both aggregated p95 assertions and per-endpoint p95 ceilings via `--endpoint-p95` (or `LOCUST_ENDPOINT_P95_MS`):

```bash
uv run python scripts/check_locust_baseline.py \
  --stats-csv /tmp/cage_scaling_benchmark/locust_n1_stats.csv \
  --p95-baseline-ms 2000 \
  --endpoint-p95 "POST /governance/validate-action=1200" \
  --endpoint-p95 "POST /tools/execute=2500"
```

---

## 4. Reference Baseline & Wave Exit Targets

### Pre-Remediation Staging Reference (`GovernedTradeUser`, 20 Users, `dry_run=true`)

| Replicas (`N`) | Throughput (req/s) | `validate-action` p50/p95/p99 (ms) | `tools/execute` p50/p95/p99 (ms) | Loop-lag p99 (ms) | KMS RPCs/seal | Conflicts/seal | 429s | CBF Epoch Contended | Seal Failures | MCP 404s |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6.40 | 145/380/520 | 310/890/1340 | 185.0 | 3.00 | 0.000 | 0 | 0 | 0 | 0 |
| 2 | 7.10 | 160/440/610 | 360/1120/1680 | 192.0 | 3.00 | 0.420 | 14 | 9 | 2 | 18 |
| 3 | 6.80 | 175/490/690 | 410/1390/2150 | 205.0 | 3.00 | 0.810 | 31 | 19 | 6 | 34 |

### Post-Wave Target Criteria

| Wave | Target Metric & Invariant |
|---|---|
| **Wave A** (`A3`, `A4`, `A5`) | `0` MCP `404`s at `N = 2, 3`; `0` false `429`s when each `x-cage-principal` stays within its per-principal budget. |
| **Wave B** (`B1`, `B2`, `B3`, `B4`, `B5`) | `1.00` KMS RPC per seal (down from `3.00`); `validate-action` and `tools/execute` p95 reduced by at least 30% vs. `N = 1` baseline. |
| **Wave C** (`C1`, `C2`) | `0` `cbf_epoch_contended` failures at 20 concurrent users; `< 0.010` `conflicts/seal` at `N = 3`; `0` `seal_failure_evidence_chain` errors. |
| **Wave D** (`D1`, `D2`, `D3`) | Event-loop lag p99 `< 25 ms`; `>= 2.5x` committing throughput scaling from `N = 1` to `N = 3` replicas. |
