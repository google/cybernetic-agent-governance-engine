# GKE Staging & Live Integration Test Runbook

> **Operational Runbook — Live GKE Cluster Testing, Daemon Port-Forwards, and Staging Lifecycle.**
> This document details the procedures for executing integration tests against a live GKE staging cluster,
> managing background port-forward daemons, and validating the staging lifecycle (POAM-024).
> 
> *For everyday hermetic unit testing and local development, see [`AGENTS.md`](../../AGENTS.md) §11.*

---

## Table of Contents

1. [Cluster Prerequisites & Port-Forward Daemon](#1-cluster-prerequisites--port-forward-daemon)
2. [Forwarded Ports & Invariant Requirements](#2-forwarded-ports--invariant-requirements)
3. [Test Harness Configuration & KMS Signing](#3-test-harness-configuration--kms-signing)
4. [Worker Concurrency Limits on Tunnels](#4-worker-concurrency-limits-on-tunnels)
5. [Canonical Live Test Invocations](#5-canonical-live-test-invocations)
6. [Partner Integration Tests Isolation](#6-partner-integration-tests-isolation)
7. [Langfuse Regional & Local Testing Limitations](#7-langfuse-regional--local-testing-limitations)
8. [Expected Outcomes for GPU-Dependent Tests](#8-expected-outcomes-for-gpu-dependent-tests)
9. [Step-by-Step Staging Smoke & Integration Workflow](#9-step-by-step-staging-smoke--integration-workflow)
10. [Staging Lifecycle Validation (POAM-024 Closure)](#10-staging-lifecycle-validation-poam-024-closure)
11. [Nightly CI Policy](#11-nightly-ci-policy)

---

## 1. Cluster Prerequisites & Port-Forward Daemon

Before running integration tests, verify the `kubectl` context points to the staging cluster (e.g., `cage-staging` in `us-central1-a`) and all non-GPU services are Running:

```bash
kubectl config current-context  # e.g., gke_laah-cybernetics_us-central1-a_cage-staging
kubectl get pods -n governance-stack
```

Start auto-reconnecting tunnels in daemon mode:

```bash
bash scripts/port_forward_staging.sh --daemon
```

Verify port reachability:

```bash
bash scripts/port_forward_staging.sh --status
```

To stop the daemon when finished:

```bash
bash scripts/port_forward_staging.sh --stop
# Or kill any orphaned background processes:
pkill -f "kubectl port-forward"
```

**Port-Forward Features & Inactive GPU Handling:**
- The script checks `kubectl get endpointslice` (`has_endpoints`) and detects whether services have ready endpoints before opening ports.
- **GPU Scaling Invariant**: In staging clusters, the GPU node pool (`gke-gpu-pool`) is typically scaled to 0 replicas to conserve compute costs. The script automatically detects 0 endpoints for `vllm-service` (port `8001`) and `vllm-reasoning` (port `8000`) and skips them, preventing tight reconnect loops from overwhelming the Kubernetes API server.

---

## 2. Forwarded Ports & Invariant Requirements

### Forwarded Localhost Endpoints:
- **Gateway**: `http://localhost:8080` (HTTP/gRPC)
- **Governed Financial Advisor Backend**: `http://localhost:8081` (service port 80)
- **Compliance Bridge**: `http://localhost:3002` (service port 80, container port 3001)
- **Langfuse UI & API**: `http://localhost:3000` / `http://localhost:3001` (service port 3000)
- **OPA Policy Engine**: `http://localhost:8181`
- **Redis**: `localhost:6379`
- **vLLM Fast (Qwen2.5-7B)**: `http://localhost:8001` (and `http://localhost:18081/v1`)
- **vLLM Reasoning (DeepSeek R1)**: `http://localhost:8000` (and `http://localhost:18082/v1`)

### Cluster Invariant Requirements:
- **Compliance Bridge `LANGFUSE_HOST`**: In GKE deployments, `LANGFUSE_HOST` must explicitly declare port `3000` (`http://langfuse-web.governance-stack.svc.cluster.local:3000`), as `langfuse-web` listens on 3000 (not 80). Without `:3000`, metrics and SLA queries time out.
- **Advisor Auth Token**: `CAGE_API_KEY` must match the cluster secret (`cage-staging-test-key` in staging).
- **Local Workstation KMS Mode**: Set `CAGE_ENV=test` on developer workstations when invoking pytest. This allows tests to exercise live GKE services (Redis, OPA, Compliance Bridge, Gateway, Advisor, vLLM) without requiring `cloudkms.cryptoKeyVersions.viewPublicKey` IAM permissions on the local developer's GCP credentials.

---

## 3. Test Harness Configuration & KMS Signing

In staging mode, `SymbolicGovernor` enforces asymmetric Cloud KMS signature verification (`KMS_GOVERNANCE_KEY`). Local workstations running pytest do not possess GKE Workload Identity IAM permissions to sign with Cloud KMS:
- **Client Test Posture**: In `tests/conftest.py`, running client test commands with `CAGE_ENV=test` allows the test harness to use software-backed HMAC/SHA256 signing for local assertions while directing all network requests to live cluster endpoints via localhost tunnels (`BACKEND_URL=http://localhost:8081`, `GATEWAY_URL=http://localhost:8080`, `OPA_URL=http://localhost:8181`, `REDIS_URL=redis://localhost:6379/0`).
- **KMS Public Key Verification**: If verifying Gateway responses signed with the staging KMS key, extract the public key PEM from the running gateway pod:
  ```bash
  kubectl exec -n governance-stack deploy/gateway -c gateway -- cat /tmp/kms_governance_public.pem > /tmp/kms_governance_public.pem
  export KMS_GOVERNANCE_PUBLIC_PEM=/tmp/kms_governance_public.pem
  ```

---

## 4. Worker Concurrency Limits on Tunnels

> [!CRITICAL]
> **Never use `-n auto` against port-forwarded tunnels.**

On multi-core developer workstations, `-n auto` spawns 16+ parallel pytest workers. Hammering localhost port-forward tunnels with 16 concurrent workers floods TCP connection pools, causing connection resets, Redis timeouts, and spurious `503 Service Unavailable` errors from Compliance Bridge.
- Always constrain concurrency to **`-n 2` or `-n 4`** with `--dist loadscope`:
  ```bash
  uv run pytest tests/ -m integration --run-integration -n 2 --dist loadscope
  ```

---

## 5. Canonical Live Test Invocations

### Full Test Suite (Unit + Live Integration):
```bash
source .env && \
export COMPLIANCE_BRIDGE_URL=http://localhost:3002 \
       BACKEND_URL=http://localhost:8081 \
       LANGFUSE_HOST=http://localhost:3001 \
       CAGE_API_KEY=cage-staging-test-key \
       CAGE_ENV=test && \
uv run pytest tests/ --run-integration -n 4 --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
```

### Integration-Marked Tests Only:
```bash
source .env && \
export COMPLIANCE_BRIDGE_URL=http://localhost:3002 \
       BACKEND_URL=http://localhost:8081 \
       LANGFUSE_HOST=http://localhost:3001 \
       CAGE_API_KEY=cage-staging-test-key \
       CAGE_ENV=test && \
uv run pytest tests/ -m integration --run-integration -n 2 --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
```

### Single Integration Test File:
```bash
ENVIRONMENT=integration COMPLIANCE_BRIDGE_URL=http://localhost:3002 \
uv run pytest tests/test_compliance_bridge_integration.py --run-integration -v --tb=short
```

---

## 6. Partner Integration Tests Isolation

External partner integration tests hitting third-party vendor APIs (such as `tests/test_provider_01_live.py`) are tagged with the **`partner_integration`** selection marker (and `live_external`), **NOT** the default `integration` marker:
- Running `uv run pytest tests/ --run-integration` or `-m integration` **excludes** partner tests by default.
- To execute partner integration tests when external sandbox credentials are configured:
  ```bash
  uv run pytest -m partner_integration --run-partner-integration
  # Or with live external flag:
  uv run pytest tests/test_provider_01_live.py --run-live-external
  ```

---

## 7. Langfuse Regional & Local Testing Limitations

`scripts/verify_langfuse_posture.py` validates dual-pipeline telemetry isolation (primary application telemetry vs. compliance audit pipeline). Because CAGE strictly enforces secret hygiene, live credentials are never committed or present in local environments.

### 1. Local Dry-Run Requirements
Running `verify_langfuse_posture.py` locally or in pre-merge validation requires `--dry-run --posture development` and mock environment variables:
```bash
export GOOGLE_CLOUD_PROJECT="mock-dev-project"
_region="${CAGE_DEPLOYMENT_REGION:-US_FED}"
case "$_region" in
  EU_ECB)    export GOOGLE_CLOUD_LOCATION="europe-west1" ;;
  APAC_MAS)  export GOOGLE_CLOUD_LOCATION="asia-southeast1" ;;
  *)         export GOOGLE_CLOUD_LOCATION="us-central1" ;;
esac
export LANGFUSE_HOST="http://localhost:3000"
export LANGFUSE_PUBLIC_KEY="pk-lf-mock"
export LANGFUSE_SECRET_KEY="sk-lf-mock"
export LANGFUSE_COMPLIANCE_HOST="http://localhost:3001"
export LANGFUSE_COMPLIANCE_PUBLIC_KEY="pk-lf-comp-mock"
export LANGFUSE_COMPLIANCE_SECRET_KEY="sk-lf-comp-mock"
uv run python scripts/verify_langfuse_posture.py --dry-run --posture development
```

### 2. Jurisdictional Region Derivation
`GOOGLE_CLOUD_LOCATION` must be derived from `CAGE_DEPLOYMENT_REGION`:
- `US_FED` → `us-central1`
- `EU_ECB` → `europe-west1`
- `APAC_MAS` → `asia-southeast1`

### 3. Live GKE Testing
Live dual-pipeline attestation, trace verification, and SLA timing are validated exclusively against live GKE clusters via port-forwarding (`scripts/port_forward_staging.sh`, forwarding ports `3000` and `3001`) with `uv run pytest tests/ --run-integration`. Local offline tests must keep telemetry tracing disabled (`-p no:langsmith -p no:langsmith_plugin`, `LANGCHAIN_TRACING_V2=false`, `LANGSMITH_TRACING=false`).

---

## 8. Expected Outcomes for GPU-Dependent Tests

When the staging cluster's GPU node pool is scaled down to 0 replicas:
- **`tests/test_langfuse_evaluation.py`**: Cleanly auto-skips with `vLLM judge endpoint is not reachable — GPU pod likely Pending in dev/staging posture`.
- **`tests/test_gateway_connectivity_live.py::test_chat_proxy`**: Cleanly auto-skips when vLLM backend is unreachable.
- **`tests/test_agent_accuracy.py`**: Will fail or return `401 Unauthorized` / connection error because the full financial advisor graph requires live vLLM inference and cluster-configured `CAGE_API_KEY`.
- **Decision Rule**: Do **not** treat GPU-disabled skips or inference failures as software regressions when running against clusters with scaled-down GPU pools.

---

## 9. Step-by-Step Staging Smoke & Integration Workflow

Follow this workflow for comprehensive staging validation:

```bash
# Step 1: Health smoke test across all port-forwarded cluster endpoints
uv run python scripts/test_live_gke_services.py

# Step 2: Live end-to-end governance flow & Langfuse trace ingestion
uv run python scripts/test_gke_e2e_flow.py

# Step 3: OPA Rego governance policies against live cluster OPA (20/20 checks)
uv run pytest tests/test_trade_governance_rego.py --run-integration -v

# Step 4: Redis durability, maxmemory, and DB0/DB1 namespace isolation
uv run pytest tests/test_redis_eviction_envelope.py --run-integration -v

# Step 5: Compliance Bridge & MCP live tool execution (constrained concurrency)
uv run pytest tests/test_compliance_bridge_smoke.py tests/test_trades_mcp.py tests/test_evaluator_mcp.py --run-integration -v
uv run pytest tests/test_compliance_bridge_integration.py --run-integration -n 2 --dist loadscope -v

# Step 6: Gateway TLS enforcement and connectivity
uv run pytest tests/test_gateway_connectivity_live.py --run-integration -v

# Step 7: Teardown port-forward daemon after testing
bash scripts/port_forward_staging.sh --stop
```

---

## 10. Staging Lifecycle Validation (POAM-024 Closure)

**Status**: Provisioned 2026-08-29

The `staging` environment is an ephemeral pre-production validation tier that proves full security posture at dev-scale cost before promoting to production:

```bash
# Automated lifecycle (recommended)
./scripts/staging_lifecycle.sh

# Manual deployment
./deploy_all.sh --target gcp-gke --env staging --auto-approve

# Manual teardown
cd infra/targets/gcp-gke
terraform destroy -var-file=staging.tfvars -auto-approve
```

**What staging validates** (ISO 42001 §A.5.3 CA-2 pre-production validation):
- All 31 Lula validation gates pass at 1-replica scale
- NIST SP 800-53 controls enforced without HA overhead
- Cluster-scoped controls active (Binary Authorization, PSS restricted, CMEK, audit logs)
- Regional compliance postures (US_FED, EU_ECB, APAC_MAS) validated

**Key characteristics**:
- **Cost**: ~$2-4 per validation cycle (20-30 minutes runtime)
- **Hardware**: Dev-scale (e2-standard-4 nodes, pd-standard disks, GPU scale-to-zero)
- **Security**: Full prod posture (`enable_nist_compliance=true` for US_FED, Binary Authorization, audit logging, CMEK, PSS restricted)
- **HA**: Decoupled (`enable_high_availability=false`, 1 replica per service, standalone Redis)
- **Lifecycle**: Ephemeral (`enable_deletion_protection=false`, allows teardown)

**Automation workflow** ([`scripts/staging_lifecycle.sh`](../../scripts/staging_lifecycle.sh)):
1. **Phase 1**: Provision staging with `./deploy_all.sh --env staging`
2. **Phase 2**: Wait for cluster readiness (`kubectl wait --for=condition=Ready`)
3. **Phase 3**: Lula validation (all 31 gates, exit on failure)
4. **Phase 4**: Region posture tests (`CAGE_DEPLOYMENT_REGION={US_FED,EU_ECB,APAC_MAS}`)
5. **Phase 5**: Cluster-scoped control verification (BinAuthz, PSS, CMEK, audit logs)
6. **Phase 6**: Teardown (`terraform destroy -var-file=staging.tfvars`)

See [`infra/targets/gcp-gke/staging.tfvars`](../../infra/targets/gcp-gke/staging.tfvars) for configuration and [`docs/operations/DEPLOYMENT_DECISION_RECORD.md`](DEPLOYMENT_DECISION_RECORD.md) ADR-004 for design rationale.

---

## 11. Nightly CI Policy

**Verdict: No new nightly workflow is needed.**

- The `local`/`unit` marker subset (~90%+ of the 2553 passing tests) already runs on every push/PR via the existing `pytest-logic` job in all three region postures (`.github/workflows/ci.yml` lines 87–134). A dedicated nightly run of the same markers adds negligible incremental regression-detection value over what is already gated on `main` before merge.
- Tests that genuinely require live GKE (live OPA policy evaluation, Langfuse SLA timing, CMEK/pod-restart checks, real backend accuracy) **cannot be replaced** by a mock-only nightly — these are the `integration`-marked corpus and the 51 skips in the full run.
- Existing CI already covers what a nightly would target: `pytest-logic` (mock/unit, every push), `ai600-unit-tests` (red-team mock, every push), `locust-load-test` (nightly load test).
- **Practical guidance**: treat `pytest-logic` + `ai600-unit-tests` (GKE-independent, secret-free) as the authoritative daily regression gate. Reserve the live-GKE `integration-smoke` job, manual full-suite runs (`scripts/port_forward_staging.sh` + `uv run pytest tests/ --run-integration`), and **staging lifecycle validation** (`./scripts/staging_lifecycle.sh`) for periodic live-service validation.
