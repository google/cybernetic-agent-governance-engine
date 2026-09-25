# Cloud Run Staging & Live Integration Test Runbook

> **Operational Runbook — Live Cloud Run Testing, Service Ingress, IAM Authentication, and Test Reusability.**
> This document details the procedures for executing live integration tests against a CAGE deployment
> running on Google Cloud Run ([`infra/targets/gcp-cloudrun`](../../infra/targets/gcp-cloudrun)),
> managing Google IAM identity tokens, and filtering test suites using pytest facet markers.
>
> *For live GKE cluster testing, see [`GKE_TEST_RUNBOOK.md`](GKE_TEST_RUNBOOK.md).*
> *For everyday hermetic unit testing, see [`AGENTS.md`](../../AGENTS.md) §11.*

---

## Table of Contents

1. [Architecture & Ingress Comparison: GKE vs. Cloud Run](#1-architecture--ingress-comparison-gke-vs-cloud-run)
2. [Prerequisites & Endpoint Discovery](#2-prerequisites--endpoint-discovery)
3. [Service Smoke Testing](#3-service-smoke-testing)
4. [Live Governed Financial Advisor & Langfuse E2E Flow](#4-live-governed-financial-advisor--langfuse-e2e-flow)
5. [Live Integration Test Invocations](#5-live-integration-test-invocations)
6. [Pytest Marker Strategy: Selection vs. Facet Markers](#6-pytest-marker-strategy-selection-vs-facet-markers)
7. [GKE-Specific vs. Reusable Test Inventory](#7-gke-specific-vs-reusable-test-inventory)
8. [IAM Authentication & Service-to-Service Invocation](#8-iam-authentication--service-to-service-invocation)

---

## 1. Architecture & Ingress Comparison: GKE vs. Cloud Run

| Dimension | GKE Staging (`infra/targets/gcp-gke`) | Cloud Run Target (`infra/targets/gcp-cloudrun`) |
|---|---|---|
| **Endpoint Access** | Multiplexed via `kubectl port-forward` to `localhost:<port>` | HTTPS service URLs (`https://<service>-<hash>.a.run.app`) |
| **Edge Transport** | TLS terminated at Ingress; plain HTTP over localhost tunnels | Automatic TLS 1.2/1.3 Google edge termination or Cloud Load Balancer |
| **Authentication** | `CAGE_API_KEY` header over plain HTTP | Google IAM ID Token (`Authorization: Bearer <token>`) + `CAGE_API_KEY` |
| **OPA Policy Engine** | Standalone Kubernetes Service (`svc/opa:8181`) | Co-located sidecar container in Gateway (`localhost:8181` inside container) |
| **State Store (Redis)** | In-cluster StatefulSet with AOF persistence | Cloud Memorystore Redis (private PSA VPC peering, RDB snapshot) |
| **OLAP Telemetry** | ClickHouse pod / in-cluster service | In-VPC ClickHouse Compute Engine VM (`pd-ssd`) |

---

## 2. Prerequisites & Endpoint Discovery

### 1. Terraform Deployment Outputs
After applying Terraform in `infra/targets/gcp-cloudrun`, export the service endpoints:

```bash
cd infra/targets/gcp-cloudrun

export GATEWAY_URL=$(terraform output -raw gateway_url)
export BACKEND_URL=$(terraform output -raw governed_advisor_url)
export COMPLIANCE_BRIDGE_URL=$(terraform output -raw compliance_bridge_url)
export LANGFUSE_HOST=$(terraform output -raw langfuse_web_url)
export AGENTSIGHT_UI_URL=$(terraform output -raw agentsight_ui_url)
```

### 2. Service Account Impersonation (Recommended)

For integration testing against Cloud Run staging/production environments, use dedicated service account impersonation instead of personal credentials:

```bash
# Set the test automation service account (created via Terraform)
export CLOUDRUN_TEST_SERVICE_ACCOUNT="cage-test-automation-dev@PROJECT_ID.iam.gserviceaccount.com"
export CAGE_TEST_TARGET=cloudrun

# Grant your user account permission to impersonate the test SA (one-time setup)
gcloud iam service-accounts add-iam-policy-binding \
  cage-test-automation-dev@PROJECT_ID.iam.gserviceaccount.com \
  --member="user:YOUR_EMAIL@google.com" \
  --role="roles/iam.serviceAccountTokenCreator"
```

**Why use service account impersonation?**
- ✅ Eliminates PII (personal email) from Cloud Audit Logs
- ✅ Enables automated CI/CD workflows
- ✅ Enforces least-privilege IAM policies
- ✅ Mirrors production authentication patterns

The [`tests/conftest.py`](../../tests/conftest.py) test harness automatically detects `CLOUDRUN_TEST_SERVICE_ACCOUNT` and uses impersonation mode.

### 3. Personal Credentials (Local Development Fallback)

For local development only (not recommended for staging/production):

```bash
export CLOUDRUN_IDENTITY_TOKEN=$(gcloud auth print-identity-token)
export CAGE_TEST_TARGET=cloudrun
```

**Note**: This method uses your personal Google Cloud credentials. For staging and production testing, use service account impersonation (Section 2) instead.

---

## 3. Service Smoke Testing

Run the automated smoke test script to verify endpoint health across all deployed Cloud Run services:

```bash
# Automated discovery via Terraform state (or uses exported env vars)
python scripts/test_live_cloudrun_services.py
```

The script validates:
- Gateway `/health` endpoint
- Governed Financial Advisor `/health` endpoint
- Compliance Bridge `/health` and `/v1/controls` endpoints
- Langfuse Web `/api/public/health` and API key authentication
- AgentSight UI endpoint reachability
- vLLM GPU inference endpoint (when GPU inference is enabled)

---

## 4. Live Governed Financial Advisor & Langfuse E2E Flow

To verify the end-to-end cybernetic loop on Cloud Run — combining the **Governed Financial Advisor** multi-agent graph with **Langfuse** telemetry trace ingestion and ClickHouse OLAP persistence:

```bash
# Run the end-to-end verification script:
python scripts/test_cloudrun_e2e_flow.py
```

What this validates over the live wire:
1. **Gateway Governance & MCP Dispatch**: Verifies gateway health and tools listing.
2. **Governed Financial Advisor Query Flow**: Dispatches a financial advisory prompt (`Analyze the performance and market risk profile of AAPL for a conservative portfolio`) to `/agent/query`, confirming that the multi-agent graph, consequence gateway, and safety filters execute properly.
3. **Langfuse Trace & Telemetry Pipeline**: Validates that trace envelopes are received by Langfuse and stored in the ClickHouse OLAP database.
4. **vLLM GPU Inference**: Verifies model generation against the serverless L4 GPU inference instance (when provisioned).

---

## 5. Live Integration Test Invocations

### Canonical Orchestrated Run (Recommended):

To run all discovery, IAM authentication, smoke validation, GPU/agent warm-up, and integration tests in a single command with **explicit skip reporting**:

```bash
make test-cloudrun
# Or directly via script:
./scripts/run_cloudrun_integration_tests.sh
```

### Manual Cloud Run Integration Run:

```bash
source .env && \
export CAGE_TEST_TARGET=cloudrun \
       CAGE_ENV=test \
       GATEWAY_URL=$(terraform -chdir=infra/targets/gcp-cloudrun output -raw gateway_url) \
       BACKEND_URL=$(terraform -chdir=infra/targets/gcp-cloudrun output -raw governed_advisor_url) \
       COMPLIANCE_BRIDGE_URL=$(terraform -chdir=infra/targets/gcp-cloudrun output -raw compliance_bridge_url) \
       LANGFUSE_HOST=$(terraform -chdir=infra/targets/gcp-cloudrun output -raw langfuse_web_url) && \
uv run pytest tests/ \
  -m "integration and not gke" \
  --run-integration \
  -n 2 --dist loadscope \
  --no-cov \
  -p no:langsmith -p no:langsmith_plugin \
  -ra -rs \
  --tb=short
```

#### Execution Parameters Rationale & Parity Invariants:
- **`-m "integration and not gke"`**: Runs all universal Layer 7 integration tests while excluding tests that require raw Kubernetes node primitives or self-managed container configs (e.g., `test_pod_restarts_are_zero` GKE path, `test_redis_dangerous_commands_disabled`).
- **`--run-integration`**: Satisfies the fail-closed selection gate in [`tests/conftest.py`](../../tests/conftest.py), preventing accidental execution of live cloud suites during local development.
- **`-n 2 --dist loadscope`**: Constrains worker concurrency to prevent a thundering herd of container cold starts on serverless Cloud Run revisions (`minScale=0`) while grouping tests by module (`loadscope`) to maintain fixture isolation.
- **`-ra -rs` (Non-Silent Skip Invariant)**: Forces Pytest to explicitly print the exact reason for every skipped test in the terminal summary. This prevents silent skips (e.g., from unexported endpoints defaulting to `localhost` or missing IAM tokens) from masquerading as passes or bugs.
- **`--no-cov`**: Disables local coverage instrumentation overhead, avoiding skewed coverage metrics from remote network assertions.
- **`-p no:langsmith -p no:langsmith_plugin`**: Enforces the AGENTS.md § Observability invariant by disabling third-party LangSmith telemetry plugins in favor of sovereign self-hosted Langfuse.
- **`--tb=short`**: Produces concise error tracebacks.

### The Non-Silent Skip Contract (Why Tests Skip & How to Diagnose):
If tests show as skipped (`s`), inspect the `-rs` summary at the end of the run:
1. **`Integration test — requires live external services`**: You omitted `--run-integration` (or did not invoke `make test-cloudrun`).
2. **`compliance-bridge not reachable at http://localhost:...`**: You did not export `COMPLIANCE_BRIDGE_URL` from Terraform, so the test fell back to an unreachable localhost address.
3. **`Backend http://localhost:18080 unreachable`**: `BACKEND_URL` is missing from your environment.
4. **`returned status=401 / 403`**: Google IAM identity token is missing or expired. Set `CLOUDRUN_TEST_SERVICE_ACCOUNT` or run `gcloud auth print-identity-token`.
5. **`US_FED-specific framework filter tests skipped for region 'EU_ECB'`**: Legitimate jurisdictional skip per CAGE regional posture design.

### Dedicated Multi-Agent & Langfuse Test Suites against Cloud Run:

```bash
# 1. Financial Advisor agent accuracy over live inference
uv run pytest tests/test_agent_accuracy.py --run-integration -n 2 --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin -v

# 2. Langfuse LLM-as-a-judge evaluation & quality scoring
uv run pytest tests/test_langfuse_evaluation.py --run-integration -n 2 --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin -v

# 3. Langfuse v3/v4 trace ingestion smoke tests
uv run pytest tests/test_langfuse_smoke.py --run-integration --no-cov -p no:langsmith -p no:langsmith_plugin -v

# 4. Gateway connectivity and TLS 1.2+ validation
uv run pytest tests/test_gateway_connectivity_live.py --run-integration --no-cov -p no:langsmith -p no:langsmith_plugin -v
```

---

## 6. Pytest Marker Strategy: Selection vs. Facet Markers

CAGE enforces a strict, fail-closed **Selection Marker Contract** (see [`AGENTS.md`](../../AGENTS.md) §11 and [`tests/conftest.py`](../../tests/conftest.py)):

1. **Selection Markers** (`unit`, `local`, `integration`, `partner_integration`, `live_external`, `chaos`, `load`):
   - Every test must carry exactly one selection marker.
   - Live Cloud Run tests **must keep `integration`** as their selection marker. Never replace `integration` with `cloudrun` as a selection marker.
2. **Facet Markers** (`gke`, `cloudrun`, `us_fed`, `eu_ecb`, `apac_mas`, etc.):
   - Additive qualifiers registered in [`pytest.ini`](../../pytest.ini).
   - Use `gke` to flag tests that depend strictly on Kubernetes-specific mechanics (e.g. `kubectl get pod` restart counts or StatefulSet Redis AOF configuration).
   - Use `cloudrun` to flag tests specific to Cloud Run revisions or IAM invoker headers.
   - Universal tests (Layer 7 HTTP endpoints) carry only `integration`, remaining runnable against both GKE and Cloud Run.

---

## 7. GKE-Specific vs. Reusable Test Inventory

### Reusable Tests (Target-Agnostic HTTP / MCP / LLM Workflows):
- [`tests/test_gateway_connectivity_live.py`](../../tests/test_gateway_connectivity_live.py) — Gateway MCP SSE, Chat Proxy, TLS version checks.
- [`tests/test_compliance_bridge_smoke.py`](../../tests/test_compliance_bridge_smoke.py) — Health checks and control catalog. Cloud Run IAM auth injected automatically via `_bridge_auth_headers()`, with adaptive SSE timeout for Cloud Run cold starts.
- [`tests/test_compliance_bridge_integration.py`](../../tests/test_compliance_bridge_integration.py) (Groups 1–11, 13, 14) — OSCAL exports, SSE streams, audit ingest. `require_live_bridge` and `session` fixtures inject IAM identity tokens on Cloud Run.
- [`tests/test_redis_eviction_envelope.py`](../../tests/test_redis_eviction_envelope.py) — Redis state store invariants. Runs on both GKE and Cloud Run (Cloud Memorystore). CONFIG GET-based assertions (`noeviction`, `maxmemory`, AOF) skip gracefully on Cloud Memorystore; connection and namespace-isolation tests run on both platforms.
- [`tests/test_trades_mcp.py`](../../tests/test_trades_mcp.py) & [`tests/test_evaluator_mcp.py`](../../tests/test_evaluator_mcp.py) — MCP tool execution.
- [`tests/test_agent_accuracy.py`](../../tests/test_agent_accuracy.py) & [`tests/test_agent_performance.py`](../../tests/test_agent_performance.py) — End-to-end multi-agent advisor loops.
- [`tests/red_team/run_red_team.py`](../../tests/red_team/run_red_team.py) — Adversarial prompt evaluation.
- [`tests/test_langfuse_smoke.py`](../../tests/test_langfuse_smoke.py) & [`tests/test_langfuse_evaluation.py`](../../tests/test_langfuse_evaluation.py) — Telemetry, v4 events_only ingestion, and LLM-as-a-judge scoring.

### GKE-Exclusive Tests (Marked with `@pytest.mark.gke` and **not** refactored for Cloud Run):
- `test_pod_restarts_are_zero` in [`tests/test_compliance_bridge_integration.py`](../../tests/test_compliance_bridge_integration.py) — On **GKE**: runs `kubectl get pod` to check restart count. On **Cloud Run**: executes the Cloud Run equivalent (revision health via `/health`) instead.
- `test_redis_dangerous_commands_disabled` in [`tests/test_redis_eviction_envelope.py`](../../tests/test_redis_eviction_envelope.py) — GKE StatefulSet disables `FLUSHDB` via redis.conf command rename; Cloud Memorystore enforces isolation via IAM roles (test skips on Cloud Run).
- `compliance/lula/*` — Validates Kubernetes CRDs and PodSecurity policies.

---

## 8. IAM Authentication & Service-to-Service Invocation

When services in Cloud Run are deployed with `INGRESS_TRAFFIC_INTERNAL_ONLY` or without public unauthenticated access:

1. **Inside VPC (Cloud Build / Bastion VM)**:
   Tests running within the VPC subnet can invoke service private endpoints directly via Direct VPC Egress without public IP traversal.
2. **Outside VPC (Developer Workstation)**:
   The [`cloudrun_auth_headers`](../../tests/conftest.py) fixture in `tests/conftest.py` automatically resolves the caller's Google IAM token via `gcloud auth print-identity-token` or `$CLOUDRUN_IDENTITY_TOKEN` and passes `Authorization: Bearer <token>` to requests targeting Cloud Run.
