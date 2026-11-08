# Cybernetic Governance Engine — Deployment

This directory contains Docker/Cloud Build configurations, local Compose stacks, deployment scripts, and operational runbooks for the Cybernetic Governance Engine (CAGE) stack.

Active Kubernetes workloads and cloud infrastructure live exclusively under [`infra/`](../infra/) (the unmanaged `de5534ac:deployment/k8s/` manifest directory was retired in v5.x and is blocked by CI `scripts/check_k8s_terraform_parity.py`). The canonical deployment entry point is [`deploy_all.sh`](../deploy_all.sh) at the repository root.

---

## Architecture Overview

CAGE is deployed as a set of Kubernetes workloads across two namespaces:

| Namespace | PSA Level | Description |
|-----------|-----------|-------------|
| `governance-stack` | `restricted` | All application services (gateway, advisor, OPA, Langfuse, Redis, compliance bridge) |
| `vllm-inference` | `baseline` | vLLM GPU workloads (requires elevated privileges for CUDA) |
| `agentsight` | `privileged` | AgentSight eBPF DaemonSet (requires host PID/network) |

### Services in `governance-stack`

| Deployment / Kind | K8s Name | Port | Image |
|-------------------|----------|------|-------|
| Gateway (HTTP + gRPC) | `gateway` | 8080 (HTTP), 50051 (gRPC) | `gcr.io/<PROJECT>/gateway:latest` |
| Governed Financial Advisor | `governed-financial-advisor` | 80 → 8080 | `gcr.io/<PROJECT>/governed-financial-advisor:latest` |
| OPA policy engine | `opa-service` | 8181 (policy), 8282 (diag) | `openpolicyagent/opa:0.68.0-static` |
| NeMo Guardrails | `nemo-service` | 8000 | `gcr.io/<PROJECT>/nemo-guardrails:latest` |
| Compliance Bridge | `compliance-bridge` | 80 → 3001 | `gcr.io/<PROJECT>/compliance-bridge:latest` |
| Langfuse Web | `langfuse-web` | 80 → 3000 | `langfuse/langfuse:3` |
| Langfuse Worker | `langfuse-worker` | — | `langfuse/langfuse-worker:3` |
| Redis (Bitnami Sentinel) | `redis-node` (StatefulSet, 3 pods) | 6379 | Bitnami Helm chart |
| AgentSight daemon | `agentsight-daemon` (DaemonSet) | — | `ghcr.io/agent-sight/agentsight-daemon:latest` |

### Services in `vllm-inference`

| Deployment | K8s Name | Port | Notes |
|------------|----------|------|-------|
| Fast inference (Qwen2.5-7B) | `vllm-service` | 8000 | Provisioned via `infra/modules/vllm_inference/main.tf` |
| Reasoning inference | `vllm-reasoning` | 8000 | Provisioned via `infra/modules/vllm_inference/main.tf` |

> **Note:** NeMo Guardrails also runs as an in-process module embedded inside the gateway. The standalone `nemo-service` Deployment handles requests that require an isolated NeMo process.
>
> **Note (2026-08-06):** Inside the Governed Financial Advisor pod, the
> in-process `LLMRails` lifecycle was consolidated to a single module-level
> singleton (`nemo_node_factory.py`), replacing a prior pattern where the
> LangGraph guardrail nodes, `src/governed_financial_advisor/tools/api.py`, and `server.py` each built and
> held their own independent `LLMRails` instance. Hot-reloads issued via
> `POST /v1/nemo/approve-refinement/{id}` now propagate to every in-process
> consumer atomically. This does not affect the standalone `nemo-service`
> Deployment, which remains a separate process/pod. See
> [`src/gateway/governance/nemo/README.md`](../src/gateway/governance/nemo/README.md#gfa-pod--singleton-consolidation-2026-08-06).

---

## Deployment Entry Point

### `deploy_all.sh` (recommended)

```bash
# Local / cloud-agnostic container stack (Docker Compose)
docker compose up --build

# GCP GKE — dev
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# GCP GKE — US_FED production (ISO 42001 + NIST SP 800-53)
CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/prod.tfvars

# GCP GKE — EU_ECB production (ISO 42001 + EU AI Act / GDPR / DORA)
CAGE_DEPLOYMENT_REGION=EU_ECB ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/eu-prod.tfvars

# GCP GKE — APAC_MAS production (ISO 42001 + MAS FEAT / Notice 655 / TRM)
CAGE_DEPLOYMENT_REGION=APAC_MAS ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/apac-prod.tfvars
```

**Options:**

| Flag | Description |
|------|-------------|
| `--target gcp-gke` | Infrastructure target (required) |
| `--env dev\|staging\|prod` | Deployment tier (default: `dev`) |
| `--auto-approve` | Skip Terraform confirmation prompt |
| `--var-file=PATH` | Additional `.tfvars` file |
| `--var KEY=VALUE` | Override any Terraform variable |
| `--skip-build` | Skip container image builds |

The script:
1. Reads `.env` and maps variables to `TF_VAR_*` (secrets go directly to `TF_VAR_*`, never as bare env vars — H-16).
2. Propagates `CAGE_DEPLOYMENT_REGION` → `TF_VAR_cage_deployment_region`.
3. Generates `infra/targets/gcp-gke/terraform.auto.tfvars` from `.env` via `scripts/gen_tfvars.py`.
4. Runs `terraform init`, `terraform plan`, and (on confirmation) `terraform apply`.
5. Pre-builds all container images via Cloud Build (`scripts/build_images.sh`) before apply.

### Background deployments (bypasses tool timeouts)

```bash
# Launch deploy_all.sh detached — survives terminal/tool closure
make deploy-bg TARGET=gcp-gke ENV=dev EXTRA_ARGS="--auto-approve"

# Build images only (background)
make build-bg

# Monitor progress
make deploy-status    # PID + last 20 log lines
make deploy-logs      # live tail
make deploy-kill      # cancel
```

---

## Container Images

All GKE images are built via Cloud Build — **never** with local `docker build` for GKE-targeted images (architecture mismatch: ARM64 laptop vs. x86 GKE nodes).

### Cloud Build configs

| Image | Cloud Build config | Dockerfile |
|-------|--------------------|------------|
| `governed-financial-advisor` | `deployment/docker/cloudbuild.image.yaml` | `Dockerfile` |
| `gateway` | `deployment/docker/cloudbuild.image.yaml` | `src/gateway/Dockerfile` |
| `compliance-bridge` | `deployment/docker/cloudbuild.image.yaml` | `src/compliance_bridge/Dockerfile` |
| `nemo-guardrails` | `deployment/docker/cloudbuild.image.yaml` | `deployment/docker/Dockerfile.nemo` |
| `vllm-streamer` | `deployment/docker/cloudbuild.vllm.yaml` | `deployment/docker/Dockerfile.vllm` |
| `agentsight-ui` | `deployment/docker/cloudbuild.image.yaml` | `src/agentsight-ui/Dockerfile` |

Tags: immutable `:<short-git-sha>` only (attested by `scripts/attest_image.sh`). Terraform pins each image by the `@sha256:` digest `scripts/render_image_digests.sh` renders per deployment; no digest is committed (POAM-2026-131).

### Approved commands

```bash
# APPROVED — build all images for GKE
./scripts/build_images.sh   # requires PROJECT_ID env var

# APPROVED — build specific image
gcloud builds submit --config deployment/docker/cloudbuild.image.yaml \
  --substitutions="_IMAGE_NAME=gateway,_DOCKERFILE=src/gateway/Dockerfile,_SHORT_SHA=$(git rev-parse --short HEAD)" .

# APPROVED — verify a Dockerfile change without pushing (build, smoke-import
# the entry module as the image user, Trivy gate identical to sbom.yml)
gcloud builds submit --config deployment/docker/cloudbuild.verify.yaml \
  --substitutions="_DOCKERFILE=src/gateway/Dockerfile,_SMOKE_MODULE=src.gateway.server.hybrid_server" .

# NEVER for GKE — architecture mismatch
# docker build ...
# docker-compose build && docker push ...
```

---

## Kubernetes Workloads (`infra/modules/` & `infra/targets/gcp-gke/`)

All Kubernetes workloads, Services, NetworkPolicies, ServiceAccounts, and Secrets are reconciled exclusively by Terraform (`scripts/check_k8s_terraform_parity.py` fails CI on any `deployment/k8s/` shadow manifest or orphan selector).

| Module / File | Kind | Notes |
|---------------|------|-------|
| [`infra/modules/gateway/main.tf`](../infra/modules/gateway/main.tf) | Deployment + Service + HPA + PDB | Gateway HTTP :8080, gRPC :50051; `cage-gateway-sa` |
| [`infra/modules/gateway/mesh-policy/`](../infra/modules/gateway/mesh-policy/templates/policy.yaml) | Linkerd `Server` / `HTTPRoute` / `AuthorizationPolicy` | Admits only verified advisor identity (`cage-advisor-sa`) |
| [`infra/modules/gateway/metrics-monitors/`](../infra/modules/gateway/metrics-monitors/templates/monitors.yaml) | GKE Managed Prometheus `PodMonitoring` | Scrapes `/metrics` on gateway pods |
| [`infra/modules/governed_advisor/main.tf`](../infra/modules/governed_advisor/main.tf) | Deployment + ClusterIP Service | Governed Financial Advisor (`cage-advisor-sa`); optional GEAP runtime (`infra/modules/gcp_geap_advisor/`) |
| [`infra/modules/compliance_bridge/main.tf`](../infra/modules/compliance_bridge/main.tf) | Deployment + ClusterIP Service | OSCAL/evidence service (`cage-compliance-bridge-sa`) |
| [`infra/modules/reconciliation_worker/main.tf`](../infra/modules/reconciliation_worker/main.tf) | Deployment + Secret | Single-replica `GroundTruthReconciler` (`cage-reconciler-sa`), anti-Spot node affinity |
| [`infra/modules/opa_policy/main.tf`](../infra/modules/opa_policy/main.tf) | Deployment + ConfigMap + ClusterIP Service | OPA policy engine (:8181 / :8282) |
| [`infra/modules/nemo_guardrails/main.tf`](../infra/modules/nemo_guardrails/main.tf) | Deployment + ConfigMap + ClusterIP Service | NeMo Guardrails; ConfigMap synced from `config/rails/` via `make update-nemo-configmap` (`infra/modules/nemo_guardrails/nemo-rails-configmap.yaml`) |
| [`infra/modules/vllm_inference/main.tf`](../infra/modules/vllm_inference/main.tf) | Deployment × 2 + Service × 2 + PDB × 2 | `vllm-inference` (`vllm-service`) & `vllm-reasoning` (`cage-vllm-sa`) |
| [`infra/modules/langfuse_stack/main.tf`](../infra/modules/langfuse_stack/main.tf) | Deployment × 2 + Service | Langfuse v3 Web & Worker (`langfuse-sa`) backed by Cloud SQL (`infra/modules/cloudsql_postgres/`) and ClickHouse (`infra/modules/clickhouse_operator/`) |
| [`infra/modules/agentsight_ui/main.tf`](../infra/modules/agentsight_ui/main.tf) | Deployment + ClusterIP Service | AgentSight governance UI |
| [`infra/modules/k8s_namespace/main.tf`](../infra/modules/k8s_namespace/main.tf) | Namespace | Pod Security Standards (`restricted` in `governance-stack`) |
| [`infra/targets/gcp-gke/network_policy.tf`](../infra/targets/gcp-gke/network_policy.tf) | `NetworkPolicy` + `FQDNNetworkPolicy` | Default-deny ingress/egress, internal L3/L4 edges, and GKE Dataplane V2 FQDN egress rules |
| [`infra/targets/gcp-gke/iam.tf`](../infra/targets/gcp-gke/iam.tf) | `ServiceAccount` + Workload Identity | 1:1 KSA-to-GSA bindings per workload (`POAM-2026-079`) |
| [`infra/targets/gcp-gke/perimeter.tf`](../infra/targets/gcp-gke/perimeter.tf) | Ingress + ManagedCertificate + BackendConfig | GKE external HTTPS LB + Cloud Armor WAF |

### Standalone Verification & Benchmark Fixtures

- [`tests/e2e/fixtures/verify-trade-e2e-job.yaml`](../tests/e2e/fixtures/verify-trade-e2e-job.yaml) — ephemeral in-cluster E2E trade verification Job
- [`scripts/fixtures/benchmark/`](../scripts/fixtures/benchmark/) — ephemeral paper benchmark Job, RBAC, and scratch Redis fixtures (`scripts/run_gke_benchmark_job.sh`)

---

## Prerequisites

### For GCP GKE deployments

- `gcloud` CLI authenticated (`gcloud auth application-default login`)
- GCP project with billing enabled
- APIs enabled via `scripts/bootstrap_gcp_project.sh`
- IAM: Kubernetes Engine Admin, Cloud Build Editor, Storage Admin

### Common CLI tooling

- `kubectl` ≥ 1.24 with cluster access configured
- `terraform` ≥ 1.5.0
- `uv` (Python package manager)
- `.env` file populated (copy from `.env.example`)

### Key `.env` variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | GCP project ID → `TF_VAR_project_id` |
| `GOOGLE_CLOUD_LOCATION` | GCP region → `TF_VAR_region` |
| `CAGE_DEPLOYMENT_REGION` | Compliance posture: `US_FED` \| `EU_ECB` \| `APAC_MAS` |
| `K8S_NAMESPACE` | Target namespace (default: `governance-stack`) |
| `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | Langfuse credentials → `TF_VAR_langfuse_public_key` |
| `HUGGING_FACE_HUB_TOKEN` | Operator-only token for out-of-band model mirroring (`deployment/scripts/mirror_models.py`), never passed to Terraform or cluster pods |
| `GOVERNANCE_SALT` | Governance salt secret → `TF_VAR_governance_salt` |

---

## Post-Deployment Verification

### Check pod status

```bash
kubectl get pods -n governance-stack
kubectl get pods -n vllm-inference
kubectl get pods -n agentsight
```

Expected running pods in `governance-stack`:

- `gateway-*`
- `governed-financial-advisor-*`
- `opa-service-*`
- `nemo-service-*`
- `compliance-bridge-*`
- `langfuse-web-*` (2 replicas)
- `langfuse-worker-*`
- `redis-node-0`, `redis-node-1`, `redis-node-2`
- `clickhouse-0`
- `minio-*`

### Local port-forwards (development)

```bash
# Start all port-forwards with auto-reconnect
bash scripts/port_forward_dev.sh
```

| Service | Local Port | Remote Port |
|---------|------------|-------------|
| OPA | 8181 | 8181 |
| Langfuse API | 3001 | 3000 |
| Langfuse UI | 3000 | 3000 |
| vLLM fast (`vllm-service`) | 8001 | 8000 |
| vLLM fast (alt) | 18081 | 8000 |
| vLLM reasoning (`vllm-reasoning`) | 8000 | 8000 |
| vLLM reasoning (alt) | 18082 | 8000 |
| Gateway | 8080 | 8080 |
| Governed FA backend | 18080 | 80 |
| Redis | 6379 | 6379 |
| Compliance Bridge | 3002 | 80 |

### Test the backend

```bash
# Forward the backend service
kubectl port-forward svc/governed-financial-advisor 18080:80 -n governance-stack

# Health check
curl http://localhost:18080/health

# Agent query (user_id is required; the advisor treats it as asserted, not authenticated)
curl -X POST http://localhost:18080/agent/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CAGE_API_KEY" \
  -d '{"prompt": "Hello", "user_id": "demo-user"}'
```

### Makefile targets

```bash
make advisor-status        # governed-financial-advisor pod status
make advisor-rollback      # rollout undo
make advisor-watch         # watch pod events
make advisor-verify-env    # dump env vars in running pod
make advisor-port-forward  # forward svc/governed-financial-advisor 8080:80
make advisor-health        # /health check
make vllm-status           # vLLM pod status
make vllm-verify-models    # list loaded models on both vLLM services
make test-integration      # run local (non-infrastructure) tests
make recovery              # print recovery checklist
```

---

## Model Weight Loading

GCS (`gs://<bucket>/`) is the **primary** model artifact store. vLLM pods (`infra/modules/vllm_inference/main.tf`) stream weights directly from GCS at startup using out-of-band mirrored model weights (`deployment/scripts/mirror_models.py`).

---

## Local Compose Stack (Development Only)

For local development without Kubernetes:

```bash
cp .env.example .env
# Edit .env with your credentials
docker-compose up -d
```

Services:

| Service | Port | Description |
|---------|------|-------------|
| `opa` | 127.0.0.1:8181 | OPA policy engine |
| `gateway` | 8080 | Gateway (HTTP) |
| `app` | 3000 | Main agent service |

The OPA port is bound to `127.0.0.1` only to prevent unauthenticated external access (HIGH-01).

### AgentSight local stack

```bash
cd deployment/agentsight
docker-compose -f docker-compose.agentsight.yaml up -d
# Dashboard: http://localhost:3000
```

---

## NeMo ConfigMap Sync

After any change to `config/rails/`:

```bash
make update-nemo-configmap
# Updates infra/modules/nemo_guardrails/nemo-rails-configmap.yaml; reconcile via Terraform (`deploy_all.sh` / `terraform apply`).
```

---

## Terraform (Infrastructure as Code)

Active IaC is in `infra/`. The old `deployment/terraform/` directory was removed 2026-03-15.

```bash
# Minimal manual apply (GCP target)
cd infra/targets/gcp-gke
terraform init
terraform apply -var-file=dev.tfvars

# Regional production
cd infra/targets/gcp-gke
CAGE_DEPLOYMENT_REGION=US_FED terraform apply -var-file=prod.tfvars
```

---

## Service Mesh (Linkerd)

The gateway authenticates callers by Linkerd mTLS workload identity (POAM-2026-080). Without the mesh, the gateway refuses every non-open route with `403`.

- **Terraform (`gcp-gke`)**: [`infra/modules/service_mesh`](../infra/modules/service_mesh/main.tf) installs cert-manager, the Google CAS issuer and Linkerd. The trust anchor is a Google CAS root CA with an HSM-backed key; no CA key is kept in Terraform state. [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf) wires the module and annotates `governance-stack` with `linkerd.io/inject=enabled`, while [`infra/modules/gateway/mesh-policy/`](../infra/modules/gateway/mesh-policy/templates/policy.yaml) installs the Linkerd `Server`, `HTTPRoute`, and `AuthorizationPolicy` resources.
- **Private clusters**: the GKE control plane must reach the Linkerd admission webhooks on TCP 8443/9443. The module creates this firewall rule (`google_compute_firewall.mesh_webhooks`); without it, injection silently never happens.


---

## Security Notes

- All application Secrets use `secretKeyRef` / `secretRef` — never plain `value:` for sensitive data.
- The `governance-stack` namespace enforces PSA `restricted:latest` (no privileged containers, no root, RuntimeDefault seccomp).
- The `vllm-inference` namespace uses PSA `baseline` for GPU/CUDA access.
- The `agentsight` namespace requires PSA `privileged` for eBPF (host PID + network).
- Gateway ingress is deny-by-default by Linkerd workload identity ([`workload_identity.py`](../src/gateway/server/workload_identity.py)). `CAGE_TRUSTED_CLIENT_IDENTITIES` lists the admitted identities (only the advisor) and is required in every environment; the gateway always enforces workload identity and fails at startup if `CAGE_TRUSTED_CLIENT_IDENTITIES` is unset. Direct unmeshed ingress callers are refused.
- The finance trade policy's `trader_role` (and `trader_id`) is bound from that verified identity, never from a request ([`trader_binding.py`](../src/cage_finance/tools/trader_binding.py)). `CAGE_TRADER_ROLE_BINDINGS` maps an identity to `junior` or `senior`; it is unset in the shipped manifests, so the advisor trades as `junior`. An invalid value stops the gateway at startup.
- `KMS_GOVERNANCE_KEY` activates Cloud KMS asymmetric signing (CTRL_KMS_001); HMAC fallback is dev/CI only.
- `RECONCILER_KMS_KEY` is the reconciler's separate snapshot-signing key. The reconciliation worker signs with it; the gateway verifies ground-truth snapshots against it by `kid` and refuses an enforcing startup without it (G8).

---

## Related Documentation

- [`infra/QUICK_START.md`](../infra/QUICK_START.md) — infrastructure quick-start
- [`infra/DEPLOYMENT_GUIDE.md`](../infra/DEPLOYMENT_GUIDE.md) — full deployment reference
- [`infra/modules/k8s_namespace/main.tf`](../infra/modules/k8s_namespace/main.tf) — namespace inventory and Pod Security Standards
- [`deployment/agentsight/README.md`](agentsight/README.md) — AgentSight setup
- [`docs/operations/DEPLOYMENT_RULES.md`](../docs/operations/DEPLOYMENT_RULES.md) — deployment rules (Cloud Build requirement)
