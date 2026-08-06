# Cybernetic Governance Engine — Deployment

This directory contains Kubernetes manifests, Docker configurations, deployment scripts, and operational runbooks for the Cybernetic Governance Engine (CAGE) stack.

Active IaC lives under [`infra/`](../infra/). The canonical deployment entry point is [`deploy_all.sh`](../deploy_all.sh) at the repository root.

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
| OPA policy engine | `opa-service` | 8181 (policy), 8282 (diag) | `openpolicyagent/opa:latest-static` |
| NeMo Guardrails | `nemo-service` | 8000 | `gcr.io/<PROJECT>/nemo-guardrails:latest` |
| Compliance Bridge | `compliance-bridge` | 80 → 3001 | `gcr.io/<PROJECT>/compliance-bridge:latest` |
| Langfuse Web | `langfuse-web` | 80 → 3000 | `langfuse/langfuse:3` |
| Langfuse Worker | `langfuse-worker` | — | `langfuse/langfuse-worker:3` |
| Redis (Bitnami Sentinel) | `redis-node` (StatefulSet, 3 pods) | 6379 | Bitnami Helm chart |
| AgentSight daemon | `agentsight-daemon` (DaemonSet) | — | `ghcr.io/agent-sight/agentsight-daemon:latest` |

### Services in `vllm-inference`

| Deployment | K8s Name | Port | Notes |
|------------|----------|------|-------|
| Fast inference (Qwen2.5-7B) | `vllm-service` | 8000 | Proxied into `governance-stack` via `vllm-services.yaml` ExternalName |
| Reasoning inference | `vllm-reasoning` | 8000 | Proxied into `governance-stack` via `vllm-services.yaml` ExternalName |

> **Note:** NeMo Guardrails also runs as an in-process module embedded inside the gateway. The standalone `nemo-service` Deployment handles requests that require an isolated NeMo process.
>
> **Note (2026-08-06):** Inside the Governed Financial Advisor pod, the
> in-process `LLMRails` lifecycle was consolidated to a single module-level
> singleton (`nemo_node_factory.py`), replacing a prior pattern where the
> LangGraph guardrail nodes, `tools/api.py`, and `server.py` each built and
> held their own independent `LLMRails` instance. Hot-reloads issued via
> `POST /v1/nemo/approve-refinement/{id}` now propagate to every in-process
> consumer atomically. This does not affect the standalone `nemo-service`
> Deployment, which remains a separate process/pod. See
> [`src/gateway/governance/nemo/README.md`](../src/gateway/governance/nemo/README.md#gfa-pod--singleton-consolidation-2026-08-06).

---

## Deployment Entry Point

### `deploy_all.sh` (recommended)

```bash
# Cloud-agnostic target (k3s, EKS, AKS, any Kubernetes ≥ 1.24)
./deploy_all.sh --target agnostic --env dev

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
| `--target agnostic\|gcp-gke` | Infrastructure target (required) |
| `--env dev\|prod` | Deployment tier (default: `dev`) |
| `--auto-approve` | Skip Terraform confirmation prompt |
| `--var-file=PATH` | Additional `.tfvars` file |
| `--var KEY=VALUE` | Override any Terraform variable |
| `--skip-build` | Skip container image builds |
| `--kubeconfig=PATH` | Kubeconfig path (agnostic target only) |

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
| `governed-financial-advisor` | inline (generated by `build_images.sh`) | `Dockerfile` |
| `gateway` | inline | `src/gateway/Dockerfile` |
| `compliance-bridge` | `deployment/docker/cloudbuild.compliance.yaml` | `src/compliance_bridge/Dockerfile` |
| `nemo-guardrails` | `deployment/docker/cloudbuild.nemo.yaml` | `deployment/docker/Dockerfile.nemo` |
| `vllm-streamer` | `deployment/docker/cloudbuild.vllm.yaml` | `deployment/docker/Dockerfile.vllm` |
| `agentsight-ui` | inline | `src/agentsight-ui/Dockerfile` |

Tags: both `:latest` and `:<short-git-sha>` (for auditability).

### Approved commands

```bash
# APPROVED — build all images for GKE
./scripts/build_images.sh   # requires PROJECT_ID env var

# APPROVED — build specific image
gcloud builds submit --config deployment/docker/cloudbuild.gateway.yaml

# NEVER for GKE — architecture mismatch
# docker build ...
# docker-compose build && docker push ...
```

---

## Kubernetes Manifests (`deployment/k8s/`)

### Core application manifests

| File | Kind | Notes |
|------|------|-------|
| `gateway.yaml` | Deployment + NodePort Service | Gateway HTTP :8080, gRPC :50051; NodePort 30080 for GCE Ingress |
| `gateway.yaml.tpl` | Template | Rendered by `deploy_all.sh` — substitutes `${CAGE_ENV}`, `${CAGE_DEPLOYMENT_REGION}` |
| `gateway-hpa.yaml` | HPA | Scale 1–5 replicas at 50% CPU |
| `gateway-deployment.yaml.tpl` | Template | Alternative Deployment template |
| `financial-advisor.yaml` | Deployment + ClusterIP Service | Port 80 → 8080; uses `financial-advisor-sa` ServiceAccount |
| `backend-deployment.yaml` | Deployment | Static (non-templated) version |
| `backend-deployment.yaml.tpl` | Template | Rendered for region-specific deployments |
| `compliance-bridge.yaml` | Deployment + ClusterIP Service | Port 80 → 3001; 150s startup delay (dowhy/matplotlib import) |
| `nemo.yaml` | Deployment + ClusterIP Service | Port 8000 |
| `nemo-rails-configmap.yaml` | ConfigMap | NeMo Colang/actions; regenerate with `make update-nemo-configmap` |
| `opa.yaml` | Deployment + ConfigMap × 2 + ClusterIP Service | Ports 8181 (policy), 8282 (diagnostics); policy package `trade.governance` |

### vLLM manifests

| File | Description |
|------|-------------|
| `vllm-namespace.yaml` | `vllm-inference` namespace (PSA: baseline) |
| `vllm-services.yaml` | ExternalName Services in `governance-stack` proxying to `vllm-inference` |
| `vllm-cross-namespace-services.yaml` | Real ClusterIP Services in `vllm-inference` |
| `vllm-deployment.yaml.tpl` | vLLM fast-path Deployment template |
| `vllm-inference-spot.yaml` / `.tpl` | Spot-node vLLM Deployment |
| `vllm-reasoning.yaml.tpl` | Reasoning vLLM Deployment template |
| `vllm-reasoning-pdb.yaml` | PodDisruptionBudget for reasoning vLLM |
| `vllm-pdb.yaml` | PodDisruptionBudget for fast-path vLLM |
| `vllm-streaming.yaml` | Streaming configuration |
| `vllm-governance.yaml` | vLLM governance sidecar |
| `model-pvc.yaml` / `.tpl` | PVC for model weights |
| `model-downloader.yaml.tpl` | Model downloader Job template |
| `tensorize-job.yaml` | One-time tensorization Job (HuggingFace → MinIO) |

### Observability and state

| File | Description |
|------|-------------|
| `langfuse-web.yaml` | Langfuse v3 Web (2 replicas, avoids Spot nodes); ClusterIP :3000 |
| `langfuse-web.yaml.tpl` | Rendered template |
| `langfuse-worker.yaml` | Langfuse Worker |
| `langfuse-worker.yaml.tpl` | Rendered template |
| `langfuse-worker-hpa.yaml` | HPA: 2–15 replicas (70% CPU / 80% memory) |
| `langfuse-db.yaml` | PostgreSQL for Langfuse |
| `langfuse-db-secrets.yaml` | Secret template (gitignored after population) |
| `redis-stack-fresh.yaml` | Active Bitnami Redis Sentinel StatefulSet |
| `redis-statefulset.yaml` | **DEPRECATED** — do not apply; retained for reference |
| `redis-config.yaml` | Redis ConfigMap (`cage-redis-config`) |
| `redis-credentials-secret.yaml` | Secret template |
| `redis-master-service.yaml` | Write-only ClusterIP pinned to Sentinel primary (`redis-node-1`) |
| `minio.yaml` | MinIO object storage (Langfuse event upload; S3-compatible) |
| `agentsight-daemon.yaml` | AgentSight eBPF DaemonSet (namespace: `agentsight`) |
| `agentsight-ui.yaml.tpl` | AgentSight UI template |

### Security manifests

| File | Description |
|------|-------------|
| `pod-security-admission.yaml` | Namespace PSA labels: `governance-stack` (restricted), `langfuse` (baseline), `vllm` (baseline) |
| `security-context-patch.yaml` | Pod security context patches |
| `linkerd-mtls-policy.yaml` | Linkerd mTLS `AuthorizationPolicy` |
| `cilium-egress-lockdown.yaml` | Cilium egress `NetworkPolicy` |
| `network-policy.yaml` | Default deny + allow rules |
| `network-policy-hardening.yaml` | Hardened network policies |
| `lula-network-policy.yaml` | NetworkPolicy for Lula compliance scanner |
| `trivy-egress-policy.yaml` | Egress policy for Trivy scanner |

### Compliance and operations

| File | Description |
|------|-------------|
| `lula-cron.yaml` | Scheduled Lula compliance scan CronJob |
| `lula-rbac.yaml` | RBAC for Lula scanner |
| `security-scan-cronjob.yaml` | Security scan CronJob (Trivy) |
| `sbom-cronjob.yaml` | SBOM generation CronJob |
| `oscal-artifact-secrets.yaml` | OSCAL artifact secret template |
| `service-account.yaml` | `financial-advisor-sa` ServiceAccount |
| `ingress.yaml` | GCE Ingress (HTTPS; uses NodePort 30080 for gateway) |
| `db-reset.yaml` | Database reset Job (one-time; dev only) |

### Inference Gateway (KEP-4121)

| File | Description |
|------|-------------|
| `inference-gateway/gateway.yaml` | Gateway API `Gateway` resource |
| `inference-gateway/http-route.yaml` | `HTTPRoute` for inference routing |
| `inference-gateway/inference-pool.yaml` | `InferencePool` resource |
| `inference-gateway/reference-grant.yaml` | `ReferenceGrant` for cross-namespace routing |

---

## Prerequisites

### For GCP deployments

- `gcloud` CLI authenticated (`gcloud auth application-default login`)
- GCP project with billing enabled
- APIs enabled: `container.googleapis.com`, `compute.googleapis.com`, `storage.googleapis.com`, `cloudbuild.googleapis.com`
- IAM: Kubernetes Engine Admin, Cloud Build Editor, Storage Admin

### For any Kubernetes target

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
| `CAGE_ROUTING_SEAL_SECRET` | HMAC routing seal (≥ 32 chars; required in production) → `TF_VAR_routing_seal_secret` |
| `HUGGING_FACE_HUB_TOKEN` | HuggingFace token for model downloads → `TF_VAR_hf_token` |
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

# Agent query
curl -X POST http://localhost:18080/agent/query \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello"}'
```

### Makefile targets

```bash
make advisor-status        # governed-financial-advisor pod status
make advisor-rollback      # rollout undo
make advisor-watch         # watch pod events
make advisor-verify-env    # dump env vars in running pod
make advisor-port-forward  # forward svc/governed-financial-advisor 8080:8080
make advisor-health        # /health check
make vllm-status           # vLLM pod status
make vllm-verify-models    # list loaded models on both vLLM services
make test-integration      # run local (non-infrastructure) tests
make recovery              # print recovery checklist
```

---

## Model Weight Loading

GCS (`gs://<bucket>/`) is the **primary** model artifact store. vLLM pods stream weights directly from GCS at startup.

### One-time tensorization (optional MinIO path)

```bash
kubectl apply -f deployment/k8s/tensorize-job.yaml -n governance-stack
kubectl wait --for=condition=complete job/tensorize-weights \
  --timeout=30m -n governance-stack
```

This downloads weights from HuggingFace Hub, serializes to TensorSerializer format, and uploads to MinIO `vllm-models` bucket. Once tensorized, vLLM starts in ~60–90 seconds instead of ~20 minutes.

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
| `slm` | 5000 | Sentence-transformers sidecar (all-MiniLM-L6-v2) |
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
# Review diff, then:
kubectl apply -f deployment/k8s/nemo-rails-configmap.yaml
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

See [`deployment/TERRAFORM_MIGRATION.md`](TERRAFORM_MIGRATION.md) for migration notes.

---

## Security Notes

- All application Secrets use `secretKeyRef` / `secretRef` — never plain `value:` for sensitive data.
- The `governance-stack` namespace enforces PSA `restricted:latest` (no privileged containers, no root, RuntimeDefault seccomp).
- The `vllm-inference` namespace uses PSA `baseline` for GPU/CUDA access.
- The `agentsight` namespace requires PSA `privileged` for eBPF (host PID + network).
- `CAGE_ROUTING_SEAL_SECRET` must be ≥ 32 characters; the gateway raises `RuntimeError` at startup if absent and `CAGE_ENV=production`.
- `KMS_GOVERNANCE_KEY` activates Cloud KMS asymmetric signing (CTRL_KMS_001); HMAC fallback is dev/CI only.

---

## Related Documentation

- [`infra/QUICK_START.md`](../infra/QUICK_START.md) — infrastructure quick-start
- [`infra/DEPLOYMENT_GUIDE.md`](../infra/DEPLOYMENT_GUIDE.md) — full deployment reference
- [`deployment/k8s/NAMESPACE-GUIDE.md`](k8s/NAMESPACE-GUIDE.md) — namespace inventory and Redis topology
- [`deployment/agentsight/README.md`](agentsight/README.md) — AgentSight setup
- [`deployment/TERRAFORM_MIGRATION.md`](TERRAFORM_MIGRATION.md) — Terraform migration notes
- [`docs/operations/DEPLOYMENT_RULES.md`](../docs/operations/DEPLOYMENT_RULES.md) — deployment rules (Cloud Build requirement)
