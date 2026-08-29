# CAGE Deployment Rules & Best Practices

> **Reference architecture only.** CAGE demonstrates governance patterns for AI systems;
> it is not deployed to production. The deployment rules below are **illustrative**
> patterns for adopters.

> **Critical Policy:** This document defines mandatory deployment rules that all
> contributors (human and AI agent) must follow. The canonical source for the
> summary of these rules is [`AGENTS.md`](../../AGENTS.md) §Deployment Rules.

---

## 🚨 GKE Deployment Policy — Cloud Build Mandatory

**When deploying to Google Kubernetes Engine (GKE), you MUST use Cloud Build.
Local `docker build` is prohibited for GKE-targeted images.**

### Why This Matters

| Issue | Local Docker Build | Cloud Build |
|-------|-------------------|-------------|
| **Platform consistency** | ❌ May produce ARM64 on M-series Macs; GKE nodes run AMD64 | ✅ Always AMD64 |
| **Build reproducibility** | ❌ Depends on local environment | ✅ Controlled environment |
| **Security scanning** | ❌ Manual/optional | ✅ Integrated via Cloud Logging |
| **Audit trail** | ❌ No automated logs | ✅ Full build provenance in GCP |
| **Team collaboration** | ❌ "Works on my machine" | ✅ Consistent across developers |

---

## Deployment Entry Point

All deployments are driven by [`deploy_all.sh`](../../deploy_all.sh) at the
repository root. Direct use of `terraform apply` or `gcloud builds submit` is
supported for advanced scenarios but `deploy_all.sh` is the approved entry point
for end-to-end deployment.

### ✅ Approved Methods for GKE

```bash
# Full deployment to GKE dev
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# Full deployment to GKE dev (background — survives terminal closure)
make deploy-bg TARGET=gcp-gke ENV=dev EXTRA_ARGS="--auto-approve"

# Direct Cloud Build submit (single service)
gcloud builds submit \
  --config deployment/docker/cloudbuild.gateway.yaml \
  --substitutions=_GCP_PROJECT_ID=<PROJECT_ID>
```

### ✅ Approved Methods for Local / Agnostic

```bash
# Deploy to any existing Kubernetes cluster (k3s, EKS, AKS, GKE)
./deploy_all.sh --target agnostic --env dev
```

### ❌ Prohibited for GKE

```bash
# NEVER — architecture mismatch crashes GKE pods
docker build -t gcr.io/PROJECT/image:tag .
docker push gcr.io/PROJECT/image:tag
kubectl apply -f deployment.yaml   # without a preceding Cloud Build step

# NEVER
docker-compose build && docker-compose push
--platform linux/amd64   # local/BuildKit cross-compilation
```

---

## `deploy_all.sh` Options

```
Usage: ./deploy_all.sh --target TARGET --env ENV [OPTIONS]

Targets:
  agnostic     Deploy to any existing Kubernetes cluster (k3s, EKS, AKS, GKE)
  gcp-gke      Provision and deploy to Google Cloud GKE cluster

Environments:
  dev          Development (fast iteration, reduced security posture)
  prod         Production (ISO 42001 baseline hardening; jurisdiction-specific
               posture controlled by CAGE_DEPLOYMENT_REGION)

Options:
  --auto-approve          Skip Terraform confirmation prompts
  --var-file=PATH         Additional .tfvars file (e.g. prod.tfvars)
  --skip-build            Skip container image builds (Cloud Build step)
  --kubeconfig=PATH       Kubeconfig path (agnostic target only)
  --var KEY=VALUE         Override any Terraform variable
```

### `staging` environment

**Status**: Provisioned (POAM-024 closed 2026-08-29)

The `staging` environment is an ephemeral pre-production validation tier that
proves full security posture at dev-scale cost:

- **Purpose**: Validate all Lula gates, region postures, and cluster-scoped
  controls (Binary Authorization, PSS, CMEK, audit logs) at 1-replica scale
  before promoting to production.
- **Cost**: ~$2-4 per validation cycle (20-30 minutes runtime, sub-hour usage).
- **Lifecycle**: Provision → Validate → Destroy (automated via `scripts/staging_lifecycle.sh`).
- **Hardware**: Dev-scale (e2-standard-4 nodes, pd-standard disks, GPU scale-to-zero).
- **Security**: Full prod posture (enable_nist_compliance=true for US_FED,
  Binary Authorization, audit logging, CMEK, PSS restricted, scoped authorized_networks).
- **HA**: Decoupled (`enable_high_availability=false`, 1 replica per service).
- **Deletion protection**: Disabled (`enable_deletion_protection=false`, allows teardown).

**Deployment**:
```bash
# Automated lifecycle (recommended)
./scripts/staging_lifecycle.sh

# Manual deployment
./deploy_all.sh --target gcp-gke --env staging --auto-approve

# Manual teardown
cd infra/targets/gcp-gke
terraform destroy -var-file=staging.tfvars -auto-approve
```

See [`infra/targets/gcp-gke/staging.tfvars`](../../infra/targets/gcp-gke/staging.tfvars)
for full configuration and [`scripts/staging_lifecycle.sh`](../../scripts/staging_lifecycle.sh)
for automated validation workflow.

---

## Deployment Target Matrix

> **Jurisdiction prerequisite:** Set `CAGE_DEPLOYMENT_REGION` in `.env` (or as
> an environment variable) before running any `prod` deployment. The script
> propagates it to `TF_VAR_cage_deployment_region`. The `--env prod` flag
> activates ISO 42001 baseline hardening; NIST SP 800-53 hardening
> (`enable_nist_compliance`) is additionally activated only for `US_FED`.

| `CAGE_DEPLOYMENT_REGION` | `--var-file` | GCP region |
|--------------------------|-------------|------------|
| `US_FED` | `infra/targets/gcp-gke/prod.tfvars` | `us-central1` |
| `EU_ECB` | `infra/targets/gcp-gke/eu-prod.tfvars` | `europe-west1` |
| `APAC_MAS` | `infra/targets/gcp-gke/apac-prod.tfvars` | `asia-southeast1` |

| Target | Env | Jurisdiction | Command |
|--------|-----|-------------|---------|
| `gcp-gke` | `prod` | US_FED | `CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/prod.tfvars` |
| `gcp-gke` | `prod` | EU_ECB | `CAGE_DEPLOYMENT_REGION=EU_ECB ./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/eu-prod.tfvars` |
| `gcp-gke` | `prod` | APAC_MAS | `CAGE_DEPLOYMENT_REGION=APAC_MAS ./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/apac-prod.tfvars` |
| `gcp-gke` | `dev` | Any | `CAGE_DEPLOYMENT_REGION=<REGION> ./deploy_all.sh --target gcp-gke --env dev --auto-approve` |
| `agnostic` | `dev` | Any | `./deploy_all.sh --target agnostic --env dev` |

---

## Cloud Build Configuration Files

All Cloud Build configs live under [`deployment/docker/`](../docker/).
`scripts/build_images.sh` generates ephemeral Cloud Build configs for most
services and submits them in parallel; the pre-built configs below are used for
direct `gcloud builds submit` invocations.

| Service | Config file | Substitutions |
|---------|------------|---------------|
| Gateway | `deployment/docker/cloudbuild.gateway.yaml` | `_GCP_PROJECT_ID`, `_SHORT_SHA` |
| Governed Financial Advisor | `deployment/docker/cloudbuild.advisor.yaml` | — |
| vLLM streamer | `deployment/docker/cloudbuild.vllm.yaml` | `_SHORT_SHA`, `_HF_TOKEN` (optional) |
| Compliance bridge | `deployment/docker/cloudbuild.compliance.yaml` | — |
| Lula validation | `deployment/docker/cloudbuild.lula.yaml` | — |
| NeMo Guardrails | `deployment/docker/cloudbuild.nemo.yaml` | — |
| AgentSight UI | `deployment/docker/cloudbuild.ui.yaml` | — |

`scripts/build_images.sh` builds the following images in parallel via Cloud Build:
1. `governed-financial-advisor` / `financial-advisor` (root `Dockerfile`)
2. `gateway` (`src/gateway/Dockerfile`)
3. `agentsight-ui` (`src/agentsight-ui/Dockerfile`)
4. `compliance-bridge` (`src/compliance_bridge/Dockerfile`)
5. `nemo-guardrails` (`deployment/docker/Dockerfile.nemo`)
6. vLLM streamer (`deployment/docker/cloudbuild.vllm.yaml`)

All images are tagged `:latest` and `:<short-sha>` and pushed to
`gcr.io/<PROJECT_ID>/<image-name>`.

---

## Background Deployment (Makefile Targets)

For long-running deployments that must survive terminal/tool closure, use the
`scripts/deploy_bg.sh`-backed Makefile targets:

```bash
# Launch full deployment in background
make deploy-bg TARGET=gcp-gke ENV=dev EXTRA_ARGS="--auto-approve"

# Launch image builds only (no Terraform)
make build-bg

# Check status of in-progress deployment
make deploy-status

# Tail live log output
make deploy-logs

# Cancel in-progress deployment
make deploy-kill
```

Background deployments write logs to `/tmp/cage-deploy-*.log` and their PIDs to
`/tmp/cage-deploy.pid`.

---

## Terraform Rules

- `terraform plan` must **always** precede `terraform apply`. `deploy_all.sh`
  enforces this automatically.
- Never edit Terraform state directly.
- Secret values belong in `terraform.auto.tfvars` (gitignored via
  `scripts/gen_tfvars.py`) — never in committed `.tf` files.
- Active IaC lives under `infra/targets/`. The removed `deployment/terraform/`
  directory is historical reference only (see
  [`deployment/TERRAFORM_MIGRATION.md`](../TERRAFORM_MIGRATION.md)).

### Terraform state backends

| Target | Backend | State path |
|--------|---------|-----------|
| `gcp-gke` | GCS (optional, configure in `infra/targets/gcp-gke/providers.tf`) | `cage/gcp-gke` |
| `agnostic` | Kubernetes Secret | namespace `terraform-state`, suffix `tfstate-agnostic` |

For the agnostic target, ensure the namespace exists before the first deploy:

```bash
kubectl create namespace terraform-state
```

---

## Pre-Deployment Checklist

- [ ] `CAGE_DEPLOYMENT_REGION` set correctly (`US_FED` / `EU_ECB` / `APAC_MAS`)
- [ ] `.env` populated (copy `.env.example` to `.env` if needed)
- [ ] `infra/targets/gcp-gke/terraform.auto.tfvars` will be generated by
      `scripts/gen_tfvars.py` (gcp-gke target only — do not commit this file)
- [ ] GCP credentials available: `gcloud auth application-default login`
- [ ] `kubectl` context correct: `kubectl config current-context`
- [ ] For GKE: Cloud Build API enabled, service account has `roles/container.developer`

---

## Post-Deployment Verification

```bash
# Check Cloud Build history
gcloud builds list --limit=5 --project=<PROJECT_ID>

# Check pod status (default namespace)
kubectl get pods -n governance-stack

# Verify key services
kubectl get deployments -n governance-stack

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack
# Open: http://localhost:9001

# Port-forward all dev services (auto-reconnecting)
bash scripts/port_forward_dev.sh
```

### Make targets for ongoing operations

```bash
# vLLM diagnostics
make vllm-status          # pod status for vLLM
make vllm-verify-models   # query /v1/models on each vLLM service

# Financial advisor diagnostics
make advisor-status        # pod status
make advisor-health        # curl /health via port-forward
make advisor-rollback      # kubectl rollout undo
make advisor-watch         # live pod watch
make advisor-verify-env    # env dump (no secrets)
make advisor-port-forward  # port-forward to localhost:8080

# Recovery checklist
make recovery             # prints ordered recovery steps
```

---

## Exception Process for Cloud Build Unavailability

If Cloud Build is unavailable:

1. **Do not** proceed with local Docker builds for GKE.
2. Investigate:
   - GCP Console → Cloud Build → History
   - Verify Cloud Build service account permissions
   - Check GCP quotas and billing status
3. Fix the Cloud Build issue.
4. Only if Cloud Build is permanently unavailable: escalate to a senior
   engineer for written approval before any local build path is used.

---

## Troubleshooting

### Cloud Build: "Permission denied"

```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member=serviceAccount:<PROJECT_NUMBER>@cloudbuild.gserviceaccount.com \
  --role=roles/container.developer
```

### Cloud Build: "Quota exceeded"

```bash
gcloud compute project-info describe --project=<PROJECT_ID>
# Request quota increase in GCP Console if needed
```

### Terraform: "terraform-state namespace not found" (agnostic)

```bash
kubectl create namespace terraform-state
```

### Terraform: "Storage class not found" (k3s)

```bash
kubectl get storageclass
# Update infra/targets/agnostic/dev.tfvars with correct storage_class value
```

### Pods in CrashLoopBackOff after deployment

```bash
make advisor-rollback   # rolls back governed-financial-advisor
make advisor-watch      # monitors recovery
```

---

## Compliance Note

Cloud Build deployments support the following controls:

- **ISO 42001 A.5.2** — AI system deployment control
- **NIST AI RMF** — Controlled deployment practices
- **SOC 2 CC8.1** — Change management controls

All GKE deployments via Cloud Build are automatically logged to Cloud Logging
for audit purposes.

---

## Related Documentation

- [`AGENTS.md`](../../AGENTS.md) — canonical source for deployment rules summary
- [`docs/operations/DEPLOYMENT_DECISION_RECORD.md`](DEPLOYMENT_DECISION_RECORD.md) — ADRs
- [`infra/QUICK_START.md`](../../infra/QUICK_START.md) — 5-minute quick start
