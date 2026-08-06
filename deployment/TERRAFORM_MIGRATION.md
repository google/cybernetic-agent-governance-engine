# Terraform Infrastructure Migration

**Migration Date:** 2026-03-15  
**Old Location:** `deployment/terraform/` (REMOVED)  
**New Location:** `infra/`

---

## What Changed

The mixed Terraform code in `deployment/terraform/` has been **completely removed** and replaced with a modular, target-oriented structure in `infra/`.

### Old Structure (REMOVED 2026-03-15)

```
deployment/terraform/        ← deleted
├── main.tf               # mixed concerns (cluster + app)
├── gcp/
│   ├── gke.tf
│   ├── storage.tf
│   └── iam.tf
├── gke.tf                # actually K8s namespace (naming confusion)
├── agentsight.tf
├── secrets.tf
└── variables.tf
```

### New Structure

```
infra/
├── modules/                   # reusable Terraform modules
│   ├── gcp_gke_cluster/       # GKE cluster + node pools + networking
│   ├── k8s_namespace/         # Kubernetes namespace with PSA labels
│   ├── minio_storage/         # MinIO S3-compatible object storage
│   ├── postgres_db/           # PostgreSQL (Bitnami Helm chart)
│   ├── redis_cache/           # Redis Sentinel HA (Bitnami Helm chart)
│   ├── langfuse_stack/        # Langfuse v3 Web + Worker
│   ├── compliance_bridge/     # Compliance bridge deployment
│   ├── opa_policy/            # OPA policy engine
│   ├── gateway/               # Gateway deployment
│   ├── governed_advisor/      # Governed Financial Advisor
│   ├── nemo_guardrails/       # NeMo Guardrails
│   ├── vllm_inference/        # vLLM inference backend
│   ├── slm_inference/         # SLM similarity sidecar
│   ├── clickhouse/            # ClickHouse (Langfuse v3 requirement)
│   ├── agentsight_ui/         # AgentSight UI
│   ├── app_secrets/           # Kubernetes Secrets provisioning
│   └── app_secrets/           # Kubernetes Secrets provisioning
│
└── targets/                   # deployment endpoints
    ├── agnostic/              # cloud-agnostic (k3s, EKS, AKS, any K8s ≥ 1.24)
    │   ├── main.tf
    │   ├── dev.tfvars
    │   ├── prod.tfvars
    │   ├── providers.tf       # Kubernetes backend (state in cluster)
    │   └── terraform.auto.tfvars.example
    └── gcp-gke/               # GCP GKE with full compliance posture support
        ├── main.tf
        ├── variables.tf
        ├── providers.tf       # GCS backend (state in GCS bucket)
        ├── iam.tf             # IAM service accounts, Workload Identity
        ├── dev.tfvars
        ├── prod.tfvars        # US_FED: ISO 42001 + NIST SP 800-53
        ├── eu-dev.tfvars
        ├── eu-prod.tfvars     # EU_ECB: ISO 42001 + EU AI Act / GDPR / DORA
        ├── apac-dev.tfvars
        ├── apac-prod.tfvars   # APAC_MAS: ISO 42001 + MAS FEAT / Notice 655 / TRM
        ├── us-dev.tfvars
        └── terraform.auto.tfvars.example
```

---

## How to Deploy

### Old Way (DEPRECATED — do not use)

```bash
# DEPRECATED — directory removed 2026-03-15
cd deployment/terraform
terraform apply
```

### New Way (RECOMMENDED)

```bash
# Cloud-agnostic deployment (k3s, EKS, AKS, any Kubernetes ≥ 1.24)
./deploy_all.sh --target agnostic --env dev

# GCP GKE deployment — dev
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

---

## State Backends

### GCP-GKE Target (GCS backend)

State is stored in a GCS bucket. The bucket name is not committed; it is supplied at init time:

```bash
export TF_BACKEND_BUCKET="${PROJECT_ID}-tfstate"
terraform -chdir=infra/targets/gcp-gke init \
  -backend-config="bucket=${TF_BACKEND_BUCKET}"
```

Or set `TF_CLI_ARGS_init="-backend-config=bucket=${PROJECT_ID}-tfstate"`.

The `prefix` is hardcoded to `cage/gcp-gke` in `providers.tf`.

### Agnostic Target (Kubernetes backend)

State is stored as a Kubernetes Secret in the cluster. Create the namespace first:

```bash
kubectl create namespace terraform-state
terraform -chdir=infra/targets/agnostic init \
  -backend-config="config_path=~/.kube/config"
```

---

## Jurisdictional Compliance — `CAGE_DEPLOYMENT_REGION`

The `gcp-gke` target exposes `cage_deployment_region` as a Terraform variable. `deploy_all.sh` propagates the shell environment variable `CAGE_DEPLOYMENT_REGION` to `TF_VAR_cage_deployment_region` automatically.

| `CAGE_DEPLOYMENT_REGION` | var-file | NIST hardening | Regional flag |
|--------------------------|----------|----------------|---------------|
| `US_FED` | `prod.tfvars` | `enable_nist_compliance=true` | — |
| `EU_ECB` | `eu-prod.tfvars` | `enable_nist_compliance=false` | `enable_eu_ecb_compliance=true` |
| `APAC_MAS` | `apac-prod.tfvars` | `enable_nist_compliance=false` | `enable_apac_mas_compliance=true` |

NIST SP 800-53 hardening (private cluster, master authorized networks, deletion protection, Redis replication) is **only activated for `US_FED`**. ISO 42001 baseline hardening is always active in all `prod` deployments regardless of region.

---

## `terraform.auto.tfvars` (gitignored)

`deploy_all.sh` auto-generates `infra/targets/gcp-gke/terraform.auto.tfvars` from `.env` via `scripts/gen_tfvars.py`. This file contains secrets and is gitignored. It must **never** be committed.

To generate manually:

```bash
uv run python scripts/gen_tfvars.py \
  --env .env \
  --output infra/targets/gcp-gke/terraform.auto.tfvars
```

---

## Module Reference

All modules under `infra/modules/` have complete variable definitions, outputs, and (where applicable) README documentation.

| Module | README | Purpose |
|--------|--------|---------|
| `gcp_gke_cluster` | [README](../infra/modules/gcp_gke_cluster/README.md) | GKE cluster + node pools |
| `langfuse_stack` | [README](../infra/modules/langfuse_stack/README.md) | Langfuse v3 observability |
| `postgres_db` | [README](../infra/modules/postgres_db/README.md) | PostgreSQL (Bitnami Helm) |
| `minio_storage` | [README](../infra/modules/minio_storage/README.md) | MinIO object storage |
| `redis_cache` | [README](../infra/modules/redis_cache/README.md) | Redis Sentinel HA |
| `compliance_bridge` | [README](../infra/modules/compliance_bridge/README.md) | Compliance bridge |
| `opa_policy` | [README](../infra/modules/opa_policy/README.md) | OPA policy engine |
| `clickhouse` | [README](../infra/modules/clickhouse/README.md) | ClickHouse (Langfuse v3) |

---

## Rollback

If you need to inspect the pre-migration state:

```bash
# Find the commit that removed deployment/terraform/
git log --oneline --all | grep -i "terraform"

# Check out the old files at a specific commit (read-only)
git show <commit-hash>:deployment/terraform/main.tf

# Restore to a working directory (creates a local branch)
git checkout -b restore-old-terraform <commit-hash>
```

---

## Related Documentation

- [`infra/QUICK_START.md`](../infra/QUICK_START.md) — 5-minute quick start
- [`infra/DEPLOYMENT_GUIDE.md`](../infra/DEPLOYMENT_GUIDE.md) — full deployment reference
- [`infra/modules/`](../infra/modules/) — module documentation
- [`docs/operations/DEPLOYMENT_RULES.md`](../docs/operations/DEPLOYMENT_RULES.md) — Cloud Build requirement for GKE
- [`infra/IMPLEMENTATION_STATUS.md`](../infra/IMPLEMENTATION_STATUS.md) — component status
