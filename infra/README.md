# CAGE Infrastructure with Terraform

This directory contains infrastructure-as-code for deploying the Cybernetic Governance Engine (CAGE) to Google Kubernetes Engine ([`infra/targets/gcp-gke/`](targets/gcp-gke/)). For local and cloud-agnostic development without cloud dependencies, use [`docker-compose.yml`](../docker-compose.yml) (`docker compose up --build`).

## 📁 Directory Structure

```
infra/
├── load_env.sh                     # Script to export .env as TF_VAR_* variables
├── ENV_INTEGRATION.md              # Detailed guide for .env → Terraform integration
├── modules/                        # Reusable Terraform modules
│   ├── agentsight_ui/              # AgentSight UI frontend
│   ├── app_secrets/                # Kubernetes Secrets management
│   ├── clickhouse_operator/        # ClickHouse analytical query plane
│   ├── cloudsql_postgres/          # Cloud SQL PostgreSQL database
│   ├── compliance_bridge/          # Langfuse → Lula compliance bridge
│   ├── deployment_config/          # Shared deployment ConfigMap
│   ├── gateway/                    # Inference & Governance Gateway
│   ├── gcp_gke_cluster/            # GKE cluster with NIST controls
│   ├── governed_advisor/           # Governed Financial Advisor on GKE
│   ├── k8s_namespace/              # Namespace with Pod Security Standards
│   ├── kms/                        # Cloud KMS keyring & CMEK keys
│   ├── langfuse_stack/             # Langfuse observability platform
│   ├── memorystore_redis/          # Memorystore Redis instance
│   ├── memorystore_valkey/         # Memorystore Valkey instance
│   ├── nemo_guardrails/            # Standalone NeMo Guardrails service
│   ├── opa_policy/                 # Open Policy Agent
│   ├── service_mesh/               # Linkerd service mesh & mTLS
│   ├── vllm_inference/             # vLLM inference engine
│   ├── vpc_network/                # VPC, subnet, Cloud Router & NAT
│   └── worm_bucket/                # Retention-locked GCS WORM evidence bucket
└── targets/                        # Deployment target
    └── gcp-gke/                    # Google Cloud GKE (sole shipped target)
        ├── main.tf                 # GKE deployment
        ├── variables.tf            # Configurable parameters
        ├── dev.tfvars              # Development configuration
        ├── staging.tfvars          # Staging configuration
        ├── prod.tfvars             # Production configuration
        └── terraform.auto.tfvars.example  # Template for local overrides
```

## 🚀 Quick Start

### Prerequisites

- Terraform >= 1.5.0
- kubectl
- Access to a GCP project (`gcloud auth application-default login`)
- `.env` file configured (see `.env.example` in project root)

### Option 1: Using deploy_all.sh (Recommended)

The simplest method — automatically loads `.env`, builds/attests images via Cloud Build, and runs Terraform:

```bash
# Local / cloud-agnostic development (Docker Compose, no Kubernetes required)
docker compose up --build

# Deploy to GCP GKE (staging profile)
./deploy_all.sh --target gcp-gke --env staging --var project_id=<PROJECT_ID> --auto-approve
```

**What it does:**
1. Loads `.env` and exports as `TF_VAR_*` variables
2. Runs `terraform init` with the GCS state backend
3. Builds and attests container images via Cloud Build and renders `image_digests.<short_sha>.tfvars.json`
4. Runs `terraform plan` and `terraform apply` with environment-specific `.tfvars`

### Option 2: Manual Terraform

If you prefer to run Terraform directly:

```bash
# 1. Load environment variables
source ./infra/load_env.sh

# 2. Navigate to target
cd infra/targets/gcp-gke

# 3. Initialize Terraform
terraform init

# 4. Plan deployment
terraform plan -var-file="dev.tfvars"

# 5. Apply
terraform apply -var-file="dev.tfvars"
```

## 🎯 Deployment Target

### GCP-GKE Target (`infra/targets/gcp-gke/`)

Provision and deploy to Google Kubernetes Engine (the sole shipped Kubernetes/Terraform target; the unvalidated `2bacc478:infra/targets/agnostic/` target was retired in `POAM-2026-185`):
- ✅ Creates GKE cluster with NIST security controls and dedicated node service account (`cage-gke-nodes-<env>`)
- ✅ Retention-locked GCS WORM bucket for tamper-evident evidence storage
- ✅ GPU node pools for vLLM inference
- ✅ Cloud Build integration with Binary Authorization attestation
- ✅ CMEK, Private endpoints, and Linkerd mTLS workload identity

**Configuration:**
```bash
cd infra/targets/gcp-gke
terraform apply -var-file="dev.tfvars"
```

See [`targets/gcp-gke/README.md`](targets/gcp-gke/README.md) for details.

## 🔐 Environment Variable Integration

CAGE uses `.env` for configuration to avoid duplication between Docker Compose and Terraform.

### Quick Reference

```bash
# Method 1: Automatic (via deploy_all.sh)
./deploy_all.sh --target gcp-gke --env dev
# ✅ Automatically loads .env and exports TF_VAR_* variables

# Method 2: Manual sourcing
source ./infra/load_env.sh
cd infra/targets/gcp-gke
terraform apply
# ✅ Exports .env → TF_VAR_* in current shell

# Method 3: terraform.auto.tfvars
cd infra/targets/gcp-gke
cp terraform.auto.tfvars.example terraform.auto.tfvars
# Edit terraform.auto.tfvars with your values
terraform apply
# ✅ Auto-loaded by Terraform
```

### Supported Variables

| .env Variable | Terraform Variable | Purpose |
|---------------|-------------------|---------|
| `LANGFUSE_PUBLIC_KEY` | `langfuse_public_key` | Langfuse API key |
| `LANGFUSE_SECRET_KEY` | `langfuse_secret_key` | Langfuse secret |
| `AWS_ACCESS_KEY_ID` | `aws_access_key` | S3/MinIO access |
| `MODEL_REASONING` | `model_reasoning` | Reasoning model path |
| `K8S_NAMESPACE` | `namespace` | Kubernetes namespace |
| `REGISTRY_URL` | `registry_url` | Container registry |

**Full mapping:** See [`ENV_INTEGRATION.md`](ENV_INTEGRATION.md) for complete list.

## 📦 Modules

### Infrastructure Modules

- **[`gcp_gke_cluster`](modules/gcp_gke_cluster/)** - GKE cluster with NIST controls
- **[`vpc_network`](modules/vpc_network/)** - VPC, subnet, Cloud Router & NAT
- **[`kms`](modules/kms/)** - Cloud KMS keyring and CMEK keys
- **[`worm_bucket`](modules/worm_bucket/)** - Retention-locked GCS WORM evidence bucket
- **[`cloudsql_postgres`](modules/cloudsql_postgres/)** - Cloud SQL PostgreSQL database
- **[`memorystore_redis`](modules/memorystore_redis/)** - Memorystore Redis instance
- **[`memorystore_valkey`](modules/memorystore_valkey/)** - Memorystore Valkey instance
- **[`service_mesh`](modules/service_mesh/)** - Linkerd service mesh and mTLS
- **[`k8s_namespace`](modules/k8s_namespace/)** - Namespace with PSS/PSA

### Application Modules

- **[`vllm_inference`](modules/vllm_inference/)** - vLLM GPU inference
- **[`langfuse_stack`](modules/langfuse_stack/)** - Observability platform
- **[`clickhouse_operator`](modules/clickhouse_operator/)** - ClickHouse analytical query plane
- **[`opa_policy`](modules/opa_policy/)** - Policy engine
- **[`compliance_bridge`](modules/compliance_bridge/)** - ISO 42001 auditing
- **[`agentsight_ui`](modules/agentsight_ui/)** - AgentSight UI frontend
- **[`app_secrets`](modules/app_secrets/)** - Kubernetes Secrets management
- **[`deployment_config`](modules/deployment_config/)** - Shared deployment ConfigMap
- **[`gateway`](modules/gateway/)** - Inference Gateway
- **[`governed_advisor`](modules/governed_advisor/)** - Governed Financial Advisor backend
- **[`nemo_guardrails`](modules/nemo_guardrails/)** - Standalone NeMo Guardrails service

Each module includes:
- ✅ `README.md` - Documentation
- ✅ `variables.tf` - Configurable inputs
- ✅ `outputs.tf` - Exported values
- ✅ `main.tf` - Resource definitions

## 🔒 Security Best Practices

### ✅ DO

1. **Use `.env` for secrets in local development**
   ```bash
   cp .env.example .env
   # Edit .env - it's in .gitignore
   ```

2. **Use secret managers in production**
   - GCP: Secret Manager
   - AWS: Secrets Manager
   - K8s: External Secrets Operator

3. **Mark sensitive variables**
   ```hcl
   variable "langfuse_secret_key" {
     type      = string
     sensitive = true  # Won't show in logs
   }
   ```

4. **Use separate Langfuse projects**
   - App performance: `LANGFUSE_PUBLIC_KEY`
   - Compliance audits: `LANGFUSE_COMPLIANCE_PUBLIC_KEY`

### ❌ DON'T

1. **Never commit secrets**
   ```bash
   # Already in .gitignore:
   .env
   *.auto.tfvars
   terraform.tfstate
   ```

2. **Don't use plaintext secrets in version-controlled files**
   ```hcl
   # dev.tfvars (version controlled) ❌ BAD
   langfuse_secret_key = "sk-lf-actual-secret"
   
   # dev.tfvars (version controlled) ✅ GOOD
   environment = "dev"
   # Secrets loaded from .env or terraform.auto.tfvars
   ```

## 🎛️ Environment-Specific Configuration

### Development (dev)

```hcl
# dev.tfvars
environment = "dev"
enable_nist_compliance = false
inference_backend = "none"  # no model; "vllm" for a live agent (see targets/gcp-gke/README.md)
primary_node_pool_min_count = 1
```

**Characteristics:**
- Minimal security (fast iteration)
- Single replicas
- No PodDisruptionBudgets
- Local/MinIO storage

### Production (prod)

```hcl
# prod.tfvars
environment = "prod"
enable_nist_compliance = true
enable_audit_logging = true
enable_binary_authorization = true
primary_node_pool_min_count = 3
```

**Characteristics:**
- Full NIST RMF controls
- HA Redis (3 replicas + Sentinel)
- PodDisruptionBudgets
- Resource limits enforced
- Deletion protection
- Encrypted storage (CMEK)

## 🧪 Testing Deployments

```bash
# Dry-run (no changes)
terraform plan -var-file="dev.tfvars"

# Preview changes
terraform plan -var-file="dev.tfvars" -out=tfplan
terraform show tfplan

# Apply with approval
terraform apply -var-file="dev.tfvars"

# Auto-approve (CI/CD)
terraform apply -var-file="dev.tfvars" -auto-approve
```

## 🔄 Updating Infrastructure

```bash
# Check for drift
terraform plan -var-file="dev.tfvars"

# Apply changes
terraform apply -var-file="dev.tfvars"

# Refresh state
terraform refresh -var-file="dev.tfvars"
```

## 🗑️ Destroying Infrastructure

```bash
# Destroy specific target
cd infra/targets/gcp-gke
terraform destroy -var-file="dev.tfvars"

# Preview destruction
terraform plan -destroy -var-file="dev.tfvars"
```

**⚠️ Warning:** This will delete:
- GKE cluster (gcp-gke target)
- All persistent volumes
- All data in databases
- Object storage buckets (if `force_destroy = true`)

## 📚 Documentation

- **[ENV_INTEGRATION.md](ENV_INTEGRATION.md)** - Complete .env → Terraform guide
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Step-by-step deployment
- **[TESTING_PLAN.md](TESTING_PLAN.md)** - Validation procedures

## 🆘 Troubleshooting

### Problem: Variables not loading from .env

```bash
# Verify .env exists
ls -la .env

# Re-source the script
source ./infra/load_env.sh

# Check exports
env | grep TF_VAR_
```

### Problem: GCP authentication fails

```bash
# Login to GCP
gcloud auth application-default login

# Set project
gcloud config set project YOUR_PROJECT_ID

# Verify
gcloud auth list
```

## 🤝 Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for infrastructure contribution guidelines.

## 📄 License

Apache License 2.0 - See [NOTICE](../NOTICE) for details.
