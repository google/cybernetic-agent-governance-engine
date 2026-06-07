# CAGE Infrastructure with Terraform

This directory contains infrastructure-as-code for deploying the Cybernetic Governance Engine (CAGE) across different cloud providers and Kubernetes distributions.

## 📁 Directory Structure

```
infra/
├── load_env.sh                     # Script to export .env as TF_VAR_* variables
├── ENV_INTEGRATION.md              # Detailed guide for .env → Terraform integration
├── modules/                        # Reusable Terraform modules
│   ├── compliance_bridge/          # Langfuse → Lula compliance bridge
│   ├── gcp_gke_cluster/           # GKE cluster with NIST controls
│   ├── k8s_namespace/             # Namespace with Pod Security Standards
│   ├── langfuse_stack/            # Langfuse observability platform
│   ├── minio_storage/             # MinIO object storage
│   ├── opa_policy/                # Open Policy Agent
│   ├── postgres_db/               # PostgreSQL database
│   ├── redis_cache/               # Redis cache
│   └── vllm_inference/            # vLLM inference engine
└── targets/                        # Deployment targets
    ├── agnostic/                   # Cloud-agnostic (any K8s cluster)
    │   ├── main.tf                # Agnostic deployment
    │   ├── variables.tf           # Configurable parameters
    │   ├── dev.tfvars             # Development configuration
    │   ├── prod.tfvars            # Production configuration
    │   └── terraform.auto.tfvars.example  # Template for local overrides
    └── gcp-gke/                    # Google Cloud GKE
        ├── main.tf                # GKE deployment
        ├── variables.tf           # Configurable parameters
        ├── dev.tfvars             # Development configuration
        ├── prod.tfvars            # Production configuration
        └── terraform.auto.tfvars.example  # Template for local overrides
```

## 🚀 Quick Start

### Prerequisites

- Terraform >= 1.5.0
- kubectl
- Access to a Kubernetes cluster (for agnostic) OR GCP project (for gcp-gke)
- `.env` file configured (see `.env.example` in project root)

### Option 1: Using deploy_all.sh (Recommended)

The simplest method - automatically loads `.env` and runs Terraform:

```bash
# Deploy to local k3s/kind cluster
./deploy_all.sh --target agnostic --env dev

# Deploy to GCP GKE
./deploy_all.sh --target gcp-gke --env dev --auto-approve
```

**What it does:**
1. Loads `.env` and exports as `TF_VAR_*` variables
2. Runs `terraform init` with appropriate backend config
3. Runs `terraform apply` with environment-specific `.tfvars`
4. Handles all target-specific configuration automatically

### Option 2: Manual Terraform

If you prefer to run Terraform directly:

```bash
# 1. Load environment variables
source ./infra/load_env.sh

# 2. Navigate to target
cd infra/targets/gcp-gke  # or infra/targets/agnostic

# 3. Initialize Terraform
terraform init

# 4. Plan deployment
terraform plan -var-file="dev.tfvars"

# 5. Apply
terraform apply -var-file="dev.tfvars"
```

## 🎯 Deployment Targets

### Agnostic Target

Deploy to **any** Kubernetes cluster:
- ✅ Local: k3s, k3d, kind, Docker Desktop
- ✅ Cloud: EKS (AWS), AKS (Azure), GKE (Google)
- ✅ On-premises: Rancher, OpenShift, vanilla K8s

**Features:**
- Uses existing cluster (no cluster provisioning)
- Kubernetes backend (state stored in cluster)
- MinIO for object storage
- Works 100% offline (no cloud dependencies)

**Configuration:**
```bash
cd infra/targets/agnostic
terraform apply -var-file="dev.tfvars"
```

See [`targets/agnostic/README.md`](targets/agnostic/README.md) for details.

### GCP-GKE Target

Provision and deploy to Google Kubernetes Engine:
- ✅ Creates GKE cluster with NIST security controls
- ✅ GCS for object storage
- ✅ GPU node pools for vLLM inference
- ✅ Cloud Build integration
- ✅ Optional CMEK, Binary Authorization, Private endpoints

**Features:**
- Full cluster lifecycle management
- GCP-optimized networking and storage
- NIST RMF compliance toggles
- Cloud Armor, VPC-SC ready

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
./deploy_all.sh --target agnostic --env dev
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
- **[`k8s_namespace`](modules/k8s_namespace/)** - Namespace with PSS/PSA
- **[`minio_storage`](modules/minio_storage/)** - S3-compatible object storage
- **[`postgres_db`](modules/postgres_db/)** - PostgreSQL database
- **[`redis_cache`](modules/redis_cache/)** - Redis with optional HA

### Application Modules

- **[`vllm_inference`](modules/vllm_inference/)** - vLLM GPU inference
- **[`langfuse_stack`](modules/langfuse_stack/)** - Observability platform
- **[`opa_policy`](modules/opa_policy/)** - Policy engine
- **[`compliance_bridge`](modules/compliance_bridge/)** - ISO 42001 auditing
- **[`agentsight_ui`](modules/agentsight_ui/)** - AgentSight UI frontend
- **[`app_secrets`](modules/app_secrets/)** - Kubernetes Secrets management
- **[`gateway`](modules/gateway/)** - Inference Gateway
- **[`governed_advisor`](modules/governed_advisor/)** - Governed Financial Advisor backend
- **[`slm_inference`](modules/slm_inference/)** - SLM inference (deprecated, kept for reference)

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
enable_vllm = false  # Use external vLLM for speed
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

### Problem: Kubernetes backend fails (agnostic target)

```bash
# Create terraform-state namespace
kubectl create namespace terraform-state

# Verify kubeconfig
kubectl config current-context
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
