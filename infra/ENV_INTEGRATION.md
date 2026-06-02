# Environment Variable Integration with Terraform

This guide explains how to use your project's `.env` file with Terraform to avoid duplicating configuration.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Methods for Loading Variables](#methods-for-loading-variables)
- [Supported Environment Variables](#supported-environment-variables)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

The CAGE infrastructure uses Terraform for deployment automation. To avoid maintaining configuration in two places (`.env` and `terraform.auto.tfvars`), we provide multiple ways to load environment variables into Terraform:

1. **Shell script** - Automatically converts `.env` to `TF_VAR_*` exports
2. **Manual `terraform.auto.tfvars`** - Traditional Terraform approach
3. **Environment-specific `.tfvars` files** - For multi-environment deployments

---

## Quick Start

### Method 1: Using the Shell Script (Recommended)

This is the easiest method - it reads your `.env` file and automatically exports variables in a format Terraform understands.

```bash
# 1. Ensure you have a .env file (copy from .env.example if needed)
cp .env.example .env
# Edit .env with your actual values

# 2. Load environment variables
source ./infra/load_env.sh

# 3. Navigate to your target directory
cd infra/targets/gcp-gke    # or infra/targets/agnostic

# 4. Initialize and apply Terraform
terraform init
terraform plan
terraform apply
```

**How it works:**
- Reads `.env` from project root
- Exports variables as both `VAR_NAME` and `TF_VAR_*` equivalents
- Terraform automatically picks up `TF_VAR_*` environment variables

### Method 2: Using terraform.auto.tfvars

For more control, you can create a `terraform.auto.tfvars` file:

```bash
# 1. Copy the example file
cd infra/targets/gcp-gke    # or infra/targets/agnostic
cp terraform.auto.tfvars.example terraform.auto.tfvars

# 2. Edit terraform.auto.tfvars with your values
vim terraform.auto.tfvars

# 3. Run Terraform (no need to source load_env.sh)
terraform init
terraform plan
terraform apply
```

**Advantages:**
- More explicit configuration
- Type-safe (Terraform validates values)
- Easier to manage per-environment configs

**Note:** `terraform.auto.tfvars` is in `.gitignore` - never commit it!

### Method 3: Environment-Specific Files

For managing multiple environments (dev/staging/prod):

```bash
cd infra/targets/gcp-gke

# Use pre-configured environment files
terraform plan -var-file="dev.tfvars"     # Development
terraform plan -var-file="prod.tfvars"    # Production

# Or create custom ones
terraform plan -var-file="my-custom.tfvars"
```

---

## Methods for Loading Variables

### Comparison Table

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **Shell script** | No file duplication, single source of truth | Must source before each Terraform run | Local development, CI/CD |
| **terraform.auto.tfvars** | Type-safe, auto-loaded, explicit | Must keep in sync with `.env` | Per-environment customization |
| **-var-file** | Multiple environments, version controlled | More files to manage | Multi-environment deployments |

### Detailed Method Comparison

#### Shell Script Method

```bash
source ./infra/load_env.sh
cd infra/targets/gcp-gke
terraform apply
```

**Variable mapping:**
```bash
# .env file:
LANGFUSE_PUBLIC_KEY=pk-lf-xxx

# Shell script exports:
export LANGFUSE_PUBLIC_KEY=pk-lf-xxx
export TF_VAR_langfuse_public_key=pk-lf-xxx
```

**When to use:**
- Local development with frequently changing configs
- CI/CD pipelines (single `.env` source)
- Quick prototyping

#### terraform.auto.tfvars Method

```hcl
# terraform.auto.tfvars
project_id = "my-gcp-project"
region = "us-central1"
langfuse_public_key = "pk-lf-xxx"
langfuse_secret_key = "sk-lf-xxx"
```

**When to use:**
- Need Terraform validation of values
- Prefer explicit configuration
- Different values than `.env` for this deployment

#### -var-file Method

```bash
# dev.tfvars
environment = "dev"
enable_nist_compliance = false
primary_node_pool_min_count = 1

# prod.tfvars
environment = "prod"
enable_nist_compliance = true
primary_node_pool_min_count = 3

# Usage:
terraform apply -var-file="prod.tfvars"
```

**When to use:**
- Multiple environments (dev/staging/prod)
- Different infrastructure configs per environment
- Version-controlled, team-shared configs

---

## Supported Environment Variables

The following `.env` variables are automatically mapped to Terraform variables:

### Authentication & Secrets

| .env Variable | Terraform Variable | Description |
|---------------|-------------------|-------------|
| `AWS_ACCESS_KEY_ID` | `aws_access_key` | S3/MinIO access key |
| `AWS_SECRET_ACCESS_KEY` | `aws_secret_key` | S3/MinIO secret key |
| `HUGGING_FACE_HUB_TOKEN` | `hf_token` | HuggingFace token for model downloads |
| `GOVERNANCE_SALT` | `governance_salt` | HMAC salt for governance |
| `CAGE_ROUTING_SEAL_SECRET` | `routing_seal_secret` | Gateway routing seal |

### Langfuse Observability

| .env Variable | Terraform Variable | Description |
|---------------|-------------------|-------------|
| `LANGFUSE_HOST` | `langfuse_host` | Langfuse server URL |
| `LANGFUSE_PUBLIC_KEY` | `langfuse_public_key` | Langfuse public API key |
| `LANGFUSE_SECRET_KEY` | `langfuse_secret_key` | Langfuse secret API key |
| `LANGFUSE_COMPLIANCE_PUBLIC_KEY` | `langfuse_compliance_public_key` | Compliance project public key |
| `LANGFUSE_COMPLIANCE_SECRET_KEY` | `langfuse_compliance_secret_key` | Compliance project secret key |

### Model Configuration

| .env Variable | Terraform Variable | Description |
|---------------|-------------------|-------------|
| `MODEL_REASONING` | `model_reasoning` | Reasoning model path |
| `MODEL_FAST` | `model_fast` | Fast model path |
| `MODEL_CONSENSUS` | `model_consensus` | Consensus model path |

### Infrastructure Endpoints

| .env Variable | Terraform Variable | Description |
|---------------|-------------------|-------------|
| `VLLM_REASONING_API_BASE` | `vllm_reasoning_url` | vLLM reasoning endpoint |
| `VLLM_FAST_API_BASE` | `vllm_fast_url` | vLLM fast endpoint |
| `VLLM_GATEWAY_URL` | `vllm_gateway_url` | vLLM gateway endpoint |
| `OPA_URL` | `opa_url` | OPA policy engine URL |
| `REDIS_URL` | `redis_url` | Redis connection URL |
| `S3_ENDPOINT_URL` | `minio_endpoint` | MinIO/S3 endpoint (agnostic only) |
| `S3_BUCKET_NAME` | `minio_bucket` | MinIO/S3 bucket (agnostic only) |

### General Configuration

| .env Variable | Terraform Variable | Description |
|---------------|-------------------|-------------|
| `ENVIRONMENT` | `environment` | Environment (dev/staging/prod) |
| `K8S_CLUSTER_NAME` | `cluster_name` | Kubernetes cluster name |
| `K8S_NAMESPACE` | `namespace` | Kubernetes namespace |
| `REGISTRY_URL` | `registry_url` | Container registry URL |
| `STORAGE_BACKEND` | `storage_backend` | Storage backend (s3/gcs/local) |
| `COLD_TIER_BUCKET` | `cold_tier_bucket` | Cold tier bucket name |

---

## Security Best Practices

### ✅ DO

1. **Always use `.env` for local development**
   ```bash
   cp .env.example .env
   # Edit .env with real values
   # .env is in .gitignore - safe!
   ```

2. **Use secret management in production**
   - GCP: Use Secret Manager with Terraform `google_secret_manager_secret_version`
   - AWS: Use AWS Secrets Manager
   - Kubernetes: Use Sealed Secrets or External Secrets Operator

3. **Audit who has access to sensitive vars**
   ```bash
   # Mark sensitive in Terraform
   variable "langfuse_secret_key" {
     type      = string
     sensitive = true  # Won't show in logs
   }
   ```

4. **Use separate Langfuse projects for compliance**
   - Main app: `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY`
   - Compliance: `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY`

### ❌ DON'T

1. **Never commit `.env` or `terraform.auto.tfvars`**
   ```bash
   # These are already in .gitignore - don't force-add!
   git add -f .env                    # ❌ DON'T
   git add -f terraform.auto.tfvars   # ❌ DON'T
   ```

2. **Don't use plaintext secrets in version-controlled `.tfvars`**
   ```hcl
   # prod.tfvars (version controlled) ❌ BAD
   langfuse_secret_key = "sk-lf-actual-secret"

   # prod.tfvars (version controlled) ✅ GOOD
   # Use variable references only:
   # langfuse_secret_key = ""  # Loaded from TF_VAR_* or auto.tfvars
   ```

3. **Don't mix development and production secrets in the same `.env`**
   ```bash
   # Use separate .env files
   .env.dev
   .env.prod

   # Load with:
   source ./infra/load_env.sh .env.dev
   ```

---

## Troubleshooting

### Problem: Terraform doesn't pick up my .env variables

**Solution 1:** Ensure you sourced the script in the current shell
```bash
# ❌ Wrong (runs in subshell)
./infra/load_env.sh

# ✅ Correct (exports in current shell)
source ./infra/load_env.sh
```

**Solution 2:** Check variable names match
```bash
# Verify exports worked
env | grep TF_VAR_

# Should see:
# TF_VAR_langfuse_public_key=pk-lf-xxx
# TF_VAR_langfuse_secret_key=sk-lf-xxx
```

### Problem: Terraform says "No value for required variable"

**Cause:** Variable not exported or misspelled

```bash
# Check if variable is set
echo $TF_VAR_project_id

# If empty, check .env file has it
grep PROJECT_ID .env

# Or set directly
export TF_VAR_project_id="my-gcp-project"
```

### Problem: "Error: Cycle" when using outputs as inputs

**Cause:** Circular dependency in Terraform

**Solution:** Use explicit values in `terraform.auto.tfvars` instead of output references:
```hcl
# ❌ Creates cycle
langfuse_host = module.langfuse.web_url

# ✅ Use explicit value
langfuse_host = "https://langfuse.example.com"
```

### Problem: Changes to .env don't take effect

**Solution:** Re-source the script after editing `.env`
```bash
vim .env
source ./infra/load_env.sh  # Reload
cd infra/targets/gcp-gke
terraform plan              # Will use new values
```

### Problem: Sensitive values showing in Terraform output

**Solution:** Mark variable as sensitive
```hcl
variable "langfuse_secret_key" {
  type      = string
  sensitive = true  # Redacts in output
}
```

### Problem: CI/CD pipeline can't find .env

**Solution:** In CI, use pipeline secrets, not `.env`:

**GitHub Actions:**
```yaml
- name: Terraform Apply
  env:
    TF_VAR_langfuse_public_key: ${{ secrets.LANGFUSE_PUBLIC_KEY }}
    TF_VAR_langfuse_secret_key: ${{ secrets.LANGFUSE_SECRET_KEY }}
  run: |
    cd infra/targets/gcp-gke
    terraform apply -auto-approve
```

**GitLab CI:**
```yaml
deploy:
  script:
    - export TF_VAR_langfuse_public_key=$LANGFUSE_PUBLIC_KEY
    - export TF_VAR_langfuse_secret_key=$LANGFUSE_SECRET_KEY
    - cd infra/targets/gcp-gke
    - terraform apply -auto-approve
```

---

## Advanced: Partial Variable Loading

If you only want to load specific variables, create a custom script:

```bash
#!/usr/bin/env bash
# infra/load_secrets_only.sh

export TF_VAR_langfuse_public_key="${LANGFUSE_PUBLIC_KEY}"
export TF_VAR_langfuse_secret_key="${LANGFUSE_SECRET_KEY}"
export TF_VAR_hf_token="${HUGGING_FACE_HUB_TOKEN}"

echo "✅ Secrets loaded (non-sensitive config must be in .tfvars)"
```

---

## Example Workflows

### Local Development

```bash
# One-time setup
cp .env.example .env
vim .env  # Add your keys

# Every time you deploy
source ./infra/load_env.sh
cd infra/targets/gcp-gke
terraform plan
terraform apply
```

### Multi-Environment Production

```bash
# Directory structure:
# infra/targets/gcp-gke/
#   ├── terraform.auto.tfvars      # Secrets (gitignored)
#   ├── dev.tfvars                 # Dev config (version controlled)
#   └── prod.tfvars                # Prod config (version controlled)

# Deploy to dev
terraform apply -var-file="dev.tfvars"

# Deploy to prod
terraform apply -var-file="prod.tfvars"
```

### CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy Infrastructure

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
      
      - name: Terraform Apply
        env:
          TF_VAR_project_id: ${{ secrets.GCP_PROJECT_ID }}
          TF_VAR_langfuse_public_key: ${{ secrets.LANGFUSE_PUBLIC_KEY }}
          TF_VAR_langfuse_secret_key: ${{ secrets.LANGFUSE_SECRET_KEY }}
          GOOGLE_CREDENTIALS: ${{ secrets.GCP_CREDENTIALS }}
        run: |
          cd infra/targets/gcp-gke
          terraform init
          terraform apply -auto-approve -var-file="prod.tfvars"
```

---

## Related Documentation

- [Terraform Variables Documentation](https://www.terraform.io/docs/language/values/variables.html)
- [CAGE Deployment Guide](./DEPLOYMENT_GUIDE.md)
- [Security Best Practices](./TESTING_PLAN.md)

---

**Questions or Issues?**

Open an issue in the repository or consult the [CONTRIBUTING.md](../CONTRIBUTING.md) guide.
