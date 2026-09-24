# GCP Cloud Run Infrastructure Target

This directory contains Terraform configurations for deploying the CAGE (Cybernetic AI Governance Engine) to Google Cloud Run with stateless services and managed infrastructure.

## Architecture Overview

### Phase 1a: Infrastructure Skeleton — Stateless Services

This implementation deploys:

- **VPC Network**: Private VPC with subnet for secure communication
- **Cloud Memorystore Redis**: Managed Redis instance (BASIC or STANDARD_HA)
- **Cloud SQL PostgreSQL**: Managed PostgreSQL database with automatic backups
- **GCS Buckets**: Object storage for Langfuse traces and compliance artifacts
- **Secret Manager**: Secure credential storage (no inline secrets)
- **Cloud Run Services** (stateless containers):
  - `gateway` — CAGE governance gateway (port 8080)
  - `governed_advisor` — Financial advisor with governance controls
  - `agentsight_ui` — Observability dashboard (port 3000)
  - `compliance_bridge` — OSCAL/Lula compliance artifact exporter
  - `langfuse_web` — Langfuse observability web UI (port 3000)
  - `langfuse_worker` — Langfuse async trace processing worker

All services use **VPC Direct Egress** via network interfaces (no VPC Connector) for private communication with Redis and PostgreSQL.

## Prerequisites

1. **GCP Project** with billing enabled
2. **APIs Enabled**:
   ```bash
   gcloud services enable \
     run.googleapis.com \
     vpcaccess.googleapis.com \
     compute.googleapis.com \
     redis.googleapis.com \
     sqladmin.googleapis.com \
     storage.googleapis.com \
     secretmanager.googleapis.com
   ```

3. **Terraform** >= 1.5.0
4. **GCS Backend Bucket** (created separately):
   ```bash
   gsutil mb -p YOUR_PROJECT_ID -c STANDARD -l us-central1 gs://YOUR_PROJECT_ID-terraform-state
   gsutil versioning set on gs://YOUR_PROJECT_ID-terraform-state
   ```

5. **Application Default Credentials**:
   ```bash
   gcloud auth application-default login
   ```

## Deployment

### Step 1: Configure Backend

Edit `providers.tf` and set the GCS bucket name:

```hcl
backend "gcs" {
  bucket = "YOUR_PROJECT_ID-terraform-state"
  prefix = "cage/gcp-cloudrun"
}
```

### Step 2: Create Secrets Configuration

#### Method A: Local Execution (terraform.auto.tfvars)

Copy the example configuration and populate secrets:

```bash
cp terraform.auto.tfvars.example terraform.auto.tfvars
# Edit terraform.auto.tfvars with your secrets (gitignored)
```

#### Method B: CI/CD Pipeline Execution (Environment Variables)

If deploying via GitHub Actions, Cloud Build, or GitLab CI, pass the variables using Terraform's `TF_VAR_` environment variable convention.

```yaml
# Example CI/CD step
env:
  TF_VAR_routing_seal_secret: ${{ secrets.ROUTING_SEAL_SECRET }}
  TF_VAR_langfuse_nextauth_secret: ${{ secrets.LANGFUSE_NEXTAUTH_SECRET }}
run: terraform apply -auto-approve
```

**Required secrets** (never commit these):
- `project_id` — GCP project ID
- `routing_seal_secret` — Gateway routing HMAC secret (32+ bytes)
- `routing_seal_salt` — Gateway routing HMAC salt (32+ bytes)
- `langfuse_nextauth_secret` — NextAuth.js secret (32+ bytes)
- `langfuse_salt` — Langfuse encryption salt (32+ bytes)

**Optional secrets** (for telemetry):
- `langfuse_public_key` — Langfuse API public key
- `langfuse_secret_key` — Langfuse API secret key
- `langfuse_compliance_public_key` — Compliance project public key (required when `enable_nist_compliance=true`)
- `langfuse_compliance_secret_key` — Compliance project secret key

### Step 3: Select Environment

Choose the appropriate tfvars file for your deployment:

| Environment | File | Region | Compliance Profile | HA |
|---|---|---|---|---|
| **Dev** | `dev.tfvars` | us-central1 | US_FED | ❌ |
| **Staging** | `staging.tfvars` | us-central1 | US_FED | ❌ |
| **Prod (US)** | `prod.tfvars` | us-central1 | US_FED (NIST) | ✅ |
| **Prod (EU)** | `eu-prod.tfvars` | europe-west1 | EU_ECB (GDPR/DORA) | ✅ |
| **Prod (APAC)** | `apac-prod.tfvars` | asia-southeast1 | APAC_MAS (MAS TRM) | ✅ |

### Step 4: Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Plan deployment (always run first)
terraform plan -var-file=dev.tfvars

# Apply deployment
terraform apply -var-file=dev.tfvars

# View outputs
terraform output
```

### Step 5: Access Services

Retrieve service URLs:

```bash
terraform output gateway_url
terraform output langfuse_web_url
terraform output agentsight_ui_url
```

### Step 6: Configure Custom Domain & Cloud DNS (Optional)

If exposing the Gateway via a custom domain and external HTTPS load balancer (`enable_load_balancer = true`):

#### 1. Architecture Invariant: Decoupled DNS Zone Lifecycle
Treat DNS managed zones as persistent foundational infrastructure. Never create or destroy the parent DNS zone inside ephemeral application deployment stacks. Deleting a managed zone while external parent delegations exist can leave an **orphaned zone**, creating a critical **subdomain takeover** vulnerability. Workload Terraform stacks should only manage the ephemeral `A` / `AAAA` record sets.

#### 2. Automated Record Management via Cloud DNS
If your domain is managed in Google Cloud DNS within your project:

In your `terraform.auto.tfvars`:
```hcl
enable_load_balancer = true
gateway_domain       = "gateway.example.com"
enable_cloud_dns     = true
dns_zone_name        = "my-dns-zone"
```

Apply the configuration:
```bash
terraform apply -var-file=dev.tfvars
```

Terraform automatically provisions the Google-managed SSL certificate (`google_compute_managed_ssl_certificate.gateway`) and creates an ephemeral `A` record (`gateway.example.com`) pointing to the external load balancer IP (`load_balancer_ip`).

#### 3. Manual / Third-Party DNS Configuration
If managing DNS outside of Cloud DNS (e.g. an external corporate DNS server or registrar), create an `A` record pointing your domain (e.g., `gateway.example.com`) to the load balancer IP:

```bash
terraform output load_balancer_ip
```

> [!NOTE]
> **Maintainer Internal Postures (Argolis / Altostrat):** Maintainers running internal `dev` or `staging` postures within Google Argolis must follow internal DNS delegation policies (mandatory Cloud DNS, `DNSSEC=Off`, 24-hour Cloud Asset Inventory wait period, and `go/argolis` portal delegation). See the maintainer runbook in `.maintainer/ARGOLIS_ALTOSTRAT_DNS.md` (gitignored).

## High Availability Configuration

Set `enable_high_availability = true` in your tfvars to activate:

- Redis: `STANDARD_HA` tier with read replicas
- PostgreSQL: `REGIONAL` availability with automatic failover
- Cloud Run: Minimum 2 instances per service (distributed across zones)

## Compliance Profiles

### US_FED (NIST SP 800-53 FedRAMP Moderate)

Set `enable_nist_compliance = true` for:
- VPC Service Controls enforcement
- Deletion protection on databases
- Dual-project Langfuse telemetry isolation (POAM-019)

### EU_ECB (GDPR + DORA)

Enforced automatically when `cage_deployment_region = "EU_ECB"`:
- Data residency in `europe-west1`
- Encryption at rest (GDPR Art. 32)
- Operational resilience (DORA Art. 10)

### APAC_MAS (MAS TRM + Notice 655)

Enforced automatically when `cage_deployment_region = "APAC_MAS"`:
- Data residency in `asia-southeast1`
- Encryption at rest (MAS TRM §9.1)
- Audit logging (MAS Notice 655)

## Networking

All Cloud Run services use **VPC Direct Egress** for private connectivity:

```hcl
vpc_access {
  network_interfaces {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.subnet.id
  }
  egress = "ALL_TRAFFIC"
}
```

This eliminates the need for a legacy VPC Connector and routes all traffic through the VPC for:
- Private Redis access (no public IP)
- Private PostgreSQL access (no public IP)
- Secure inter-service communication

## Cost Optimization

For development environments:

1. Set `enable_high_availability = false`
2. Use `redis_tier = "BASIC"`
3. Use `postgres_tier = "db-f1-micro"`
4. Set `*_min_instances = 0` (scale to zero)

Estimated monthly cost (dev): **~$50-100/month**

For production environments with HA enabled: **~$500-800/month**

## Future Phases

### Phase 1b: Sidecar Integration (Planned)

- vLLM GPU inference sidecar (DeepSeek-R1, Qwen2.5)
- NeMo Guardrails PII detection sidecar
- OPA policy enforcement sidecar

Toggle via:
```hcl
enable_vllm_gpu        = true
enable_nemo_guardrails = true
```

## Troubleshooting

### PostgreSQL Connection Errors

Ensure the Cloud SQL instance is accessible from Cloud Run:

```bash
gcloud sql instances describe cage-cloudrun-postgres-dev --format="get(ipAddresses)"
```

### Redis Connection Errors

Verify Redis instance is in the same VPC:

```bash
gcloud redis instances describe cage-cloudrun-redis-dev --region=us-central1
```

### Secret Manager Access Denied

Grant Secret Manager access to service accounts:

```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:cage-gateway-dev@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Clean Up

To destroy all resources:

```bash
# WARNING: This is irreversible!
terraform destroy -var-file=dev.tfvars
```

**Note**: Production environments (`prod.tfvars`) have deletion protection enabled on databases.

> [!WARNING]
> **Preserve Persistent DNS Managed Zones:** Running `terraform destroy` safely removes the ephemeral application stack and `A` record (`google_dns_record_set.gateway`). **Never delete the foundational DNS managed zone itself** during routine application teardowns, as orphaned delegations create severe subdomain takeover risks.

## References

- [Cloud Run VPC Direct Egress](https://cloud.google.com/run/docs/configuring/vpc-direct-vpc)
- [Cloud Memorystore Redis](https://cloud.google.com/memorystore/docs/redis)
- [Cloud SQL PostgreSQL](https://cloud.google.com/sql/docs/postgres)
- [Secret Manager](https://cloud.google.com/secret-manager/docs)
