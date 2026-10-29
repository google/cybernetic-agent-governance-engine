# GCP-GKE Deployment Target

Provisions a complete GKE cluster with GCP-optimized settings and security posture toggles.

## Quick Start

### Prerequisites

1. **GCP Project** with billing enabled
2. **gcloud CLI** authenticated (`gcloud auth application-default login`)
3. **Terraform** >= 1.5.0
4. **kubectl** installed
5. **uv** (Python package manager)

### Deploy to Dev

```bash
# From repository root
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# Or manually
cd infra/targets/gcp-gke

# First time: create the state bucket
# gsutil mb -p YOUR_PROJECT gs://YOUR_PROJECT-tfstate

# One state per cluster: the prefix names the cluster dev.tfvars sets
terraform init -reconfigure \
  -backend-config="bucket=YOUR_PROJECT-tfstate" \
  -backend-config="prefix=cage/gcp-gke/cage-dev"
terraform apply -var-file=dev.tfvars \
  -var="minio_root_password=SecurePassword123"
```

### Deploy to Prod

```bash
./deploy_all.sh --target gcp-gke --env prod

# Or manually (review plan first!)
cd infra/targets/gcp-gke
terraform plan -var-file=prod.tfvars
terraform apply -var-file=prod.tfvars
```

## What Gets Provisioned

### GCP Resources

- ✅ GKE cluster (with private nodes option)
- ✅ Primary CPU node pool (autoscaling)
- ✅ GPU node pool (NVIDIA L4 or T4; pool-wide total autoscaling across verified `gpu_node_locations`)
- ✅ GCS bucket for Langfuse events (7-year retention)
- ✅ Cloud Router & NAT (when private cluster enabled)
- ✅ Workload Identity federation service accounts
- ✅ IAM bindings and KMS storage keys

### Kubernetes Resources

- ✅ Namespace with environment labels
- ✅ MinIO object storage (S3-compatible)
- ✅ PostgreSQL database
- ✅ Redis cache
- ✅ vLLM inference engines (fast and reasoning) and the advisor, only with `inference_backend = "vllm"`
- ✅ Langfuse stack (observability, database, ClickHouse, UI)
- ✅ Compliance bridge (Langfuse-to-Lula dynamic bootstrapping)
- ✅ OPA policy engine

## Inference Backend

`inference_backend` decides which model-dependent workloads exist, not only how they are configured. It also sets `CAGE_INFERENCE_BACKEND` on the gateway and the compliance bridge.

| `inference_backend` | Deploys | For |
|---|---|---|
| `"none"` (the default, and staging's) | No vLLM, no advisor, no NeMo server | The governance core on its own, as an evaluator assesses it. No GPU, quota or model key. |
| `"vllm"` | vLLM (fast and reasoning) on the GPU pool, and the advisor | Manual evaluation and demos with a live agent |

- **Absent, not degraded.** Under `"none"` no workload points at a model service that does not exist, so nothing crash-loops. On the gateway, content safety and the inference proxy refuse with reason codes. The compliance bridge records its remediation advisory as not performed.
- **Switching to `"vllm"` is a variable change.** Set `inference_backend = "vllm"` and apply. The GPU pool already exists at min 0, so the cluster and its node pools don't change. GKE adds GPU nodes when the vLLM pods request them. The plan refuses `"vllm"` without `enable_gpu_node_pool = true`.
- **The GPU pool uses pool-wide total counts (`total_min_node_count` / `total_max_node_count`, `location_policy = "ANY"`) and `initial_node_count = 0` across every profile.** Listing all verified L4 + `g2-standard-8` zones in each region (`us-central1-a/b/c`, `europe-west1-b/c`, `asia-southeast1-a/b/c`) gives Cluster Autoscaler capacity fallback on a zonal stockout without multiplying counts, and requesting zero nodes at create avoids creation-time stockout failures. The undeployed `prod` profiles also leave `gpu_node_pool_min_count = 0` until a live production cluster sets its own floor.
- **`"external"` is compose-only.** The cluster denies external egress by default (L3/L4 default-deny, plus a per-workload FQDN egress allowlist), and the advisor's egress is cluster-internal only. Reaching a third-party model provider would mean opening that control for the agent, so the plan refuses `"external"` on GKE. Allowing it later would be a deliberate decision with its own entry, not a deployment convenience.
- **Where no zone offers an L4, `external` is the only live agent.** In `europe-west1`, `-b` and `-c` offer both `nvidia-l4` and `g2-standard-8` while `-d` offers neither (POAM-2026-132, closed). In a jurisdiction whose region has no L4 zone at all, the only way to see a live agent is the compose stack with `CAGE_INFERENCE_BACKEND=external`.
- **The advisor calls its models directly, by design.** It does not go through the gateway's inference proxy. That looks like a bypass, but it is the architecture: the agent reasons freely and is constrained when it acts, at the gateway's action boundary.
- **`enable_vllm` is removed.** A profile that still sets it fails the plan with a message that names `inference_backend` (AG-7 in [`BREAKING_CHANGES_v3.md`](../../../docs/BREAKING_CHANGES_v3.md)).
- **The standalone NeMo server** (`enable_nemo_guardrails`, off by default) needs `"vllm"`, because it calls the in-cluster vLLM service. Nothing in CAGE calls the server: the gateway builds its rails in process.

The backend each need uses is below. The integration tiers are not built yet; this is the split they are designed around.

| Need | Backend | Agent |
|---|---|---|
| Unit and hermetic CI | `none` | none (stubs) |
| Integration: governance path | `none` | scripted client |
| Integration: agent behaviour | `external`, in compose | real LLM serving the shipped models |
| Manual evaluation, demos | `vllm`, on GKE | real LLM; the GPU pool scales up on demand |
| An evaluator assessing CAGE | `none` | none |

## Security Postures

### Dev (Fast Iteration)

```hcl
enable_nist_compliance      = false  # Public cluster
enable_binary_authorization = false  # Any image can run
enable_audit_logging        = false  # Minimal logging
enable_cmek                 = false  # Google-managed keys

# Cost optimization
gpu_node_pool_min_count = 0  # Scale to zero
primary_node_pool_machine_type = "e2-medium"
```

**Result**: Public cluster, accessible from anywhere, cheap nodes, scales to zero.

### Prod (NIST RMF Compliance)

```hcl
enable_nist_compliance      = true   # Private cluster
enable_binary_authorization = true   # Only signed images
enable_audit_logging        = true   # Comprehensive logs
enable_cmek                 = true   # Customer-managed keys

# High availability
gpu_node_pool_min_count = 0      # Total pool floor (raise when standing up a live prod cluster)
primary_node_pool_min_count = 3  # HA requirement
```

**Result**: Private cluster, VPN-only access, audit logs to immutable GCS bucket, signed images only.

## Testing Individual Controls

You can test NIST controls one at a time:

```bash
# Test binary authorization
terraform apply -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"

# Test private cluster
terraform apply -var-file=dev.tfvars \
  -var="enable_nist_compliance=true" \
  -var="authorized_networks=[{cidr=\"YOUR_IP/32\",display_name=\"My IP\"}]"

# Test audit logging
terraform apply -var-file=dev.tfvars \
  -var="enable_audit_logging=true"
```

## Access the Cluster

### Configure kubectl

```bash
# After deployment
gcloud container clusters get-credentials <your-cluster-name> \
  --zone=us-central1-a \
  --project=YOUR_PROJECT

# Verify
kubectl cluster-info
kubectl get nodes
```

### Access MinIO Console

```bash
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

## Cost Estimates

### Dev Cluster (Minimal)
- **Primary nodes**: 1x e2-medium = ~$25/month
- **GPU nodes**: 0-1x n1-standard-4 + T4 = ~$200/month when running
- **Storage**: 50 GB pd-standard = ~$2/month
- **GCS**: ~$1/month

**Total**: ~$30/month (idle), ~$230/month (GPU active)

### Prod Cluster (HA)
- **Primary nodes**: 3x e2-standard-8 = ~$200/month
- **GPU nodes**: 2x g2-standard-8 (L4) = ~$1200/month
- **Storage**: 500 GB pd-ssd = ~$90/month
- **GCS**: ~$5/month

**Total**: ~$1500/month

## NIST Control Evidence

For compliance audits:

```bash
# Show cluster configuration
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --project=YOUR_PROJECT

# Show private cluster config (SC-7)
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --format="value(privateClusterConfig)"

# Show binary authorization status (CM-7)
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --format="value(binaryAuthorization.evaluationMode)"

# Show audit logging config (AU-2)
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --format="value(loggingConfig.componentConfig.enableComponents)"
```

## Troubleshooting

### Terraform state locked

```bash
# List locks
terraform force-unlock <LOCK_ID>
```

### Provider authentication failed

```bash
# Re-authenticate
gcloud auth application-default login

# Verify credentials
gcloud auth list
```

### GPU quota exceeded

```bash
# Request quota increase in Cloud Console
# Navigation: IAM & Admin → Quotas → NVIDIA L4 GPUs
```

## Migration from Old Structure

If migrating from `deployment/terraform/`, see the Migration Guide.

The old code in `deployment/terraform/gcp/` can be safely archived after validating this target works.

## See Also

- [Agnostic Target](../agnostic/) - Deploy to any Kubernetes cluster
- [GKE Cluster Module](../../modules/gcp_gke_cluster/) - Module documentation
- Security Postures - Dev vs Prod configurations
- [NIST Controls Mapping](../../modules/gcp_gke_cluster/NIST_CONTROLS.md)
