# Governed Financial Advisor Deployment

This directory contains the configuration and scripts to deploy the Financial Advisor agent to **Kubernetes** (GKE on Google Cloud is the reference deployment; EKS, AKS, and bare-metal Kubernetes are also supported).

## Architecture

The system is deployed as a distributed microservices architecture on GKE:

1.  **Gateway Service (`gateway-service`)**:
    - gRPC service (Port 50051).
    - Acts as the central router and "Physical Layer" for the agent.
    - Handles Tool Execution and LLM Routing.
    - Connects to OPA and NeMo Guardrails.

2.  **Financial Advisor Agent (`governed-financial-advisor`)**:
    - FastAPI backend (Port 8080).
    - Hosts the LangGraph control plane and ADK agents.
    - Connects to the Gateway via internal DNS.

3.  **Inference Services**:
    - `vllm-inference`: Hosted vLLM instance for the "Fast Path" (Control Plane/Format Enforcer).
    - `vllm-reasoning`: Hosted vLLM instance for the "Reasoning Plane".

4.  **Governance Sidecars/Services**:
    - `opa-service`: Open Policy Agent server.
    - `nemo-service`: NeMo Guardrails server.
    - `langfuse-server`: Langfuse v3 observability stack (Web, Worker, ClickHouse, MinIO, Redis).

## Prerequisites

- Google Cloud Project with billing enabled.
- `gcloud` CLI installed and authenticated.
- `kubectl` installed (or installed via script).
- Permissions to manage GKE and Artifact Registry.

> **Note:** The prerequisites above apply to GCP deployments. For other Kubernetes providers, use your cloud provider's CLI and ensure cluster access via kubectl.

## Deployment Script

The `deploy_sw.py` script is the central entry point for deploying the entire Cybernetic Governance Engine stack to GKE.

### Usage

**1. Staged Deployment (Recommended)**
For production environments with pre-existing resources, follow the staged flow:

a. **Infrastructure State Reconciliation:**

```bash
cd deployment/terraform
# Import existing resources (if any)
# terraform import google_container_cluster.primary projects/<PROJECT>/zones/<ZONE>/clusters/governance-cluster
terraform apply -auto-approve
```

b. **Software & Manifest Deployment:**
Use the manual deployment venv to ensure dependency isolation:

```bash
python3 -m venv .manual_deploy_venv
.manual_deploy_venv/bin/pip install -e ".[dev,deployment]"
.manual_deploy_venv/bin/python deployment/deploy_sw.py --project-id YOUR_PROJECT_ID --is-oss
```

**2. Standard Deployment (Automation)**
This will attempt to provision and build everything in one pass (best for fresh projects).

```bash
python3 deployment/deploy_sw.py --project-id YOUR_PROJECT_ID --is-oss
```

**3. Mandatory OIDC Configuration**
The system uses OIDC/Workload Identity for secure communication. Ensure the following are in your `.env`:

- `GOOGLE_CLOUD_PROJECT`: Target project. (GCP-specific — only required for GCP deployments with Workload Identity)
- `GOOGLE_CLOUD_LOCATION`: Target region (e.g. `us-central1`). (GCP-specific — only required for GCP deployments with Workload Identity)
- `BACKEND_URL`: The audience for OIDC tokens.

**3. Customizing Region/Zone**

```bash
python3 deployment/deploy_sw.py \
    --project-id YOUR_PROJECT_ID \
    --is-oss \
    --region us-east1 \
    --zone us-east1-c
```

**3. Skipping Build (Fast Redeploy)**
If images are already built and you only modified manifests:

```bash
python3 deployment/deploy_sw.py --project-id YOUR_PROJECT_ID --skip-build
```

### Configuration

Configuration is managed via `deployment/config.yaml` (default settings) and `.env` (secrets/overrides).

**Key Environment Variables:**

- `MODEL_FAST`: Model path for the fast path (e.g., `gs://YOUR_GCP_PROJECT_ID-models/models--Qwen--Qwen2.5-7B-Instruct/snapshots/...`).
- `MODEL_REASONING`: Model path for the reasoning path (e.g., `gs://YOUR_GCP_PROJECT_ID-models/casperhansen/deepseek-r1-distill-qwen-14b-awq`).
- `HUGGING_FACE_HUB_TOKEN`: Optional - only needed if downloading from HuggingFace Hub. Models now stream from GCS by default.
- `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`: Credentials for the in-cluster MinIO instance used as the vLLM model weight store. `deploy_sw.py` automatically bootstraps these via `_bootstrap_minio_credentials()` and `_ensure_minio_bucket()` pre-flight functions.
- `OPENAI_API_KEY`: Required if using OpenAI models via NeMo.

## vLLM Model Weight Loading (MinIO + Tensorizer)

vLLM deployments load model weights from **MinIO** (in-cluster S3-compatible object store) using vLLM's native `--load-format tensorizer`. This replaces the previous approach of mounting GCS buckets via the GKE-proprietary GCS Fuse CSI driver.

### One-Time Tensorization

Before starting vLLM pods for the first time (or when adding a new model), run the tensorization job:

```bash
kubectl apply -f deployment/k8s/tensorize-job.yaml -n governance-stack
kubectl wait --for=condition=complete job/tensorize-weights \
  --timeout=30m -n governance-stack
```

This Job:

1. Downloads model weights from HuggingFace Hub (requires `HUGGING_FACE_HUB_TOKEN` as a K8s Secret).
2. Serializes weights to TensorSerializer format using the `tensorizer` library.
3. Uploads serialized shards to the MinIO `vllm-models` bucket via S3-compatible API.

### Runtime Loading

Once tensorized, vLLM pods start in **~60–90 seconds** (vs. ~20 minutes for a full HuggingFace download) by streaming shards directly from MinIO via `--load-format tensorizer`.

**No GCS Fuse CSI driver required** — works on any Kubernetes distribution with MinIO or any S3-compatible object store.

### Pre-flight Bootstrap

`deploy_sw.py` automatically runs `_bootstrap_minio_credentials()` and `_ensure_minio_bucket()` before applying the stack, ensuring MinIO is operational and the `vllm-models` bucket exists before vLLM pods start.

## Terraform (Infrastructure as Code)

For managing the GKE cluster and underlying VPC via Terraform:

```bash
cd deployment/terraform
terraform init
terraform apply -var="project_id=YOUR_PROJECT_ID"
```

The Terraform state tracks the GKE cluster, Node Pools, and Kubernetes Secret objects. The `deploy_sw.py` script respects existing infrastructure.

## Post-Deployment Verification

### 1. Check Pod Status

```bash
kubectl get pods -n governance-stack
```

Expected output should show `Running` status for:

- `gateway-service-*`
- `governed-financial-advisor-*`
- `vllm-fast-*` (if enabled)
- `financial-advisor-ui-*`
- `langfuse-web-*`
- `langfuse-worker-*`
- `clickhouse-0`
- `minio-*`

ACCESS_UI_INSTRUCTIONS
The deployment is fully hardened and uses **ClusterIP** for all services. To access the UI locally:

```bash
kubectl port-forward svc/financial-advisor-ui 3000:80 -n governance-stack
```

Open `http://localhost:3000` in your browser.

### 3. Test Backend API

Use `kubectl port-forward` to access the backend locally:

```bash
kubectl port-forward svc/governed-financial-advisor 8081:80 -n governance-stack
```

Then query the agent:

```bash
curl -X POST localhost:8081/agent/query \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello"}'
```
