# vLLM Inference Module

Deploys vLLM (Very Large Language Model) inference engine with GPU support for serving LLMs.

## Features

- ✅ GPU scheduling with node selector and tolerations
- ✅ Configurable GPU count and type (T4, L4, A100, etc.)
- ✅ Pod anti-affinity for GPU distribution
- ✅ Persistent model storage (optional)
- ✅ S3/MinIO integration for model loading
- ✅ Health checks and readiness probes
- ✅ Pod Disruption Budget support
- ✅ Shared memory configuration for vLLM
- ✅ Environment variable customization

## Usage

### Basic Deployment (HuggingFace Model)

```hcl
module "vllm" {
  source = "../../modules/vllm_inference"
  
  namespace  = "my-namespace"
  model_path = "meta-llama/Llama-3.2-3B-Instruct"
  gpu_count  = 1
}
```

### Production Deployment with Multiple GPUs

```hcl
module "vllm" {
  source = "../../modules/vllm_inference"
  
  namespace       = "my-namespace"
  deployment_name = "vllm-inference"
  model_path      = "meta-llama/Meta-Llama-3.1-70B-Instruct"
  
  # GPU configuration
  gpu_count   = 2
  gpu_product = "NVIDIA-A100"
  
  # Scaling
  replicas   = 2
  enable_pdb = true
  
  # Resources
  memory_limit   = "128Gi"
  cpu_limit      = "32"
  memory_request = "64Gi"
  cpu_request    = "16"
  
  # Node selector for specific GPU nodes
  node_selector = {
    "nvidia.com/gpu.product" = "NVIDIA-A100"
  }
}
```

### With Model Storage PVC

```hcl
module "vllm" {
  source = "../../modules/vllm_inference"
  
  namespace  = "my-namespace"
  model_path = "/model-storage/llama-3.2-3b"
  
  # Enable model volume
  enable_model_volume = true
  model_pvc_name      = "model-storage-pvc"
}
```

### With S3/MinIO for Model Loading

```hcl
module "vllm" {
  source = "../../modules/vllm_inference"
  
  namespace  = "my-namespace"
  model_path = "s3://my-bucket/models/llama-3.2-3b"
  
  # S3 configuration
  enable_s3_credentials = true
  s3_endpoint_url       = "http://minio:9000"
  s3_credentials_secret = "minio-credentials"
}
```

### Custom vLLM Configuration

```hcl
module "vllm" {
  source = "../../modules/vllm_inference"
  
  namespace  = "my-namespace"
  model_path = "meta-llama/Llama-3.2-3B-Instruct"
  
  # Custom vLLM command
  vllm_command = <<-EOT
    python3 -m vllm.entrypoints.openai.api_server \
      --model $MODEL_PATH \
      --host 0.0.0.0 \
      --port 8000 \
      --tensor-parallel-size 2 \
      --max-model-len 4096 \
      --gpu-memory-utilization 0.9
  EOT
  
  # Additional environment variables
  env_vars = {
    VLLM_ATTENTION_BACKEND = "FLASHINFER"
    CUDA_VISIBLE_DEVICES   = "0,1"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| namespace | Kubernetes namespace | string | - | yes |
| deployment_name | Deployment name | string | "vllm-inference" | no |
| service_name | Service name | string | "vllm-service" | no |
| image | vLLM container image | string | "vllm/vllm-openai:latest" | no |
| replicas | Number of replicas | number | 1 | no |
| gpu_count | GPUs per pod | number | 1 | no |
| gpu_product | GPU type | string | "" | no |
| memory_limit | Memory limit | string | "64Gi" | no |
| cpu_limit | CPU limit | string | "16" | no |
| memory_request | Memory request | string | "10Gi" | no |
| cpu_request | CPU request | string | "3" | no |
| shared_memory_size | Shared memory size | string | "16Gi" | no |
| model_path | Model path/HuggingFace ID | string | "meta-llama/Llama-3.2-3B-Instruct" | no |
| vllm_load_format | Load format | string | "auto" | no |
| enable_model_volume | Enable model PVC | bool | false | no |
| model_pvc_name | PVC name | string | "model-storage" | no |
| vllm_command | vLLM startup command | string | (default command) | no |
| env_vars | Additional env vars | map(string) | {} | no |
| enable_s3_credentials | Enable S3 credentials | bool | false | no |
| s3_endpoint_url | S3 endpoint | string | "" | no |
| s3_credentials_secret | S3 secret name | string | "minio-credentials" | no |
| service_type | Service type | string | "ClusterIP" | no |
| enable_pdb | Enable PDB | bool | false | no |
| pdb_min_available | Min available pods | number | 1 | no |
| enable_pod_anti_affinity | Pod anti-affinity | bool | true | no |
| node_selector | Node selector | map(string) | {} | no |
| tolerations | Tolerations | list(object) | GPU tolerations | no |
| readiness_initial_delay | Readiness delay (s) | number | 120 | no |
| liveness_initial_delay | Liveness delay (s) | number | 600 | no |

## Outputs

| Name | Description |
|------|-------------|
| deployment_name | Deployment name |
| service_name | Service name |
| service_fqdn | Service FQDN |
| endpoint_url | vLLM endpoint URL |
| health_check_url | Health check URL |
| model_path | Configured model path |
| replicas | Number of replicas |

## GPU Requirements

### Node Requirements

- GPU nodes with NVIDIA GPUs
- NVIDIA GPU Operator or device plugin installed
- GPU drivers loaded

### Supported GPU Types

- NVIDIA T4 (entry-level)
- NVIDIA L4 (recommended for cost/performance)
- NVIDIA A100 (high-performance)
- NVIDIA H100 (cutting-edge)

### GPU Scheduling

The module uses:
1. **Resource limits**: `nvidia.com/gpu` for GPU allocation
2. **Node selector**: Target specific GPU types
3. **Tolerations**: Allow scheduling on GPU nodes
4. **Pod anti-affinity**: Distribute replicas across nodes

## Model Loading

### HuggingFace Hub (Default)

```hcl
model_path = "meta-llama/Llama-3.2-3B-Instruct"
```

vLLM downloads from HuggingFace automatically.

### Local PVC

```hcl
enable_model_volume = true
model_pvc_name      = "my-model-pvc"
model_path          = "/model-storage/my-model"
```

### S3/MinIO

```hcl
enable_s3_credentials = true
s3_endpoint_url       = "http://minio:9000"
model_path            = "s3://bucket/path/to/model"
```

## Health Checks

- **Readiness**: `/health` endpoint (2 min initial delay)
- **Liveness**: `/health` endpoint (10 min initial delay)

Long delays account for model loading time.

## Accessing vLLM

### From Another Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: client
spec:
  containers:
    - name: app
      env:
        - name: VLLM_URL
          value: "http://vllm-service:8000"
```

### Port-Forward for Local Testing

```bash
kubectl port-forward svc/vllm-service 8000:8000 -n <namespace>
curl http://localhost:8000/health
```

### Test Inference

```bash
curl http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "meta-llama/Llama-3.2-3B-Instruct",
    "prompt": "Hello, how are you?",
    "max_tokens": 100
  }'
```

## Performance Tuning

### Tensor Parallelism

For multi-GPU:

```hcl
vllm_command = <<-EOT
  python3 -m vllm.entrypoints.openai.api_server \
    --model $MODEL_PATH \
    --tensor-parallel-size ${var.gpu_count} \
    --host 0.0.0.0 --port 8000
EOT
```

### GPU Memory Utilization

```hcl
env_vars = {
  GPU_MEMORY_UTILIZATION = "0.95"
}
```

### Max Model Length

```hcl
vllm_command = "... --max-model-len 8192"
```

## Troubleshooting

### GPU Not Allocated

```bash
kubectl describe pod <pod-name> -n <namespace>
# Check Events for GPU allocation issues
```

### Model Download Slow

Use a PVC or S3 bucket for pre-downloaded models.

### Out of Memory

Reduce `--gpu-memory-utilization` or `--max-model-len`.

### Check vLLM Logs

```bash
kubectl logs -f deployment/vllm-inference -n <namespace>
```

## Monitoring

vLLM exposes Prometheus metrics at `/metrics`.

## Security

- Run as non-root user
- Use network policies to restrict access
- Secure S3 credentials in Kubernetes Secrets
