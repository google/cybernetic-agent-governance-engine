# SLM (Small Language Model) Inference Module

> **⚠️ DEPRECATED — since v2.0.0**
>
> The SLM sidecar has been **fully deprecated** as of CAGE v2.0.0. The
> `SymbolicGovernor` no longer calls the SLM HTTP endpoint; semantic
> similarity filtering is bypassed via the `slm_available=false` sentinel
> (see `src/gateway/governance/symbolic_governor.py`). This Terraform module
> is retained for reference only and **must not be deployed** in new
> environments. It will be removed in a future release.

Deploys a semantic similarity sidecar using sentence-transformers BERT models.

## Purpose (Historical — Pre-v2.0.0)

The SLM sidecar previously provided **Tier-2 semantic filtering** in CAGE's
three-tier semantic shielding architecture:

1. **Tier 1**: Aho-Corasick heuristic pattern matching
2. **Tier 2**: SLM semantic similarity (this module — **deprecated**)
3. **Tier 3**: OPA policy enforcement + NeMo reasoning

## Model

Default model: `all-MiniLM-L6-v2` (lightweight, 384-dim embeddings)
- Fast inference (~10ms on CPU)
- Good balance of speed/quality for similarity tasks
- Can be changed via `model_name` variable

## Usage

```hcl
module "slm" {
  source = "../../modules/slm_inference"
  
  namespace  = "governance-stack-dev"
  replicas   = 2
  model_name = "all-MiniLM-L6-v2"
  image      = "gcr.io/my-project/slm-inference:v1.0"
  
  # Production settings
  enable_pdb = true
  resources_limits_cpu    = "2000m"
  resources_limits_memory = "4Gi"
}
```

## Integration

The symbolic governor queries the SLM service via HTTP:

```python
POST http://slm:5000/similarity
{
  "text": "execute trade for AAPL"
}

Response:
{
  "similarity": 0.87,
  "model": "all-MiniLM-L6-v2"
}
```

## Outputs

- `service_url`: Full URL for in-cluster access (e.g., `http://slm.governance-stack-dev.svc.cluster.local:5000`)
- `service_name`: Kubernetes service name
- `model_name`: Model being used
