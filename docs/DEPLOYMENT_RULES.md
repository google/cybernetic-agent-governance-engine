# CAGE Deployment Rules & Best Practices

> **Critical Policy:** This document defines mandatory deployment rules that all agents (Antigravity, Roo Code) and human operators must follow.

## 🚨 GKE Deployment Policy

### Mandatory Rule: Cloud Build Only

**When deploying to Google Kubernetes Engine (GKE), you MUST use Cloud Build. Local Docker builds are prohibited for GKE deployments.**

#### Why This Matters

| Issue | Local Docker Build | Cloud Build |
|-------|-------------------|-------------|
| **Platform consistency** | ❌ May use ARM64 on M-series Macs | ✅ Always uses AMD64 for GKE |
| **Build reproducibility** | ❌ Depends on local environment | ✅ Controlled build environment |
| **Security scanning** | ❌ Manual/optional | ✅ Integrated vulnerability scanning |
| **Audit trail** | ❌ No automated logs | ✅ Full build provenance in GCP |
| **Team collaboration** | ❌ "Works on my machine" issues | ✅ Consistent across all developers |

### Enforcement

#### ✅ Approved Methods for GKE

```bash
# Option 1: Using deployment script (recommended)
./deploy_all.sh --target gcp-gke --env dev

# Option 2: Using MCP server via agents
# Ask Antigravity or Roo: "Deploy to GKE development environment"
# The agent will use the cage-infrastructure MCP server

# Option 3: Direct Cloud Build (advanced)
gcloud builds submit --config deployment/docker/cloudbuild_gateway.yaml
```

#### ❌ Prohibited for GKE

```bash
# NEVER do this for GKE deployments:
docker build -t gcr.io/PROJECT/image:tag .
docker push gcr.io/PROJECT/image:tag
kubectl apply -f deployment.yaml

# NEVER do this:
docker-compose build
docker-compose push
```

### Exception Process

If Cloud Build is unavailable:
1. **Do not** proceed with local builds
2. Investigate the Cloud Build failure:
   - Check GCP Console > Cloud Build > History
   - Verify service account permissions
   - Check GCP quotas and billing
3. Fix the Cloud Build issue
4. **Only** if Cloud Build is permanently unavailable: escalate to senior engineer for approval

## Deployment Target Matrix

| Target | Environment | Build Method | Command | Use Case |
|--------|------------|--------------|---------|----------|
| `gcp-gke` | prod | ☁️ Cloud Build | `./deploy_all.sh --target gcp-gke --env prod` | Production deployment |
| `gcp-gke` | dev | ☁️ Cloud Build | `./deploy_all.sh --target gcp-gke --env dev` | GKE development cluster |
| `agnostic` | dev | 🐳 Local Docker | `./deploy_all.sh --target agnostic --env dev` | k3d/kind local cluster |
| `docker-compose` | dev | 🐳 Local Docker | `./deploy_all.sh` | Local development |

## Cloud Build Configuration Files

| Service | Config File | Purpose |
|---------|------------|---------|
| Gateway | `deployment/docker/cloudbuild_gateway.yaml` | Inference gateway |
| vLLM | `deployment/docker/cloudbuild.vllm.yaml` | LLM inference engine |
| LULA | `deployment/docker/cloudbuild.lula.yaml` | Compliance validation |

## MCP Server Integration

The `cage-infrastructure` MCP server enforces these rules automatically:

```json
{
  "tool": "deploy_environment",
  "arguments": {
    "target": "gcp-gke",
    "environment": "dev"
  }
}
```

- When `target: "gcp-gke"` → Uses Cloud Build automatically
- When `target: "agnostic"` → Uses local Docker
- When `target: "docker-compose"` → Uses Docker Compose

## Verification

### Before Deployment Checklist

- [ ] Correct target selected (`gcp-gke` vs `agnostic` vs `docker-compose`)
- [ ] If GKE: Cloud Build will be used (not local Docker)
- [ ] Environment variables configured (`.env` file)
- [ ] GCP credentials available (`gcloud auth list`)
- [ ] Kubernetes context correct (`kubectl config current-context`)

### After Deployment Verification

```bash
# Check Cloud Build history
gcloud builds list --limit=5

# Verify images in GCR
gcloud container images list

# Check deployment status
kubectl get deployments -n cage-system
```

## Agent Instructions

### For Antigravity

This file serves as a knowledge artifact. When asked to deploy to GKE, reference this document and use the `cage-infrastructure` MCP server with `target: "gcp-gke"`.

### For Roo Code

The deployment rules are enforced via `.clinerules` at the project root. When deploying to GKE, always use the approved methods above.

### For Human Operators

Follow the deployment matrix above. If unsure, use `./deploy_all.sh` with the appropriate `--target` flag. The script enforces the correct build method.

## Troubleshooting

### Cloud Build Failures

**Error: "Permission denied"**
```bash
# Fix: Grant Cloud Build service account permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:PROJECT_NUMBER@cloudbuild.gserviceaccount.com \
  --role=roles/container.developer
```

**Error: "Quota exceeded"**
```bash
# Check quotas
gcloud compute project-info describe --project=PROJECT_ID

# Request quota increase in GCP Console
```

**Error: "Build timeout"**
```bash
# Increase timeout in cloudbuild.yaml
timeout: 3600s  # 1 hour
```

## Related Documentation

- [Deployment Guide](../infra/DEPLOYMENT_GUIDE.md) - Complete deployment procedures
- [MCP Integration Guide](MCP_INTEGRATION_GUIDE.md) - Using MCP servers for deployment
- [Infrastructure README](../infra/README.md) - Infrastructure architecture

## Compliance Note

This policy supports:
- **ISO 42001 A.5.2** (AI system deployment control)
- **NIST AI RMF** (Controlled deployment practices)
- **SOC 2 CC8.1** (Change management controls)

All GKE deployments using Cloud Build are automatically logged for audit purposes.
