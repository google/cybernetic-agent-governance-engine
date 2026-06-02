# Terraform Infrastructure Migration

**Migration Date**: 2026-03-15  
**Old Location**: `deployment/terraform/` (REMOVED)  
**New Location**: `infra/`

---

## What Changed

The old mixed Terraform code in `deployment/terraform/` has been **completely removed** and replaced with a modular structure in `infra/`.

### Old Structure (REMOVED)
```
deployment/terraform/
├── main.tf               # Mixed concerns
├── gcp/                  # GCP-specific submodule
│   ├── gke.tf
│   ├── storage.tf
│   └── iam.tf
├── gke.tf                # Actually K8s namespace (confusing!)
├── agentsight.tf
├── secrets.tf
└── variables.tf
```

### New Structure
```
infra/
├── modules/              # Reusable Terraform modules
│   ├── k8s_namespace/
│   ├── minio_storage/
│   ├── postgres_db/
│   ├── redis_cache/
│   ├── vllm_inference/
│   ├── langfuse_stack/
│   ├── compliance_bridge/
│   ├── opa_policy/
│   └── gcp_gke_cluster/
│
└── targets/              # Deployment endpoints
    ├── agnostic/         # Cloud-agnostic (k3s, EKS, AKS)
    └── gcp-gke/          # GCP-optimized GKE
```

---

## How to Deploy

### Old Way (DEPRECATED)
```bash
cd deployment/terraform
terraform apply
```

### New Way (RECOMMENDED)
```bash
# Cloud-agnostic deployment
./deploy_all.sh --target agnostic --env dev

# GCP GKE deployment
./deploy_all.sh --target gcp-gke --env prod
```

---

## Benefits of New Structure

1. **Clarity**: Explicit separation of agnostic vs GCP-specific code
2. **Maintainability**: Shared modules = DRY (Don't Repeat Yourself)
3. **Testability**: Can test agnostic target without GCP account
4. **Scalability**: Easy to add AWS/Azure targets
5. **Best Practices**: Industry-standard monorepo pattern

---

## State Migration

If you had existing Terraform state from the old structure:

### GCP-GKE Target
State is now stored in GCS bucket (configured in backend):
```hcl
backend "gcs" {
  bucket = "YOUR_PROJECT-tfstate"
  prefix = "cage/gcp-gke"
}
```

### Agnostic Target
State is stored in Kubernetes cluster:
```hcl
backend "kubernetes" {
  secret_suffix = "tfstate-agnostic"
  namespace     = "terraform-state"
}
```

---

## Module Reference

All modules are now reusable components with:
- ✅ Complete variable definitions
- ✅ Comprehensive outputs
- ✅ README documentation
- ✅ Terraform validation passing

See [`infra/modules/`](../infra/modules/) for module documentation.

---

## Rollback

If you need the old code:

```bash
# Find the commit before migration
git log --oneline --all | grep -i "Remove old terraform"

# Revert the changes
git revert <commit-hash>

# Or checkout specific files
git checkout <commit-hash> -- deployment/terraform/
```

---

## Documentation

- [Infrastructure README](../infra/README.md)
- [Deployment Guide](../infra/DEPLOYMENT_GUIDE.md)
- [Module Documentation](../infra/modules/)
- [Testing Plan](../infra/TESTING_PLAN.md)
- [Implementation Status](../infra/IMPLEMENTATION_STATUS.md)

---

## Questions?

See the [Monorepo Executive Summary](../plans/monorepo-executive-summary.md) for the full rationale and benefits of this migration.
