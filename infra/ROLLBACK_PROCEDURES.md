# Rollback Procedures

## Overview

This document provides step-by-step procedures for rolling back to the original infrastructure structure if issues are encountered.

## Safety Measures

The refactoring was designed with rollback in mind:

- ✅ Original code backed up (`deploy_all.sh.backup`, `deploy_sw.py.backup`)
- ✅ New infrastructure in `infra/` (fully migrated from `deployment/terraform/`)
- ✅ Active Terraform targets: `infra/targets/gcp-gke/` and `infra/targets/agnostic/`
- ✅ Can run both in parallel for validation

## Rollback Scenarios

### Scenario 1: Rollback Scripts Only

If new `deploy_all.sh` has issues but infrastructure is fine:

```bash
# Restore original deployment script
mv deploy_all.sh deploy_all.sh.new
mv deploy_all.sh.backup deploy_all.sh

# Restore original deploy_sw.py
mv deployment/deploy_sw.py deployment/deploy_sw.py.new
mv deployment/deploy_sw.py.backup deployment/deploy_sw.py

# Test original deployment
./deploy_all.sh --dev --storage=minio
```

### Scenario 2: Rollback Infrastructure

If new Terraform structure has issues:

```bash
# Destroy new infrastructure
cd infra/targets/gcp-gke
terraform destroy -var-file=dev.tfvars -auto-approve

# OR for agnostic
cd infra/targets/agnostic
terraform destroy -var-file=dev.tfvars -auto-approve

# Resume using active Terraform target
cd infra/targets/gcp-gke
terraform init
terraform apply -var-file=dev.tfvars
```

### Scenario 3: Full Rollback (Git)

If the entire refactoring needs to be reverted:

```bash
# Find the commit before refactoring started
git log --oneline | grep -i "monorepo\|refactor"

# Revert all refactoring commits
git revert <commit-hash>..HEAD

# Or reset to before refactoring (destructive!)
git reset --hard <commit-hash>

# Force push (use with caution)
git push origin main --force
```

### Scenario 4: Partial Rollback

Keep new structure but fix specific issues:

```bash
# Revert specific file
git checkout deploy_all.sh.backup -- deploy_all.sh

# Or revert specific module
rm -rf infra/modules/minio_storage
git checkout HEAD -- infra/modules/minio_storage
```

## State Recovery

### Recover Terraform State (GCP)

```bash
# List state versions in GCS
gsutil ls -l gs://YOUR_PROJECT-tfstate/cage/gcp-gke/

# Download specific state version
gsutil cp gs://YOUR_PROJECT-tfstate/cage/gcp-gke/default.tfstate \
  terraform.tfstate.recovered

# Restore
mv terraform.tfstate.recovered terraform.tfstate
```

### Recover Terraform State (Kubernetes Backend)

```bash
# Get state from Kubernetes secret
kubectl get secret tfstate-agnostic -n terraform-state \
  -o jsonpath='{.data.tfstate}' | base64 -d > terraform.tfstate.recovered

# Restore
cd infra/targets/agnostic
mv terraform.tfstate.recovered terraform.tfstate
```

## Validation After Rollback

### Check Deployment Works

```bash
# Active Terraform target
cd infra/targets/gcp-gke
terraform plan -var-file=dev.tfvars

# Verify services
kubectl get pods -n governance-stack
kubectl get svc -n governance-stack
```

### Check Scripts Work

```bash
# Test old deploy_all.sh
./deploy_all.sh --help

# Test original deployment flow
./deploy_all.sh --dev --storage=minio --no-build
```

## Emergency Procedures

### Critical Production Issue

1. **Immediate**: Switch traffic to backup/old deployment
```bash
kubectl scale deployment <new-deployment> --replicas=0 -n governance-stack
kubectl scale deployment <old-deployment> --replicas=3 -n governance-stack
```

2. **Investigate**: Check logs and metrics
```bash
kubectl logs -n governance-stack <pod-name> --tail=100
kubectl describe pod -n governance-stack <pod-name>
```

3. **Rollback**: Use appropriate scenario above

4. **Postmortem**: Document issue and fix before retrying

### Data Loss Prevention

**BEFORE destroying any infrastructure**:

```bash
# Backup all Kubernetes resources
kubectl get all -n governance-stack -o yaml > backup-k8s-resources.yaml

# Backup MinIO data (if critical)
kubectl exec -n governance-stack <minio-pod> -- \
  mc mirror myminio/vllm-models /tmp/backup

# Backup Terraform state
terraform show > terraform-state-backup.txt
```

## Testing Rollback Procedures

Practice rollback in dev environment:

```bash
# 1. Deploy new infrastructure
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# 2. Validate it works
./infra/validate_deployment.sh governance-stack-dev

# 3. Practice rollback
cd infra/targets/gcp-gke
terraform destroy -auto-approve

# 4. Restore infrastructure from active target
cd infra/targets/gcp-gke
terraform init
terraform apply -var-file=dev.tfvars -auto-approve

# 5. Verify old works
kubectl get pods -n governance-stack
```

## Decision Tree

```
Issue Detected
     │
     ├─> Scripts broken but infra works?
     │   └─> Rollback Scenario 1 (restore scripts)
     │
     ├─> Infrastructure broken?
     │   ├─> Minor module issue?
     │   │   └─> Fix module and redeploy
     │   │
     │   └─> Major infrastructure issue?
     │       └─> Rollback Scenario 2 (destroy new, use old)
     │
     └─> Everything broken?
         └─> Rollback Scenario 3 (Git revert)
```

## Prevention

To avoid needing rollback:

1. **Test in dev first**: Always validate changes in dev before prod
2. **Parallel deployments**: Run old and new in parallel
3. **Incremental migration**: Move one service at a time
4. **Monitoring**: Watch metrics during migration
5. **Backups**: Always backup state and data before major changes

## Contact

If rollback procedures don't work:

1. Check Git history for original files
2. Restore from `*.backup` files
3. Use `git reflog` to find lost commits
4. Contact infrastructure team for help

## Summary

**Rollback is safe and straightforward because**:

- Original code is backed up
- New code is in separate directories
- Can run both structures in parallel
- Terraform state is version-controlled
- No data loss (MinIO data in PVCs)

**The refactoring was designed to be reversible at every step.**
