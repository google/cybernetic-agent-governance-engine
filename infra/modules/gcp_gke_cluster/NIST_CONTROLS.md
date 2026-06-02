# NIST SP 800-53 Control Mapping

This document maps the GKE cluster module's security feature flags to specific NIST SP 800-53 Rev5 controls.

## Control Implementation Matrix

| Flag | NIST Controls | Implementation | Evidence |
|------|---------------|----------------|----------|
| `enable_nist_compliance` | SC-7 | **Boundary Protection**: Private cluster with private nodes, no public endpoints | GKE private_cluster_config |
| `enable_nist_compliance` | AC-3 | **Access Enforcement**: Master authorized networks restrict control plane access to corporate VPN | master_authorized_networks_config |
| `enable_nist_compliance` | N/A | **Deletion Protection**: Prevents accidental cluster deletion | deletion_protection=true |
| `enable_binary_authorization` | CM-7 | **Least Functionality**: Only signed/approved container images allowed | Binary Authorization ENFORCE mode |
| `enable_binary_authorization` | SI-7 | **Software Integrity**: Cryptographic signature verification | Binary Authorization attestations |
| `enable_audit_logging` | AU-2 | **Audit Events**: Comprehensive logging of system and workload events | logging_config.enable_components |
| `enable_audit_logging` | AU-3 | **Content of Audit Records**: API server, scheduler, controller logs | logging_config includes all components |
| `enable_audit_logging` | AU-9 | **Protection of Audit Information**: Immutable GCS bucket (configured in target) | Logs exported to locked GCS bucket |
| `enable_audit_logging` | AU-12 | **Audit Generation**: Managed Prometheus metrics | monitoring_config.managed_prometheus |
| `enable_cmek` | SC-12 | **Cryptographic Key Establishment**: Customer-managed KMS keys | database_encryption with Cloud KMS |
| `enable_cmek` | SC-13 | **Cryptographic Protection**: FIPS 140-2 validated crypto modules | Google Cloud KMS (FIPS 140-2 Level 3) |

## Always-Enabled Baseline Controls

These controls are enabled in both dev and prod for basic security:

| Control | Implementation | Rationale |
|---------|----------------|-----------|
| AC-6 | Workload Identity | Least privilege - pods can't access node service accounts |
| IA-3 | Shielded Nodes | Device identification - secure boot + integrity monitoring |
| SC-8 | Node encryption at rest | In-transit protection - all node disks encrypted by default |

## Control Implementation Details

### SC-7: Boundary Protection

**Dev Mode** (`enable_nist_compliance=false`):
```hcl
# Public cluster
private_cluster_config: not configured
master_authorized_networks: 0.0.0.0/0 (all IPs allowed)
```

**Prod Mode** (`enable_nist_compliance=true`):
```hcl
private_cluster_config {
  enable_private_nodes    = true  # Nodes have no public IPs
  enable_private_endpoint = true  # Master endpoint private (optional)
}

master_authorized_networks_config {
  cidr_blocks {
    cidr_block = "10.0.0.0/8"  # Corporate VPN only
  }
}
```

### CM-7: Least Functionality

**Dev Mode** (`enable_binary_authorization=false`):
```hcl
binary_authorization {
  evaluation_mode = "DISABLED"  # Any image can run
}
```

**Prod Mode** (`enable_binary_authorization=true`):
```hcl
binary_authorization {
  evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"  # Only signed images
}
```

Requires: Binary Authorization policy + CI pipeline image signing.

### AU-2, AU-3: Audit Logging

**Dev Mode** (`enable_audit_logging=false`):
```hcl
# Default GKE logging (Cloud Logging enabled but minimal)
logging_config: not configured
```

**Prod Mode** (`enable_audit_logging=true`):
```hcl
logging_config {
  enable_components = [
    "SYSTEM_COMPONENTS",  # Node logs
    "WORKLOADS",          # Container logs
    "API_SERVER",         # K8s API audit logs
    "SCHEDULER",          # Scheduling decisions
    "CONTROLLER_MANAGER"  # Controller actions
  ]
}

monitoring_config {
  managed_prometheus {
    enabled = true  # AU-12: Metric generation
  }
}
```

### SC-12, SC-13: Encryption Keys

**Dev Mode** (`enable_cmek=false`):
```hcl
# Google-managed encryption keys (automatic)
database_encryption: not configured
```

**Prod Mode** (`enable_cmek=true`):
```hcl
database_encryption {
  state    = "ENCRYPTED"
  key_name = "projects/PROJECT/locations/REGION/keyRings/RING/cryptoKeys/KEY"
}
```

Requires: Cloud KMS key created in target.

## Testing Controls Individually

You can test each control in isolation:

```bash
# Test binary authorization
cd infra/targets/gcp-gke
terraform apply \
  -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"

# Test audit logging
terraform apply \
  -var-file=dev.tfvars \
  -var="enable_audit_logging=true"

# Test full NIST compliance
terraform apply \
  -var-file=prod.tfvars  # All flags enabled
```

## Audit Evidence

For compliance audits, provide:

1. **Configuration Evidence**: This README + `terraform show` output
2. **Runtime Evidence**: GKE cluster details from Cloud Console
3. **Log Evidence**: Cloud Logging query showing API server audit logs
4. **Binary Auth Evidence**: Binary Authorization policy + attestation records

## See Also

- [Security Postures Guide](../../../plans/monorepo-security-postures.md)
- [NIST RMF Implementation](../../../docs/NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md)
- [GCP IAM Configuration](../../targets/gcp-gke/iam.tf) - Least privilege service accounts
