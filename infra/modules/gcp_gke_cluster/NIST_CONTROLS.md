# GKE Cluster Compliance Controls

> **Architecture Note:** This document is organized by jurisdictional scope. ISO 42001 controls are **universal** and apply to all `CAGE_DEPLOYMENT_REGION` values. NIST SP 800-53 controls are **US_FED only** and apply exclusively when `CAGE_DEPLOYMENT_REGION=US_FED`. EU_ECB and APAC_MAS additional controls are listed in their respective sections.

## ISO 42001 Universal Controls (All Regions)

> **Scope: Universal — applies to ALL `CAGE_DEPLOYMENT_REGION` values**

These controls implement ISO/IEC 42001:2023 requirements and are active in every CAGE deployment regardless of jurisdiction.

| ISO 42001 Control | Implementation | GKE Feature | Evidence |
|-------------------|----------------|-------------|----------|
| **A.8.4** — AI system operation controls | Workload Identity: pods cannot access node service accounts | `workload_identity_config` | GKE Workload Identity binding |
| **A.8.4** — AI system operation controls | Shielded Nodes: secure boot + integrity monitoring | `shielded_instance_config` | GKE Shielded Nodes attestation |
| **A.9.2** — Evidence integrity | Node disk encryption at rest | Google-managed encryption (default) | GKE disk encryption status |
| **A.5.2** — AI policy | Binary Authorization: only signed images allowed | `enable_binary_authorization` | Binary Authorization policy |
| **A.5.3** — AI roles and responsibilities | Comprehensive audit logging of system and workload events | `enable_audit_logging` | Cloud Logging export |

## US_FED Additional Controls (NIST SP 800-53)

> **Scope: US_FED only — applies when `CAGE_DEPLOYMENT_REGION=US_FED`**

These controls implement NIST SP 800-53 Rev 5 requirements and are activated by `enable_nist_compliance=true`, which is set **only** for US_FED production deployments.

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

## EU_ECB Additional Controls

> **Scope: EU_ECB only — applies when `CAGE_DEPLOYMENT_REGION=EU_ECB`**

| EU Framework | Control | Implementation | Evidence |
|--------------|---------|----------------|----------|
| GDPR Art. 32 | Encryption at rest | CMEK with `europe-west1` KMS key | Cloud KMS key location |
| DORA Art. 10 | Comprehensive audit logging | `enable_audit_logging=true` | Cloud Logging export to `europe-west1` bucket |
| EU AI Act Art. 9 | Risk management system | Binary Authorization + Workload Identity | Binary Authorization policy |

## APAC_MAS Additional Controls

> **Scope: APAC_MAS only — applies when `CAGE_DEPLOYMENT_REGION=APAC_MAS`**

| MAS Framework | Control | Implementation | Evidence |
|---------------|---------|----------------|----------|
| MAS TRM §9.1 | Encryption at rest | CMEK with `asia-southeast1` KMS key | Cloud KMS key location |
| MAS Notice 655 | Audit logging | `enable_audit_logging=true` | Cloud Logging export to `asia-southeast1` bucket |
| MAS FEAT | Accountability controls | Workload Identity + Binary Authorization | GKE Workload Identity binding |

## Control Implementation Details

### ISO 42001 A.8.4 / US_FED SC-7: Boundary Protection

**Dev Mode** (`enable_nist_compliance=false`):
```hcl
# Public cluster
private_cluster_config: not configured
master_authorized_networks: 0.0.0.0/0 (all IPs allowed)
```

**Prod Mode — US_FED** (`enable_nist_compliance=true`):
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

### ISO 42001 A.5.2 / US_FED CM-7: Least Functionality

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

### ISO 42001 A.5.3 / US_FED AU-2, AU-3: Audit Logging

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
    enabled = true  # AU-12 (US_FED): Metric generation
  }
}
```

### ISO 42001 A.9.2 / US_FED SC-12, SC-13: Encryption Keys

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
  # REGION must match cage_deployment_region:
  #   US_FED   → us-central1
  #   EU_ECB   → europe-west1
  #   APAC_MAS → asia-southeast1
}
```

Requires: Cloud KMS key created in target with region matching `cage_deployment_region`.

## Testing Controls Individually

```bash
# Test binary authorization (universal ISO 42001 A.5.2)
cd infra/targets/gcp-gke
terraform apply \
  -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"

# Test audit logging (universal ISO 42001 A.5.3)
terraform apply \
  -var-file=dev.tfvars \
  -var="enable_audit_logging=true"

# Test full US_FED NIST compliance
terraform apply \
  -var-file=prod.tfvars  # cage_deployment_region=US_FED, all NIST flags enabled

# Test EU_ECB compliance
terraform apply \
  -var-file=eu-prod.tfvars  # cage_deployment_region=EU_ECB

# Test APAC_MAS compliance
terraform apply \
  -var-file=apac-prod.tfvars  # cage_deployment_region=APAC_MAS
```

## Audit Evidence

For compliance audits, provide:

1. **Configuration Evidence**: This document + `terraform show` output
2. **Runtime Evidence**: GKE cluster details from Cloud Console
3. **Log Evidence**: Cloud Logging query showing API server audit logs
4. **Binary Auth Evidence**: Binary Authorization policy + attestation records
5. **Jurisdiction Evidence**: `cage_deployment_region` value from `terraform show`

## See Also

- Security Postures Guide
- [NIST RMF Implementation](../../../docs/compliance/us_fed/NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md) — US_FED only
- [GCP IAM Configuration](../../targets/gcp-gke/iam.tf) - Least privilege service accounts
- [Jurisdictional Separation Analysis](../../../docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md)
