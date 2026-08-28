# Account Management Procedures — CAGE v3.0.0

**Document:** POAM-001 / NIST SP 800-53 AC-2 / ISO 42001 §A.9.2
**Date:** 2026-06-23
**Status:** Draft — requires System Owner review
**POAM:** POAM-001

---

## 1. Purpose

This document establishes account management procedures for the CAGE system, satisfying NIST SP 800-53 AC-2 (Account Management). It covers GCP IAM service accounts, GKE RBAC, and application-level service accounts.

---

## 2. GCP IAM Account Lifecycle

### 2.1 Provisioning

All GCP IAM service accounts for CAGE are managed via Terraform (`infra/targets/gcp-gke/iam.tf`). No manual IAM changes are permitted in production.

**Process:**
1. Engineer creates a PR modifying `infra/targets/gcp-gke/iam.tf` with the required service account and role binding
2. PR requires review from security engineer and engineering lead
3. After approval, Terraform apply is run in the CI/CD pipeline
4. Service account key is never created — workload identity federation is used for all GCP API access

### 2.2 Least-Privilege Role Assignments

| Service Account | GCP Roles | Purpose |
|---|---|---|
| `cage-gateway-sa` | `roles/storage.objectViewer`, `roles/secretmanager.secretAccessor`, `roles/cloudkms.cryptoKeyEncrypterDecrypter` | Gateway: reads model weights, accesses secrets, signs audit evidence |
| `cage-compliance-bridge-sa` | `roles/storage.objectCreator`, `roles/storage.objectViewer` | Compliance bridge: writes OSCAL artifacts to GCS |
| `cage-lula-sa` | `roles/container.viewer` | Lula: read-only cluster inspection for validation manifests |
| `cage-vllm-sa` | `roles/storage.objectViewer` | vLLM: reads model weights from GCS |
| `cage-agentsight-sa` | `roles/logging.logWriter`, `roles/monitoring.metricWriter` | AgentSight: writes eBPF telemetry to Cloud Logging |

### 2.3 Deactivation

When a service account is no longer needed:
1. Remove the service account and binding from `iam.tf`
2. PR review required as per provisioning process
3. Run `terraform plan` to verify only the target service account is affected before applying

### 2.4 Periodic Review

Service accounts are reviewed quarterly:
- Run `gcloud iam service-accounts list --project=$PROJECT_ID` to enumerate active accounts
- Cross-reference against `iam.tf` to identify any orphaned accounts (not managed by Terraform)
- Orphaned accounts are removed within 5 business days of discovery

---

## 3. GKE RBAC

### 3.1 Namespace-Scoped RBAC

CAGE workloads run in the `governance-stack` namespace. RBAC is namespace-scoped to enforce least privilege:

```yaml
# Example: Compliance bridge ServiceAccount with read-only access to ConfigMaps
apiVersion: v1
kind: ServiceAccount
metadata:
  name: compliance-bridge
  namespace: governance-stack
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: compliance-bridge-reader
  namespace: governance-stack
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: compliance-bridge-reader-binding
  namespace: governance-stack
subjects:
  - kind: ServiceAccount
    name: compliance-bridge
roleRef:
  kind: Role
  name: compliance-bridge-reader
  apiGroup: rbac.authorization.k8s.io
```

### 3.2 ClusterRole Restrictions

No CAGE workload has ClusterAdmin or cluster-scoped write permissions. Lula has `roles/container.viewer` (read-only) to inspect Deployments for validation assertions.

---

## 4. Application Service Account Lifecycle

The compliance bridge and gateway use Langfuse API keys stored in the `advisor-secrets` Kubernetes Secret. API key lifecycle:

| Event | Process |
|---|---|
| **Creation** | Langfuse API key generated in cage-compliance Langfuse project; stored in GCP Secret Manager; mounted as K8s Secret |
| **Rotation** | Rotate in Langfuse UI → update GCP Secret Manager → rolling restart of compliance bridge pod |
| **Deactivation** | Revoke in Langfuse UI → remove from GCP Secret Manager → verify `/health` endpoint reports `langfuse_compliance_configured: false` |

---

## 5. Review Cadence

| Review Type | Cadence | Owner |
|---|---|---|
| Quarterly IAM service account enumeration | Every 3 months | Security engineer |
| Annual full AC-2 review | Every 12 months | System Owner + AO |
| POAM-001 milestone review | Monthly (per POAM review cadence) | Compliance officer |

---

## Related Documents

- `infra/targets/gcp-gke/iam.tf` — Terraform IAM resource definitions
- `docs/POAM_US_FED.md` — POAM-001 tracking item
