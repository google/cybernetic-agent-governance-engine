# Langfuse Logical Tenant Project Isolation Architecture

| Field              | Value                     |
| ------------------ | ------------------------- |
| **Classification** | PUBLIC                    |
| **Date**           | 2026-06-03                |
| **Last Updated**   | 2026-11-08                |
| **Version**        | 3.3.0                     |
| **Status**         | Implemented & Verified    |

> **Scope Distinction — Logical Langfuse Tenant Projects vs. GCP Project Custody Boundary:**
> This document specifies **logical tenant project isolation inside Langfuse** (`APPLICATION METRICS` vs. `COMPLIANCE AUDIT` Langfuse projects, keyed by distinct `LANGFUSE_*` vs. `LANGFUSE_COMPLIANCE_*` API credentials). It is distinct from CAGE's **GCP cloud project custody boundary** (`<PROJECT_ID>` workload project vs. `<PROJECT_ID>-evidence` dedicated evidence custody project for WORM GCS buckets and KMS signing keys; see [§6](#6-gcp-evidence-project-boundary-vs-langfuse-tenant-projects) and [`EVIDENCE_CHAIN.md`](EVIDENCE_CHAIN.md)).
>
> **Authoritative Compliance Metrics Source (`R-16`, `F-84`, `F-103`):**
> Per-control compliance metrics (`/v1/metrics/{control_id}` in [`metrics.py`](../../src/compliance_bridge/metrics.py)) and Step 5 remediation context (`_fetch_failing_traces` in [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py)) are computed **exclusively** over the signed, SHA-256 hash-chained `cage_evidence` custody chain — **Redis DB 1 (`cage:evidence:stream`, `EVIDENCE_STREAM_REDIS_DB=1`) merged with the GCS/S3 WORM `.ndjson` archive (`EVIDENCE_ARCHIVE_BUCKET`)**. Langfuse is **never** queried as an authoritative compliance control-outcome store.

---

## 1. Design Rationale

CAGE separates operational LLM observability from compliance audit scoring and custody-chain evidence across three planes:

| Plane | Backing Store | Content | Sensitivity | Retention |
| --- | --- | --- | --- | --- |
| **Authoritative Custody Chain** | Redis DB 1 (`cage:evidence:stream`) + GCS/S3 WORM `.ndjson` (`EVIDENCE_ARCHIVE_BUCKET`) | Signed, SHA-256 hash-chained governance decisions, spending seals, actuation receipts, refusals, deferrals, INFRA events | Primary evidentiary record | 7 years (WORM) |
| **Operational LLM Telemetry** | Langfuse Tenant Project 1 (`LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY`) | Inference latency, token counts, prompt lookups, agent execution spans | Operational (may contain redacted prompts) | Operational |
| **Compliance Audit & Advisory Telemetry** | Langfuse Tenant Project 2 (`LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY`) | Mirrored OSCAL finding scores, FAIL eval dataset items, Step 5 LLM remediation advisories | Secondary audit observability | Audit dashboard |

Separating the two logical Langfuse tenant projects — and decoupling both from authoritative control-outcome computation — enforces three security properties:

### 1.1 Evidentiary Independence

If compliance scores or control metrics were read from the same Langfuse project that governed advisor pods can write to, a compromised application workload could forge passing `iso_42001_outcome` metadata or pollute compliance dashboards. In CAGE:
1. [`metrics.py`](../../src/compliance_bridge/metrics.py) and `_fetch_failing_traces()` read **only** from the governance-plane `cage_evidence` custody chain (Redis DB 1 + WORM `.ndjson`), which workload pods cannot forge or mutate.
2. [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) mirrors deterministic OSCAL audit scores and LLM remediation advisories into the dedicated **Compliance Audit** Langfuse tenant project (`LANGFUSE_COMPLIANCE_*`), to which workload pods hold zero credentials.

### 1.2 Credential Blast Radius Containment

The governed financial advisor workload (`src/governed_financial_advisor/`) mounts only `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` (`advisor-secrets`) for operational trace export. If a workload pod is compromised, the attacker gains write access only to operational LLM traces — they **cannot** write or delete records in the `COMPLIANCE AUDIT` Langfuse project (`LANGFUSE_COMPLIANCE_*` is mounted exclusively in `compliance-bridge`), and **cannot** alter per-control Lula pass/fail outcomes backed by `cage_evidence`.

### 1.3 Regulatory Alignment

- **ISO/IEC 42001:2023 §A.7.5** — AI management system records are preserved in tamper-evident WORM custody independent of operational telemetry sinks.
- **NIST SP 800-53 Rev. 5 AU-9** — Audit information and audit tools are protected from unauthorized access, modification, and deletion via separate secret objects and WORM retention.
- **DORA Art. 12** — ICT audit trails remain segregated from the operational application workloads being monitored.

---

## 2. Logical Tenant & Custody Topology

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                         GKE Cluster: governance-stack                        │
│                                                                              │
│  ┌───────────────────────────┐   ┌─────────────────────────────────────────┐ │
│  │ governed-financial-advisor│   │ compliance-bridge (port 3001)           │ │
│  │ (workload pod)            │   │                                         │ │
│  │                           │   │ Custody-Chain Readers (metrics.py &     │ │
│  │ Credentials:              │   │ Step 5 _fetch_failing_traces):          │ │
│  │  LANGFUSE_PUBLIC_KEY      │   │  • EVIDENCE_STREAM_REDIS_URL (DB 1) (R) │ │
│  │  LANGFUSE_SECRET_KEY      │   │  • EVIDENCE_ARCHIVE_BUCKET (WORM)   (R) │ │
│  │                           │   │                                         │ │
│  │ Writes operational spans: │   │ Langfuse Tenant Credentials:            │ │
│  │  → App Langfuse Project   │   │  • LANGFUSE_COMPLIANCE_PUBLIC_KEY  (RW) │ │
│  │                           │   │  • LANGFUSE_COMPLIANCE_SECRET_KEY  (RW) │ │
│  │ Zero access to:           │   │  • LANGFUSE_PUBLIC_KEY (/v1/prompts)(R) │ │
│  │  ✗ Compliance Langfuse    │   │  • LANGFUSE_SECRET_KEY (/v1/prompts)(R) │ │
│  │  ✗ WORM custody archive   │   │                                         │ │
│  └─────────────┬─────────────┘   └──────────┬──────────────────────┬───────┘ │
│                │                            │                      │         │
└────────────────┼────────────────────────────┼──────────────────────┼─────────┘
                 │                            │                      │
                 ▼                            ▼                      ▼
┌──────────────────────────┐  ┌─────────────────────────────┐  ┌──────────────────────────────┐
│ Langfuse Tenant Project: │  │ Authoritative Custody Chain │  │ Langfuse Tenant Project:     │
│ APPLICATION METRICS      │  │ (Redis DB 1 + GCS WORM)     │  │ COMPLIANCE AUDIT             │
│                          │  │                             │  │                              │
│ • Inference traces       │  │ • GOVERNANCE_DECISION       │  │ • Mirrored OSCAL scores      │
│ • Token & latency spans  │  │ • GOVERNANCE_SEAL_CONSUMED  │  │ • FAIL eval dataset items    │
│ • Prompt registry items  │  │ • ACTUATION_RECEIPT         │  │ • Step 5 remediation         │
│                          │  │ • GOVERNANCE_REFUSAL        │  │   advisory traces            │
│ Never queried for Lula   │  │ • Signed .ndjson batches    │  │                              │
│ control metrics!         │  │                             │  │ Access: compliance-bridge    │
│                          │  │ Queried by: metrics.py &    │  │         ONLY                 │
│ Access: advisor (W),     │  │             Step 5 context  │  │                              │
│ bridge (/v1/prompts R)   │  │                             │  │                              │
└──────────────────────────┘  └─────────────────────────────┘  └──────────────────────────────┘
```

**Key architectural boundary:**
- **Control outcomes & Lula API metrics (`metrics.py`)**: read **exclusively** from the Redis DB 1 (`cage:evidence:stream`, `cage:evidence:infra:stream`) + GCS/S3 WORM `.ndjson` custody chain (`_query_cage_evidence_records()`). Neither Langfuse tenant project is queried.
- **Compliance Langfuse tenant project (`LANGFUSE_COMPLIANCE_*`)**: written by [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) (`_make_compliance_langfuse()`) to mirror OSCAL assessment scores, populate failure evaluation datasets, and record human-reviewed LLM remediation advisories.
- **Application Langfuse tenant project (`LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY`)**: written by governed agents/gateway OTLP exporters for operational observability, and read on `compliance-bridge` solely by the optional `/v1/prompts/{name}` prompt proxy in [`main.py`](../../src/compliance_bridge/main.py) — never by `metrics.py` or `audit_workflow.py`.

---

## 3. Implementation Map

### 3.1 Kubernetes Secrets (Separate Secret Objects)

Distinct Kubernetes `Secret` objects are provisioned by Terraform ([`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf)):

| Secret Name | Keys | Mounted By |
| --- | --- | --- |
| `advisor-secrets` | `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY` | `governed-financial-advisor` |
| `langfuse-secrets` | `public-key`, `secret-key` | `compliance-bridge` (prompt proxy & startup credential check) |
| `langfuse-compliance-secrets` | `public-key`, `secret-key` (`LANGFUSE_COMPLIANCE_*`) | `compliance-bridge` only |

Source: [`app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf) and [`compliance_bridge/main.tf` L143-L183](../../infra/modules/compliance_bridge/main.tf#L143-L183).

### 3.2 Compliance Bridge Pod Credential Mounts

The compliance bridge Deployment ([`infra/modules/compliance_bridge/main.tf`](../../infra/modules/compliance_bridge/main.tf)) mounts separate secret references for operational prompt lookup vs. isolated compliance scoring:

```hcl
env {
  name = "LANGFUSE_PUBLIC_KEY"
  value_from {
    secret_key_ref {
      name = "langfuse-secrets" # Operational tenant project
      key  = "public-key"
    }
  }
}
# ...
env {
  name = "LANGFUSE_COMPLIANCE_PUBLIC_KEY"
  value_from {
    secret_key_ref {
      name     = "langfuse-compliance-secrets" # Isolated compliance tenant project
      key      = "public-key"
      optional = true
    }
  }
}
```

### 3.3 Python Boundaries (`metrics.py` vs. `audit_workflow.py`)

#### Authoritative Custody-Chain Metrics ([`metrics.py`](../../src/compliance_bridge/metrics.py))

[`metrics.py`](../../src/compliance_bridge/metrics.py) contains zero Langfuse SDK imports or queries. `_query_cage_evidence_records()` merges attested WORM `.ndjson` batches (`get_cold_store()`) with recent Redis DB 1 stream entries (`cage:evidence:stream` and `cage:evidence:infra:stream`), deduplicating by `record_hash`, `(chain_id, sequence)`, or `stream_id`.

#### Compliance Telemetry Client ([`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py))

[`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) instantiates only the isolated compliance Langfuse client (`_make_compliance_langfuse()`) to mirror OSCAL findings and advisory metadata:

```python
def _make_compliance_langfuse():
    import httpx

    return _get_langfuse_class()(
        public_key=os.environ.get("LANGFUSE_COMPLIANCE_PUBLIC_KEY", ""),
        secret_key=os.environ.get("LANGFUSE_COMPLIANCE_SECRET_KEY", ""),
        host=os.environ.get(
            "LANGFUSE_COMPLIANCE_HOST",
            os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        ),
        httpx_client=httpx.Client(timeout=_LANGFUSE_SDK_TIMEOUT_S),
    )
```

### 3.4 Data Flow by Audit Pipeline Step

The 6-step audit pipeline in [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) maintains strict separation between custody evidence and Langfuse telemetry:

| Step | Action | Backing Store / Tenant | Helper |
| --- | --- | --- | --- |
| 1 | Persist raw OSCAL YAML artifact | GCS/S3 WORM cold store | `put_oscal_artifact()` |
| 2 | Parse OSCAL YAML → `list[OscalFinding]` | Deterministic in-memory | `parse_oscal_yaml()` |
| 2b | Append findings to SHA-256 hash chain | Context Accumulator + WORM | `ContextAccumulator` |
| 3 | Mirror findings as compliance scores | **Compliance** Langfuse tenant | `_make_compliance_langfuse()` |
| 3c | Populate FAIL eval dataset items | **Compliance** Langfuse tenant | `_make_compliance_langfuse()` |
| 4 | Dispatch critical failure alert | Slack / PagerDuty / Webhook | `create_notifier()` |
| 5a | Fetch 24h blocking governance records | **`cage_evidence` custody chain (R)** | `_query_cage_evidence_records()` |
| 5b | Log LLM remediation advisory | **Compliance** Langfuse tenant | `_make_compliance_langfuse()` |
| 6 | Persist AARM conformance report | GCS/S3 WORM cold store | `get_cold_store()` |

Step 5a reads blocking governance records (`GOVERNANCE_REFUSAL`, `GOVERNANCE_DEFERRAL`, failed `ACTUATION_RECEIPT`, `CBF_ROLLBACK`, etc.) directly from the `cage_evidence` custody chain rather than from application Langfuse traces, then logs the generated human-review advisory to the isolated **Compliance** Langfuse tenant project.

---

## 4. Threat Model

### 4.1 Threats Mitigated

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **Control Metric Poisoning** | Compromised workload emits fake `PASSED` spans to Langfuse | `metrics.py` and Step 5 ignore Langfuse completely and read only signed/hash-chained `cage_evidence` custody records |
| **Compliance Score Tampering** | Compromised workload attempts to overwrite OSCAL audit scores in Langfuse | Workload pods do not mount `LANGFUSE_COMPLIANCE_*` credentials |
| **Evidence Deletion** | Attacker with `advisor-secrets` attempts to delete audit records | WORM retention on `<PROJECT_ID>-evidence` archive bucket + separate compliance Langfuse tenant keys |
| **Credential Rotation Blast Radius** | Rotating operational `advisor-secrets` keys | `langfuse-compliance-secrets` has an independent lifecycle |

### 4.2 Residual Risks & Mitigations

| Risk | Description | Status / Mitigation |
| --- | --- | --- |
| **Shared Self-Hosted Langfuse Instance** | Both logical Langfuse tenant projects share the regional self-hosted `LANGFUSE_HOST` deployment | Mitigated because Langfuse holds secondary observability mirrors only; authoritative evidence lives in WORM object storage with KMS signatures |
| **Compliance Bridge Pod Compromise** | `compliance-bridge` holds `LANGFUSE_COMPLIANCE_*` and custody reader access | Mitigated by Linkerd mTLS authorization policies, non-root `securityContext`, and WORM bucket retention locks (`put_if_absent` immutability) |

---

## 5. Operational Configuration & POA&M Closure Status

### 5.1 Environment Variables

| Variable | Required By | Purpose |
| --- | --- | --- |
| `EVIDENCE_STREAM_REDIS_URL` / `EVIDENCE_STREAM_REDIS_DB` | Gateway, Compliance Bridge | Redis DB 1 hot `cage_evidence` stream (`cage:evidence:stream`) |
| `EVIDENCE_COLD_STORE` / `EVIDENCE_ARCHIVE_BUCKET` | Compliance Bridge | GCS/S3 WORM `.ndjson` custody archive written by `EvidenceCustodian` |
| `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | Advisor, Compliance Bridge | Operational LLM telemetry tenant project credentials |
| `LANGFUSE_HOST` | Advisor, Compliance Bridge | Regional self-hosted Langfuse base URL |
| `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` | Compliance Bridge only | Isolated compliance audit tenant project credentials |
| `LANGFUSE_COMPLIANCE_HOST` | Compliance Bridge (optional) | Optional dedicated host for compliance Langfuse; falls back to `LANGFUSE_HOST` |

### 5.2 Startup Credential Guard & `/health` Reporting (`POAM-018` — Closed)

> ✅ **POAM-018 (AU-9 / ISO 42001 §A.9.4) — Closed (verified 2026-09-22):** Both remediation clauses are implemented and verified on `main` (see [`POAM_US_FED.md`](../compliance/us_fed/POAM_US_FED.md) and [`POAM_ISO42001.md`](../compliance/universal/POAM_ISO42001.md)):
> 1. **Fail-closed startup validation (`489949a`):** `validate_langfuse_credentials()` in [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) (invoked from FastAPI lifespan in [`main.py`](../../src/compliance_bridge/main.py)) raises `RuntimeError` at startup in non-development environments when `LANGFUSE_COMPLIANCE_PUBLIC_KEY`, `LANGFUSE_COMPLIANCE_SECRET_KEY`, `LANGFUSE_PUBLIC_KEY`, or `LANGFUSE_SECRET_KEY` is absent (emitting a `[POAM-018]` warning only in `dev` / `development` / `test` / `ci`).
> 2. **Health surface (`fd5e28b`):** `GET /health` in [`main.py`](../../src/compliance_bridge/main.py) reports `langfuse_compliance_configured` and `langfuse_app_configured`, covered by [`tests/test_gateway_compliance_bridge_contract.py`](../../tests/test_gateway_compliance_bridge_contract.py).

Historical context for the original gap is preserved in [`NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md`](../compliance/us_fed/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md).

### 5.3 Terraform Fallback Elimination (`POAM-019` — Closed)

> ✅ **POAM-019 (AU-9, SC-7) — Closed (verified 2026-09-22):** [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf) removed the credential fallback that previously substituted application Langfuse keys when `langfuse_compliance_public_key` / `langfuse_compliance_secret_key` were empty. Under `local.enforcing_posture`, `terraform_data.poam_019_empty_key_guard` rejects empty compliance keys and `terraform_data.poam_019_shared_key_guard` rejects compliance keys identical to application keys, verified by [`poam_019.tftest.hcl`](../../infra/targets/gcp-gke/tests/poam_019.tftest.hcl) (with targeted-plan scope documented under `POAM-2026-180` in [`POAM.md`](../POAM.md)).

### 5.4 Verification Commands

```bash
# 1. Confirm separate Kubernetes Secret objects exist
kubectl get secret advisor-secrets langfuse-compliance-secrets -n governance-stack

# 2. Confirm advisor workload pod mounts ZERO compliance Langfuse credentials
kubectl exec -n governance-stack deploy/governed-financial-advisor -- env | grep LANGFUSE_COMPLIANCE
# Expected: no output

# 3. Confirm compliance-bridge health reports compliance project configuration
kubectl exec -n governance-stack deploy/compliance-bridge -- \
  python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:3001/health').read().decode())"
```

---

## 6. GCP Evidence Project Boundary vs. Langfuse Tenant Projects

Logical Langfuse tenant isolation (two projects inside Langfuse) is complementary to — and must not be conflated with — **GCP cloud project isolation** for cryptographic custody:

| Boundary Layer | Scope | Isolation Mechanism |
| --- | --- | --- |
| **Langfuse Logical Tenant Isolation** *(this document)* | Operational LLM traces (`LANGFUSE_PUBLIC_KEY`) vs. compliance audit/advisory scores (`LANGFUSE_COMPLIANCE_PUBLIC_KEY`) inside self-hosted regional Langfuse | Separate Langfuse project API key pairs, separate K8s `Secret` objects, `poam_019_*` Terraform guards |
| **GCP Custody Project Boundary (`<PROJECT_ID>-evidence`)** | Primary workload project (`<PROJECT_ID>`) vs. dedicated evidence custody GCP project (`<PROJECT_ID>-evidence`) | Cross-project IAM boundary isolating WORM GCS custody buckets (`EVIDENCE_ARCHIVE_BUCKET`), Cloud KMS asymmetric attestation keys (`EVIDENCE_KMS_KEY`), and immutable Cloud Audit Logs from workload project administrators |

Optionally hosting a dedicated compliance Langfuse instance inside `<PROJECT_ID>-evidence` over Private Service Connect requires only updating `LANGFUSE_COMPLIANCE_HOST` and IAM bindings without changing `metrics.py` or `audit_workflow.py`.

---

## Related Documentation

| Document | Relationship |
| --- | --- |
| [`EVIDENCE_CHAIN.md`](EVIDENCE_CHAIN.md) | Authoritative Redis DB 1 + WORM `.ndjson` custody architecture |
| [`GATEWAY_ARCHITECTURE.md`](GATEWAY_ARCHITECTURE.md) | Layer 1 governance gateway and OTLP telemetry pipeline |
| [`EXTENSIBILITY_ARCHITECTURE.md`](EXTENSIBILITY_ARCHITECTURE.md) | Layer boundaries and telemetry provider seam |
| [`NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md`](../compliance/us_fed/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md) | Historical assessment context for `POAM-018` |
| [`infra/ENV_INTEGRATION.md`](../../infra/ENV_INTEGRATION.md) | Environment variable and secret wiring map |
| [`compliance_bridge/main.tf`](../../infra/modules/compliance_bridge/main.tf) | Terraform Kubernetes Deployment for `compliance-bridge` |
| [`app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf) | Terraform provisioning of isolated Kubernetes Secrets |
| [`POAM_US_FED.md`](../compliance/us_fed/POAM_US_FED.md) | `POAM-018` / `POAM-019` closure records (NIST AU-9, SC-7) |
| [`POAM_ISO42001.md`](../compliance/universal/POAM_ISO42001.md) | `POAM-018` / `POAM-019` closure records (ISO 42001 §A.9.4) |
