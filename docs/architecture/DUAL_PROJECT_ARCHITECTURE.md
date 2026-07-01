# Dual-Project Telemetry Isolation Architecture

| Field              | Value                     |
| ------------------ | ------------------------- |
| **Classification** | PUBLIC                    |
| **Date**           | 2026-06-03                |
| **Version**        | 0.1.0-rc.1                |
| **Status**         | Implemented & Verified (GKE deployment confirmed 2026-06-03) |

---

## 1. Design Rationale

CAGE produces two fundamentally different categories of telemetry:

| Category                    | Content                                                     | Sensitivity        | Retention     |
| --------------------------- | ----------------------------------------------------------- | ------------------ | ------------- |
| **Application Metrics**     | Inference latency, token counts, model performance, traces  | May contain PII    | Operational   |
| **Compliance Audit Evidence** | OSCAL findings, governance verdicts, ISO 42001 control scores, hash-chained context accumulator, AARM conformance reports | Evidentiary record | 7 years       |

These categories must be physically isolated for three reasons:

### 1.1 Evidentiary Independence

If compliance audit evidence is stored in the same project that produces the telemetry being audited, a single compromised credential can both generate the data and tamper with the evidence. In litigation, opposing counsel asks: *"Who controls the project where the compliance evidence is stored?"* If the answer is *"the same service account that runs the AI agent"*, the evidence is self-attested and its evidentiary weight collapses.

### 1.2 IAM Blast Radius Containment

The governed financial advisor pod (`src/governed_financial_advisor/`) has `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` credentials that allow it to write traces and scores to the application metrics project. If a container breakout or dependency supply-chain attack compromises this pod, the attacker gains write access to application telemetry — but **cannot read, write, or delete compliance audit evidence** because those credentials (`LANGFUSE_COMPLIANCE_*`) are mounted only in the compliance bridge pod.

### 1.3 Regulatory Requirement

- **ISO 42001 §A.7.5** — Records of AI management system performance must be maintained with controls to ensure integrity and availability.
- **NIST SP 800-53 AU-9** — Audit records must be protected against unauthorized access, modification, and deletion.
- **DORA Art. 12** — ICT audit trails must be maintained independently of the systems being audited.

Separate project credentials satisfy all three by ensuring no single service account has write access to both the operational telemetry and the audit evidence.

---

## 2. Project Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                     GKE Cluster: governance-stack                   │
│                                                                     │
│  ┌───────────────────────────┐   ┌────────────────────────────────┐ │
│  │ governed-financial-advisor│   │ compliance-bridge              │ │
│  │ (port 8000)              │   │ (port 3001)                    │ │
│  │                          │   │                                │ │
│  │ Credentials:             │   │ Credentials:                   │ │
│  │  LANGFUSE_PUBLIC_KEY     │   │  LANGFUSE_PUBLIC_KEY      (R)  │ │
│  │  LANGFUSE_SECRET_KEY     │   │  LANGFUSE_SECRET_KEY      (R)  │ │
│  │                          │   │  LANGFUSE_COMPLIANCE_PUBLIC_KEY │ │
│  │ Writes to:               │   │  LANGFUSE_COMPLIANCE_SECRET_KEY│ │
│  │  → Application Project   │   │                                │ │
│  │                          │   │ Reads from:                    │ │
│  │                          │   │  → Application Project    (R)  │ │
│  │                          │   │ Writes to:                     │ │
│  │                          │   │  → Compliance Project          │ │
│  └───────────┬──────────────┘   └────────────┬───────────────────┘ │
│              │                                │                     │
└──────────────┼────────────────────────────────┼─────────────────────┘
               │                                │
               ▼                                ▼
┌──────────────────────────┐   ┌──────────────────────────────────────┐
│ Langfuse Project:        │   │ Langfuse Project:                    │
│ APPLICATION METRICS      │   │ COMPLIANCE AUDIT                     │
│                          │   │                                      │
│ Contents:                │   │ Contents:                            │
│  • Inference traces      │   │  • OSCAL finding scores              │
│  • Token counts          │   │  • ISO 42001 control verdicts        │
│  • Model latency         │   │  • Governance violation records      │
│  • Agent routing spans   │   │  • Remediation advisory traces       │
│  • iso_42001_safety_rate │   │  • Eval dataset items (FAIL findings)│
│    scores                │   │  • AARM conformance evidence         │
│                          │   │                                      │
│ Access: governed-advisor │   │ Access: compliance-bridge ONLY       │
│         compliance-bridge│   │                                      │
│         (read only)      │   │                                      │
└──────────────────────────┘   └──────────────────────────────────────┘
```

**Key observation:** The compliance bridge has credentials for *both* projects, but uses them asymmetrically:
- **Application project** — read-only access for [`metrics.py`](../../src/compliance_bridge/metrics.py) to query traces tagged with `control:<controlId>` and aggregate `iso_42001_outcome` metadata.
- **Compliance project** — write access for [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) to ingest OSCAL findings, create per-control compliance scores, and log LLM remediation advisories.

The governed financial advisor pod has **no access** to the compliance project.

---

## 3. Implementation Map

### 3.1 Kubernetes Secrets (Separate Secret Objects)

Two distinct Kubernetes secrets are provisioned by Terraform ([`app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf)):

| Secret Name                      | Keys                                             | Mounted By              |
| -------------------------------- | ------------------------------------------------ | ----------------------- |
| `advisor-secrets`                | `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`      | governed-financial-advisor, compliance-bridge |
| `langfuse-compliance-secrets`    | `LANGFUSE_COMPLIANCE_PUBLIC_KEY`, `LANGFUSE_COMPLIANCE_SECRET_KEY` | compliance-bridge only  |

Source: [`app_secrets/main.tf` L10-31](../../infra/modules/app_secrets/main.tf) (advisor-secrets) and [`app_secrets/main.tf` L45-58](../../infra/modules/app_secrets/main.tf) (compliance-secrets).

### 3.2 Compliance Bridge Pod (Dual Credential Mount)

The compliance bridge K8s deployment ([`compliance-bridge.yaml`](../../deployment/k8s/compliance-bridge.yaml)) mounts both secret objects:

```yaml
# Main Langfuse project (application performance metrics)
- name: LANGFUSE_PUBLIC_KEY
  valueFrom:
    secretKeyRef:
      name: langfuse-secrets      # ← Application project
      key: public-key
# ...
# Dedicated Langfuse compliance project (audit traces isolated from app metrics)
- name: LANGFUSE_COMPLIANCE_PUBLIC_KEY
  valueFrom:
    secretKeyRef:
      name: langfuse-compliance-secrets   # ← Compliance project
      key: public-key
```

Source: [`compliance-bridge.yaml` L44-68](../../deployment/k8s/compliance-bridge.yaml).

### 3.3 Python Client Factories (Explicit Separation)

Two separate Langfuse client factories enforce the isolation in application code:

#### Application Project Client

Used by [`metrics.py`](../../src/compliance_bridge/metrics.py) to **read** traces for compliance metrics aggregation:

```python
# src/compliance_bridge/metrics.py L55-61
def _make_app_langfuse():
    from langfuse.api import LangfuseAPI
    return LangfuseAPI(
        username=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
        password=os.environ.get("LANGFUSE_SECRET_KEY", ""),
        base_url=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
    )
```

#### Compliance Project Client

Used by [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) to **write** OSCAL findings and governance scores:

```python
# src/compliance_bridge/audit_workflow.py L102-110
def _make_compliance_langfuse():
    return _get_langfuse_class()(
        public_key=os.environ.get("LANGFUSE_COMPLIANCE_PUBLIC_KEY", ""),
        secret_key=os.environ.get("LANGFUSE_COMPLIANCE_SECRET_KEY", ""),
        host=os.environ.get(
            "LANGFUSE_COMPLIANCE_HOST",
            os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        ),
    )
```

The docstring in [`metrics.py`](../../src/compliance_bridge/metrics.py) makes the boundary explicit:

> *"Queries the application Langfuse project (LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY) for traces tagged control:<controlId>. [...] The compliance project (LANGFUSE_COMPLIANCE_PUBLIC_KEY / LANGFUSE_COMPLIANCE_SECRET_KEY) is used only by audit_workflow.py."*

### 3.4 Data Flow by Step

The 6-step audit pipeline in [`audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) uses both projects:

| Step | Action                            | Langfuse Project    | Client Factory              |
| ---- | --------------------------------- | ------------------- | --------------------------- |
| 1    | Persist OSCAL YAML to GCS         | Neither             | —                           |
| 2    | Parse OSCAL → `OscalFinding[]`    | Neither             | —                           |
| 2b   | SHA-256 hash-chain accumulator    | Neither             | —                           |
| 3    | Ingest findings as scored traces  | **Compliance**      | `_make_compliance_langfuse()` |
| 3c   | Populate eval dataset (FAIL)      | **Compliance**      | `_make_compliance_langfuse()` |
| 4    | Alert on critical failures        | Neither             | —                           |
| 5    | Fetch failing traces for context  | **Application** (R) | `_make_app_langfuse()`      |
| 5    | Log LLM advisory to compliance    | **Compliance**      | `_make_compliance_langfuse()` |
| 6    | AARM conformance report           | Neither (GCS)       | —                           |

Step 5 is the only cross-project operation: it reads failing traces from the application project to provide evidence context for the LLM remediation advisor, then writes the advisory back to the compliance project. This is an intentional one-way data flow — the compliance bridge acts as a read-only observer of application telemetry and a write-only producer of audit evidence.

---

## 4. Threat Model

### 4.1 Threats Mitigated

| Threat | Vector | Mitigation |
|--------|--------|------------|
| **Audit Evidence Tampering** | Compromised workload pod writes false compliance scores | Workload pod has no `LANGFUSE_COMPLIANCE_*` credentials |
| **Evidence Deletion** | Attacker with `advisor-secrets` access deletes compliance traces | Application project credentials cannot access compliance project |
| **Cross-Contamination** | Application trace volume drowns compliance signals | Separate projects with independent storage, retention, and query scope |
| **Credential Rotation Blast Radius** | Rotating app Langfuse keys disrupts audit pipeline | Compliance credentials are a separate secret object with independent lifecycle |

### 4.2 Threats NOT Mitigated (Known Gaps)

| Gap | Description | Status |
|-----|-------------|--------|
| **Shared Langfuse Host** | Both projects may be hosted on the same Langfuse instance (`LANGFUSE_HOST`). A Langfuse-level compromise affects both projects. | Accepted risk — mitigated by self-hosted Langfuse on GKE with dedicated namespace |
| **Compliance Bridge Compromise** | The compliance bridge pod has credentials for both projects. A full pod compromise gives read access to app telemetry AND write access to compliance evidence. | Mitigated by minimal attack surface (no public endpoint, no user input parsing, CPU/memory-limited), but remains the single point of credential aggregation |
| **Same GCP Project** | Both Langfuse projects currently run within the same GCP project. No GCP-level IAM boundary separates them. | Future: Move compliance Langfuse to a dedicated GCP project with separate IAM policy |

---

## 5. Operational Configuration

### 5.1 Environment Variables

| Variable                            | Required By              | Purpose                                      |
| ----------------------------------- | ------------------------ | -------------------------------------------- |
| `LANGFUSE_PUBLIC_KEY`               | Advisor, Compliance Bridge | Application metrics project — public key      |
| `LANGFUSE_SECRET_KEY`               | Advisor, Compliance Bridge | Application metrics project — secret key      |
| `LANGFUSE_HOST`                     | All                      | Langfuse server URL (shared)                  |
| `LANGFUSE_COMPLIANCE_PUBLIC_KEY`    | Compliance Bridge only   | Compliance audit project — public key         |
| `LANGFUSE_COMPLIANCE_SECRET_KEY`    | Compliance Bridge only   | Compliance audit project — secret key         |
| `LANGFUSE_COMPLIANCE_HOST`          | Compliance Bridge only   | Optional: separate host for compliance project; falls back to `LANGFUSE_HOST` |

### 5.2 Silent Failure Warning (POAM-018 — Open)

> ⚠️ **POAM-018 (AU-9) — Open:** If `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` are not set, the compliance project client initializes with empty credentials. Langfuse SDK calls will fail silently (no exception raised — the SDK logs a warning and drops the trace). This means **audit evidence collection fails without any visible error** unless Langfuse SDK logs are monitored.
>
> **Remediation (scheduled 2026-07-15):** Add startup validation in `audit_workflow.py` that raises `RuntimeError` if compliance credentials are empty in non-dev environments; add `/health` check that reports compliance Langfuse connectivity status. See [`docs/POAM.md` POAM-018](../compliance/cross-region/POAM.md).

This is documented as a known gap in [NIST_RMF_CHUNK4](../compliance/us_fed/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md):

> *"Compliance Langfuse project is a separate credential from the main project. `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` must be configured. If these env vars are absent, the compliance project fails silently — a critical evidence collection gap."*

### 5.3 Verification

To verify the dual-project isolation is correctly configured:

```bash
# 1. Check that both secret objects exist in the cluster
kubectl get secret advisor-secrets -n governance-stack
kubectl get secret langfuse-compliance-secrets -n governance-stack

# 2. Verify the compliance bridge pod has both sets of credentials
kubectl exec -n governance-stack deploy/compliance-bridge -- env | grep LANGFUSE

# Expected output should include ALL of:
#   LANGFUSE_PUBLIC_KEY=pk-lf-...
#   LANGFUSE_SECRET_KEY=sk-lf-...
#   LANGFUSE_COMPLIANCE_PUBLIC_KEY=pk-lf-...  (DIFFERENT key)
#   LANGFUSE_COMPLIANCE_SECRET_KEY=sk-lf-...  (DIFFERENT key)

# 3. Verify the advisor pod does NOT have compliance credentials
kubectl exec -n governance-stack deploy/governed-financial-advisor -- env | grep COMPLIANCE
# Expected: no output (compliance credentials not mounted)
```

---

## 5.4 Terraform Fallback Warning (POAM-019 — Open)

> ⚠️ **POAM-019 (AU-9, SC-7) — Open:** `infra/targets/gcp-gke/main.tf` contains a fallback that silently collapses dual-project telemetry isolation when `langfuse_compliance_public_key` / `langfuse_compliance_secret_key` Terraform variables are empty — it falls back to application project credentials. This silently defeats the evidentiary independence design.
>
> **Impact:** If `prod.tfvars` does not define compliance credentials (which it currently does not by default), production deployment has no telemetry isolation — all audit evidence flows to the same Langfuse project as application metrics.
>
> **Remediation (scheduled 2026-07-15):** Remove the Terraform fallback; make compliance credentials a required variable with no default; add compliance credentials to `prod.tfvars` template; add a Terraform `validation` block requiring non-empty compliance keys when `enable_compliance_bridge = true`. See [`docs/POAM.md` POAM-019](../compliance/cross-region/POAM.md).

---

## 6. Future: Full GCP Project Separation

The current architecture uses two Langfuse *projects* within a single GCP project. The target architecture separates at the GCP project level:

| Component                     | Current                              | Target                                        |
| ----------------------------- | ------------------------------------ | --------------------------------------------- |
| **Workload GCP Project**      | Single project (e.g., `cage-prod`)   | `cage-prod` — workloads + application Langfuse |
| **Compliance GCP Project**    | Same project                         | `cage-compliance` — compliance Langfuse + GCS audit evidence + Cloud Audit Logs |
| **IAM Boundary**              | Shared IAM policy                    | Separate IAM — `cage-prod` SA cannot access `cage-compliance` resources |
| **VPC Peering**               | N/A (same project)                   | VPC peering or Private Service Connect for compliance bridge → compliance Langfuse |
| **Cloud Audit Logs**          | Shared                               | Independent — compliance project logs are immutable to `cage-prod` administrators |

This would be a Terraform infrastructure change, not a code change. The Python client factories, K8s secret structure, and data flow already support this topology — only the Langfuse host URLs and IAM bindings need to change.

---

## Related Documentation

| Document                                                                  | Relationship                                           |
| ------------------------------------------------------------------------- | ------------------------------------------------------ |
| [02-ARCHITECTURE.md §9.2](../technical-report/02-ARCHITECTURE.md)         | Brief mention of dual-project setup                    |
| [NIST_RMF_CHUNK4](../compliance/us_fed/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md)                | Documents the silent failure gap                       |
| [EXTENSIBILITY_ARCHITECTURE.md §2.4](EXTENSIBILITY_ARCHITECTURE.md)      | References telemetry isolation as implementation requirement |
| [infra/ENV_INTEGRATION.md](../../infra/ENV_INTEGRATION.md)                | Credential mapping for both projects                   |
| [compliance-bridge.yaml](../../deployment/k8s/compliance-bridge.yaml)     | K8s deployment with dual secret mounts                 |
| [app_secrets/main.tf](../../infra/modules/app_secrets/main.tf)            | Terraform provisioning of separate K8s secrets         |
| [docs/POAM.md POAM-018](../compliance/cross-region/POAM.md)                                       | Silent credential failure — open remediation item      |
| [docs/POAM.md POAM-019](../compliance/cross-region/POAM.md)                                       | Terraform fallback defeats isolation — open remediation item |
