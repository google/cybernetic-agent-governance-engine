# 07 — Security Infrastructure

| Field              | Value                                           |
| ------------------ | ----------------------------------------------- |
| **Version**        | 2.0                                                             |
| **Date**           | 2026-06-01                                                      |
| **Classification** | INTERNAL                                        |
| **Document**       | CAGE Technical Report — Security Infrastructure |

---

## 1. Security Architecture Overview

CAGE implements a defense-in-depth security model across seven distinct layers. The architecture assumes zero inherent trust between components and enforces explicit allow decisions at every boundary.

| Layer                   | Mechanism                            | Implementation                               |
| ----------------------- | ------------------------------------ | -------------------------------------------- |
| Cryptographic Integrity   | Cloud KMS HSM (primary) + HMAC-SHA256 (fallback) | KMS RSA-4096 governance signing + HMAC routing seal |
| Policy Authorization      | OPA Rego RBAC                        | `trade.governance` package, fail-closed      |
| Network Isolation         | Kubernetes NetworkPolicy             | 9 objects, default-deny ingress/egress       |
| External Normative Gate   | Adaptive FRIA enforcement (v2.1.0)   | `normative_provider.py`: confidence-mapped sync/async external validation (SA-9) |
| PII Protection            | NeMo Guardrails + Microsoft Presidio | Input/output scanning + anonymization        |
| Audit Logging             | OpenTelemetry + Langfuse             | 7-year retention, ISO 42001 control stamping; direct OTLP ingestion (OTel Collector deprecated 2026-05-31) |
| Continuous Monitoring     | AgentSight eBPF DaemonSet            | Kernel-level process audit trail             |

> ⚠️ **Current Security Posture: HIGH Overall Risk — ATO Not Recommended**
>
> One **critical** open finding remains unresolved: unsigned FIPS 199 categorization (FIND-007). Two critical findings have been resolved: HMAC bypass vulnerability FIND-010 / POAM-012 is **CLOSED**, and intra-cluster mTLS FIND-011 / POAM-007 is **CLOSED** (Linkerd mTLS + Cilium L7 egress lockdown deployed).

---

## 2. Authorization Boundary

**Kubernetes Namespace**: `governance-stack` on Google Kubernetes Engine (GKE)

Source: [`compliance/boundary/AUTHORIZATION_BOUNDARY.md`](../../compliance/boundary/AUTHORIZATION_BOUNDARY.md)

### Network Policy Objects (9 Total)

All network policy manifests are defined in:

- [`deployment/k8s/network-policy.yaml`](../../deployment/k8s/network-policy.yaml) — baseline default-deny rules
- [`deployment/k8s/network-policy-hardening.yaml`](../../deployment/k8s/network-policy-hardening.yaml) — hardened explicit allow rules
- [`deployment/k8s/pod-security-admission.yaml`](../../deployment/k8s/pod-security-admission.yaml) — restricted pod security profile
- [`deployment/k8s/security-context-patch.yaml`](../../deployment/k8s/security-context-patch.yaml) — runtime security context

Explicit allow rules cover: agent server → gateway, gateway → OPA, gateway → Redis, gateway → vLLM, and compliance bridge → Langfuse.

### External Interconnections

| External System     | Purpose                           | ISA Status                             |
| ------------------- | --------------------------------- | -------------------------------------- |
| GCS Artifact Bucket | OSCAL results; model artifacts    | GCP ToS                                |
| MinIO               | Model weight storage              | Internal cluster service               |
| Langfuse SaaS       | Observability; compliance metrics | ISA — DPA risk (Langfuse DPA required) |
| yfinance            | Market data                       | **Yes** — read-only API; ISA required for data correlation risk |

> **ADR**: GCP Secret Manager was removed as an external interconnection.
> Secrets are now provided exclusively via Kubernetes `Secret` objects mounted
> as environment variables. No runtime dependency on `google-cloud-secret-manager`.

> ⚠️ **Langfuse DPA Risk**: Langfuse SaaS processes compliance metrics and agent traces. A Data Processing Agreement (DPA) is required before production use. This represents a residual ISA risk until the DPA is executed.

---

## 3. Authentication & Authorization

### HMAC-SHA256 Routing Seal

Every `POST /tools/execute` call is protected by the `X-CAGE-Routing-Seal` request header:

- **Algorithm**: HMAC-SHA256 of the full request body bytes
- **Secret**: `CAGE_ROUTING_SEAL_SECRET` environment variable
- **Enforcement**: [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py)
- **Behavior**: Fail-closed — returns HTTP 401 on missing or invalid seal

> ✅ **FIND-010 / POAM-012: RESOLVED** — The HMAC bypass vulnerability that allowed unsigned requests to reach governed endpoints has been patched. This critical finding is closed.

### HMAC-SHA256 Governance State Signature

A second HMAC-SHA256 layer protects agent state transitions within the LangGraph pipeline:

- **Scope**: Applied over `execution_plan_output` content in `AgentState`
- **Flow**: Evaluator agent signs → stored as `governance_signature` in state → [`check_safety_signature(state)`](../../src/governed_financial_advisor/graph/nodes/safety_node.py) validates in `safety_node` before `governed_trader` executes
- **Purpose**: Prevents state tampering between evaluator and trader graph nodes

### OPA Rego RBAC (`trade.governance` Package)

Policy files:

- [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](../../src/governed_financial_advisor/governance/policy/trade_governance.rego)
- [`deployment/system_authz.rego`](../../deployment/system_authz.rego)

| Role     | Trade Limit      | Behavior            |
| -------- | ---------------- | ------------------- |
| `junior` | ≤ $5,000         | Allow               |
| `junior` | $5,001 – $10,000 | Escalate for review |
| `senior` | ≤ $500,000       | Allow               |
| Any      | Above role limit | **DENY**            |

- Default policy: **DENY** (fail-closed)
- Confidence gate: `confidence_sufficient ≥ 0.95` enforced via `deployment/system_authz.rego`

### Authentication Gaps (Open Findings)

| Finding                                           | Area                     | Status |
| ------------------------------------------------- | ------------------------ | ------ |
| No MFA implemented                                | IA family (15% coverage) | Open   |
| FIND-001: No formal account management procedures | IA                       | Open   |
| FIND-012: No automated secret rotation schedule   | IA                       | Open   |

---

## 4. Network Security

### Kubernetes NetworkPolicy Enforcement

The `governance-stack` namespace enforces default-deny for all ingress and egress traffic. Explicit allow rules are defined per-service pair. Pod security admission applies the `restricted` profile, enforcing non-root execution, read-only root filesystem, and dropped capabilities.

**Ingress controller**: [`deployment/k8s/ingress.yaml`](../../deployment/k8s/ingress.yaml)

### Kubernetes Inference Gateway (ADR-002)

CAGE migrates from GKE GCE GatewayClass to nginx-based Kubernetes Inference Gateway:

| Manifest                                                                                                               | Purpose                                 |
| ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| [`deployment/k8s/inference-gateway/gateway.yaml`](../../deployment/k8s/inference-gateway/gateway.yaml)                 | Gateway definition (nginx GatewayClass) |
| [`deployment/k8s/inference-gateway/http-route.yaml`](../../deployment/k8s/inference-gateway/http-route.yaml)           | HTTP routing rules                      |
| [`deployment/k8s/inference-gateway/inference-pool.yaml`](../../deployment/k8s/inference-gateway/inference-pool.yaml)   | vLLM backend pool                       |
| [`deployment/k8s/inference-gateway/reference-grant.yaml`](../../deployment/k8s/inference-gateway/reference-grant.yaml) | Cross-namespace reference grant         |

### Zero-Trust Network Hardening (Z3N)

CAGE defines a **Zero-Trust Network (Z3N)** architecture combining two complementary network enforcement layers:

#### Layer 1 — Linkerd mTLS (Intra-Cluster Encryption)

Source: [`deployment/k8s/linkerd-mtls-policy.yaml`](../../deployment/k8s/linkerd-mtls-policy.yaml)

Linkerd proxy injection encrypts all service-to-service traffic within the `governance-stack` namespace using mutual TLS. Certificates are automatically rotated every 24 hours by the Linkerd control plane.

| Resource Type | Purpose | Manifest Section |
| ------------- | ------- | ---------------- |
| `Server` (policy.linkerd.io/v1beta2) | Declares OPA (port 8181), NeMo (port 8000), and vLLM (port 8000) as named server resources | Lines 130–180 |
| `AuthorizationPolicy` | Fine-grained service-to-service allow rules (e.g., gateway → OPA, gateway → NeMo) | Lines 180–250 |
| `MeshTLSAuthentication` | Requires valid Linkerd mesh identity for all inbound connections | Lines 250+ |

Identity format: `<serviceaccount>.<namespace>.serviceaccount.identity.linkerd.cluster.local`

Verification: `linkerd viz authz deployment/opa-service -n governance-stack`

#### Layer 2 — Cilium L7 Egress Lockdown (Outbound FQDN Filtering)

Source: [`deployment/k8s/cilium-egress-lockdown.yaml`](../../deployment/k8s/cilium-egress-lockdown.yaml)

Three `CiliumNetworkPolicy` resources extend the standard L3/L4 NetworkPolicies with L7 DNS-aware filtering:

| Policy | Target | Allowed FQDNs | Purpose |
| ------ | ------ | -------------- | ------- |
| `cage-egress-inference` | `role: inference-node` | `generativelanguage.googleapis.com`, `oauth2.googleapis.com` | LLM API access only |
| `cage-egress-sovereign-agent` | `role: sovereign-agent` | `query1.finance.yahoo.com`, `storage.googleapis.com`, `generativelanguage.googleapis.com` | Market data + cloud storage + LLM |
| `cage-default-deny-egress` | All pods | None | Cilium-layer default-deny for all non-allowlisted external egress |

**Full approved FQDN egress allowlist** (all roles combined):

| FQDN | Purpose |
| ---- | ------- |
| `api.openai.com` | OpenAI-compatible API (external LLM fallback) |
| `api.anthropic.com` | Anthropic Claude API (external LLM fallback) |
| `generativelanguage.googleapis.com` | Google Gemini / Vertex AI |
| `*.googleapis.com` | GCS, Cloud KMS, Cloud Audit Logs, Workload Identity |
| `metadata.google.internal` | GKE Workload Identity metadata server |
| `us.i.posthog.com` | Product analytics (Langfuse telemetry) |
| `cloud.langfuse.com` | Langfuse SaaS OTLP ingestion |
| `api.trade.gov` | OFAC sanctions screening |
| `www.treasury.gov` | OFAC SDN list reference |

Cilium's DNS proxy intercepts all UDP/53 responses and dynamically populates FQDN-based IP sets, ensuring that sovereign agent pods cannot exfiltrate data to arbitrary external endpoints.

Verification: `cilium monitor --type l7 --from-label role=sovereign-agent`

#### ✅ Deployment Status (FIND-011 / POAM-007 — RESOLVED)

> **Z3N manifests are deployed and verified.** Linkerd mTLS proxy injection is active in the `governance-stack` namespace, enforcing SPIFFE/SVID identity for Gateway→OPA and Gateway→NeMo paths. Cilium L7 egress lockdown prevents lateral movement to unauthorized external endpoints. POAM-007 closed 2026-05-17.
>
> Verification: `linkerd viz authz deployment/opa-service -n governance-stack`

- **Residual Risk**: NONE (formerly PR-6 MODERATE)
- **FIPS Impact**: Resolved — all intra-cluster traffic is now mTLS-encrypted

---

## 5. Secret Management

Source: [`docs/SECRET_MANAGEMENT_OPTIONS.md`](../SECRET_MANAGEMENT_OPTIONS.md)

### Current Kubernetes Secrets (3 Objects in `governance-stack`)

| Secret Name              | Contents                                       |
| ------------------------ | ---------------------------------------------- |
| `oscal-artifact-secrets` | GCS credentials for OSCAL artifact storage     |
| `advisor-secrets`        | LLM API keys; governance salt; Langfuse tokens |
| `minio-credentials`      | MinIO access key and secret key                |

### Current Approach — Kubernetes-native Secret Injection

> **ADR**: Google Secret Manager was removed in favour of Kubernetes-native
> secret injection (env vars from `Secret` objects). No runtime dependency on
> `google-cloud-secret-manager`.

- Secrets are stored as `kubernetes_secret` resources provisioned by Terraform
  (see [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf))
- Pods consume secrets via `envFrom` / `secretRef` — values are standard
  environment variables inside containers
- Rotation: update the Kubernetes `Secret` object and trigger a rolling restart

### Alternative Approaches (for future consideration)

| Option   | Approach                                         | Note                                              |
| -------- | ------------------------------------------------ | ------------------------------------------------- |
| Option A | External Secrets Operator (ESO) with any backend | Cloud-portable; Vault, AWS SM, Azure KV supported |
| Option C | CI pipeline injection at deployment time         | Fallback; manual `kubectl create secret` commands          |

### Terraform IAM Configuration

- [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf) — least-privilege service account IAM bindings
- [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf) — base IAM configuration
- [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf) — GKE Workload Identity and shielded node configuration

> ⚠️ **FIND-012 (Open)**: No automated secret rotation schedule is defined or enforced. Manual rotation is the current practice.

---

## 6. PII & Privacy Protection

### Unified PII Protection Architecture

```
User Input
    │
    ▼
NeMo Guardrails (Input Scan)
    │  Blocks PII before reaching LLM using in-process Presidio
    │
    ▼
LLM Inference
    │
    ▼
NeMo Guardrails (Output Rail)
    │  Masks PII in LLM responses using in-process Presidio
    │
    ▼
Sanitized Output
    │
    ▼
OTel Telemetry Export
    │  Inference Proxy applies `scrub_pii` regex for span redaction
```

### Layer 1 — NeMo Guardrails with In-Process Presidio

- Configuration: [`config/rails/config.yml`](../../config/rails/config.yml) — 15 Presidio PII entity types configured
- Microsoft Presidio is executed **in-process** as a custom action within NeMo Guardrails, scanning for 15 entity types (names, SSNs, account numbers, addresses, etc.) at `score_threshold = 0.3`.
- Input scan (`nemo_input_scan`): blocks PII-containing prompts before LLM inference
- Output rail (`nemo_output_rail`): masks PII in LLM responses
- ISO 42001 mapping: A.9.2 (data minimization) and A.5.2 (privacy by design)
- Implementation: [`src/governed_financial_advisor/utils/privacy.py`](../../src/governed_financial_advisor/utils/privacy.py)

### Layer 2 — Telemetry Redaction

- The Inference Proxy uses a lightweight `scrub_pii` (regex-based) utility strictly to redact telemetry span attributes before export to observability backends.

### Privacy Data Retention Schedule

| Data Type                      | Retention Period | Regulatory Authority            |
| ------------------------------ | ---------------- | ------------------------------- |
| Audit logs                     | 7 years          | FINRA Rule 4511, SEC Rule 17a-4 |
| AI interaction logs (raw)      | 90 days          | Internal policy                 |
| AI interaction logs (redacted) | 7 years          | Internal policy                 |
| PII in session                 | 24 hours         | SEC Reg S-P                     |
| Session tokens                 | ≤ 8 hours        | Internal policy                 |

---

## 7. Audit Logging Architecture

### OpenTelemetry Pipeline

- Auto-instrumentation: `FastAPIInstrumentor` (gateway API) + `LangchainInstrumentor` (agent graph)
- **Collector:** Langfuse integrated OTLP ingestion (standalone `opentelemetry-collector-contrib` deprecated 2026-05-31)
- Sampling strategy: 1% general traffic (RA-001 requirement); 100% governance decision spans
- Export: OTLP/HTTP → Langfuse integrated collector endpoint

### ISO 42001 Control Stamping

Every governance span receives 6 OpenTelemetry attributes applied by [`src/gateway/governance/iso_control.py:stamp_iso_control()`](../../src/gateway/governance/iso_control.py):

| OTel Attribute             | Purpose                                   |
| -------------------------- | ----------------------------------------- |
| `iso42001.control`         | Control identifier (e.g., A.6.1.3)        |
| `iso42001.tier`            | Risk tier classification                  |
| `iso42001.outcome`         | Pass / Fail / Escalate                    |
| `iso42001.timestamp`       | UTC timestamp of control evaluation       |
| `iso42001.gateway_version` | Gateway version that enforced the control |
| `iso42001.evidence_chain`  | Hash chain linking prior evidence spans   |

### Langfuse Dual-Project Setup

| Project                 | Data Captured                                          |
| ----------------------- | ------------------------------------------------------ |
| Project 1 — Application | Agent traces, latency, token usage, quality metrics    |
| Project 2 — Compliance  | Control pass/fail rates, evidence age, OSCAL alignment |

- Cache: `TTLCache(maxsize=32, ttl=300)` — 5-minute cache per compliance metric to reduce Langfuse API load

> ⚠️ **FIND-003 / POAM-003 (High, Open)**: The `EvaluatorAuditor` component partially uses mock trace data instead of real audit events. This means audit evidence for evaluator decisions is not fully trustworthy. Remediation requires replacing mock data sources with genuine telemetry instrumentation.

---

## 8. AgentSight eBPF Monitoring

Source: [`deployment/agentsight/agentsight-config.yaml`](../../deployment/agentsight/agentsight-config.yaml), [`deployment/agentsight/README.md`](../../deployment/agentsight/README.md)

### DaemonSet Deployment

Manifest: [`deployment/k8s/agentsight-daemon.yaml`](../../deployment/k8s/agentsight-daemon.yaml)

- **Scope**: Runs on every GKE node as a DaemonSet (kernel-privileged)
- **Target**: `python3` processes specifically (narrows to CAGE application processes)
- **Intercepts**:
  - OpenSSL uprobes — captures TLS handshake metadata
  - Syscall events — file I/O operations and network calls
- **Output**: Kernel-level audit trail of all process activity within the node

### ✅ Gap G7.1-2 (RESOLVED)

The eBPF exporter has been updated to `remote` output mode:

- Exporter type: `"remote"` (targeting `http://agentsight-dashboard:8080`)
- eBPF findings are now exported to the AgentSight dashboard backend for centralized collection
- **Previous gap**: Console-only output meant no centralized storage or alerting

---

## 8a. Vendor Integration Security (`src/integrations/`)

> **Status:** Implemented in v2.1.0. See [`EXTENSIBILITY_ARCHITECTURE.md §2.6`](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md).

All third-party compliance and attestation provider adapters are isolated under `src/integrations/{vendor}/`. This boundary prevents vendor SDK code from leaking into the governance kernel or gateway packages, limiting the blast radius of any vendor-side vulnerability.

| Vendor        | Module                                    | Role                                                                 | Security Boundary                                      |
| ------------- | ----------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------ |
| TrustLayers   | `src/integrations/trustlayers/provider.py` | Normative legal-baseline provider (Tier 6b FRIA gate)               | Isolated package; lazy-loaded only when `TRUSTLAYERS_API_KEY` is set |
| NexArt        | `src/integrations/nexart/provider.py`      | CER (Compliance Evidence Record) attestation provider                | Isolated package; lazy-loaded only when `NEXART_API_KEY` is set |

**Key security properties:**
- Vendor SDKs are **not imported at module load time** — the provider factory in `src/integrations/__init__.py` uses lazy imports, so a missing or misconfigured vendor credential does not crash the gateway.
- Each vendor directory has its own test suite (`src/integrations/{vendor}/tests/`) to prevent regressions from vendor SDK updates.
- Cloud KMS (`kms_signer.py`) and Redis (`evidence_stream.py`) are **not** vendor adapters — they are substrate infrastructure invariants and remain in `src/gateway/governance/`.

> ⚠️ **POAM-018 (Open):** TrustLayers credentials (`LANGFUSE_COMPLIANCE_*`) fail silently when absent. See [`DUAL_PROJECT_ARCHITECTURE.md §5.2`](../../docs/architecture/DUAL_PROJECT_ARCHITECTURE.md) for remediation details.

---

## 9. Cryptographic Controls

| Mechanism               | Algorithm                  | Usage                            | FIPS Status              | Gaps                             |
| ----------------------- | -------------------------- | -------------------------------- | ------------------------ | -------------------------------- |
| **KMS Governance Signing** | RSA-PKCS1-4096-SHA256 (HSM) | **Primary** — all governance decisions; non-repudiation | ✅ FIPS-approved | Production only; HMAC fallback for dev/CI |
| Routing Seal            | HMAC-SHA256                | Every `POST /tools/execute` call | ✅ FIPS-approved         | Fallback only when KMS unavailable |
| Governance Signature    | HMAC-SHA256                | Agent state transitions          | ✅ FIPS-approved         | None — fully implemented         |
| TLS (external)          | TLS 1.2+                   | External service connections     | ✅ FIPS-compliant        | No intra-cluster equivalent      |
| Intra-cluster transport | **Linkerd mTLS**           | Service-to-service               | ✅ FIPS-compliant        | **FIND-011 RESOLVED** — Linkerd mTLS |
| Context Evidence Chain  | SHA-256 Hash Chain         | OscalFindings integrity tracking | ✅ FIPS-approved         | None — fully implemented         |
| Session token expiry    | N/A (expiry policy)        | Session tokens ≤ 8h              | N/A                      | No rotation schedule (FIND-012)  |

**FIPS 140-2/3 Assessment**: HMAC-SHA256 is a FIPS-approved algorithm. Intra-cluster mTLS is now enforced via Linkerd (FIND-011 resolved), satisfying FIPS transport requirements for all service-to-service communication within the `governance-stack` namespace.

### 9.1 Cryptographic Context Accumulator (AARM-V1)

CAGE v2.0.0 introduces a **Cryptographic Context Accumulator** (`src/compliance_bridge/context_accumulator.py`) to seal audit evidence against retroactive tampering or Memory Poisoning attempts. 
*   **SHA-256 Hash-Chaining:** Every emitted `OscalFinding` is chained cryptographically to its predecessor. The `record_hash` for finding $n$ is calculated as `SHA-256(prev_hash || content_json)`.
*   **Seal Sentinel:** Each audit execution is capped by a `CHAIN_SEALED` sentinel payload. The compliance API validates `chain_root`, `chain_length`, and `chain_integrity_valid` on all reads, satisfying **ISO 42001 Annex A.5.3** evidence logging controls.

---

### 9.2 CVE-2025-69872 Remediation (`outlines` Package Removal)

The `outlines` Python package was removed from all CAGE container images following the discovery of **CVE-2025-69872** (critical severity). This remediation satisfies **NIST SP 800-53 SI-2 (Flaw Remediation)** and is validated by the `compliance/lula/lula-validation-si2.yaml` Lula manifest.

| Attribute | Value |
| --------- | ----- |
| **CVE** | CVE-2025-69872 |
| **Severity** | Critical |
| **Affected Package** | `outlines` (structured output library) |
| **Remediation** | Package removed from all images; vLLM FSM guided decoding used for `ExecutionPlan` schema compliance |
| **NIST Control** | SI-2 (Flaw Remediation) |
| **Status** | **RESOLVED** |

---

## 10. Red Team & Adversarial Testing

Source: [`tests/red_team/`](../../tests/red_team/), [`src/governed_financial_advisor/agents/evaluator/red_agent.py`](../../src/governed_financial_advisor/agents/evaluator/red_agent.py)

### Adversarial Test Coverage

| Component                                                                                                                            | Description                                              |
| ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| [`tests/red_team/adversarial_dataset.json`](../../tests/red_team/adversarial_dataset.json)                                           | 290+ adversarial payloads across attack categories       |
| [`src/governed_financial_advisor/agents/evaluator/red_agent.py`](../../src/governed_financial_advisor/agents/evaluator/red_agent.py) | Adversarial harness running the full governance pipeline |
| [`tests/red_teaming/test_adversarial.py`](../../tests/red_teaming/test_adversarial.py)                                               | Automated adversarial test suite (CI-integrated)         |
| [`tests/red_team/run_red_team.py`](../../tests/red_team/run_red_team.py)                                                             | Full red team execution script                           |

### Attack Categories Covered

- **Prompt injection** — attempts to override system instructions via user input
- **Policy bypass** — semantic tricks to circumvent OPA authorization decisions
- **PII extraction** — attempts to elicit protected personal information from LLM responses
- **Semantic override** — rephrasing to bypass NeMo Guardrails entity detection
- **HMAC forgery attempts** — invalid seal construction to test routing seal enforcement

### Governance Policy Regression Testing

| Test Artifact                                                                                          | Purpose                                               |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| [`tests/opa_snapshots/01_no_identity_match.json`](../../tests/opa_snapshots/01_no_identity_match.json) | Validates OPA DENY on unrecognized identity           |
| [`tests/opa_snapshots/02_trade_no_auth.json`](../../tests/opa_snapshots/02_trade_no_auth.json)         | Validates OPA DENY on unauthorized trade request      |
| [`scripts/canary_opa_policy.sh`](../../scripts/canary_opa_policy.sh)                                   | Canary check for policy regression across deployments |

---

## 11. Security Assessment Findings Summary

Sources: [`compliance/sar/SAR_2026Q1.md`](../../compliance/sar/SAR_2026Q1.md), [`docs/SECURITY_ASSESSMENT_PLAN.md`](../SECURITY_ASSESSMENT_PLAN.md), [`docs/POAM.md`](../POAM.md)

> ⚠️ **Overall Assessment: HIGH Risk — ATO Not Recommended**

| Finding ID                                      | Severity     | Security Area     | Status                            |
| ----------------------------------------------- | ------------ | ----------------- | --------------------------------- |
| FIND-010: HMAC routing seal bypass              | **Critical** | Cryptography      | ✅ **RESOLVED (POAM-012 Closed)** |
| FIND-011: No intra-cluster mTLS                 | **Critical** | Network           | ✅ **RESOLVED (POAM-007 Closed)** |
| FIND-007: FIPS 199 unsigned                     | **Critical** | Compliance        | 🔄 In-Progress                    |
| FIND-001: No account management procedures      | High         | Identity & Access | ❌ Open                           |
| FIND-003: Mock audit traces in EvaluatorAuditor | High         | Audit             | ❌ Open                           |
| FIND-008: No vulnerability scanning            | High         | Risk Assessment   | ✅ **RESOLVED (POAM-010 Closed)** |
| FIND-006: No Incident Response Plan             | High         | Incident Response | ❌ Open                           |
| FIND-012: No automated secret rotation          | Medium       | Identity & Access | ❌ Open                           |

### Supporting Security Documents

| Document                                                               | Purpose                            |
| ---------------------------------------------------------------------- | ---------------------------------- |
| [`docs/SECURITY_ASSESSMENT_PLAN.md`](../SECURITY_ASSESSMENT_PLAN.md)   | Security Assessment Plan (SAP)     |
| [`docs/IR_PLAN.md`](../IR_PLAN.md)                                     | Incident Response Plan (draft)     |
| [`docs/CHANGE_MANAGEMENT_PROCESS.md`](../CHANGE_MANAGEMENT_PROCESS.md) | Change Management Process          |
| [`compliance/sar/SAR_2026Q1.md`](../../compliance/sar/SAR_2026Q1.md)   | Security Assessment Report Q1 2026 |

---

## 12. Terraform Security Configuration

Source: [`infra/README.md`](../../infra/README.md)

CAGE infrastructure is provisioned via Terraform with security controls encoded as IaC:

| Terraform File                                                                                     | Security Relevance                                                   |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf) | Least-privilege IAM bindings for all service accounts                |
| [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf)                                 | Base IAM configuration and role assignments                          |
| [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf)                         | Kubernetes Secret resource provisioning (GSM removed)                |
| [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf)                                 | GKE cluster: Workload Identity, shielded nodes, binary authorization |
| [`infra/modules/gcp_gke_cluster/networking.tf`](../../infra/modules/gcp_gke_cluster/networking.tf)                   | VPC configuration and firewall rules                                 |
| [`infra/modules/agentsight_ui/main.tf`](../../infra/modules/agentsight_ui/main.tf)                   | AgentSight eBPF monitoring deployment                                |

**Key security principles enforced in Terraform**:

- Workload Identity Federation — eliminates static service account key files
- Shielded GKE nodes — Secure Boot, vTPM, Integrity Monitoring enabled
- VPC-native cluster networking — no legacy routes
- Least-privilege IAM — each service account bound to minimum required roles

---

_End of Document — CAGE Technical Report: Security Infrastructure_
