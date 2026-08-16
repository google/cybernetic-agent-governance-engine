# Governance Crosswalk: Mapping Law to Logic

This document serves as the formal **Governance Crosswalk**, mapping high-level regulatory controls (ISO 42001, NIST RMF) to specific engineering artifacts (STPA Constraints, NeMo Rails, Rego Policies) within the Cybernetic Governance Engine, and to the **Lula validation manifests** that automatically verify compliance.

## Jurisdiction Separation Principle

**ISO/IEC 42001:2023 is the sole universal governance baseline.** Every control, pipeline step, and audit artifact in this document that is marked *All regions* applies to every deployment regardless of geography. All other regulatory frameworks are **additive, jurisdiction-specific layers** that are activated exclusively by the `CAGE_DEPLOYMENT_REGION` environment variable and impose no obligations on other regions.

```
┌─────────────────────────────────────────────────────────────────────┐
│  UNIVERSAL BASELINE (all regions: US_FED, EU_ECB, APAC_MAS)        │
│  • ISO/IEC 42001:2023   • CSA AARM v1.0   • FIPS 140-2/3           │
├──────────────────┬──────────────────────┬───────────────────────────┤
│  US_FED addendum │  EU_ECB addendum     │  APAC_MAS addendum        │
│  SR 26-2         │  EU AI Act 2024/1689 │  MAS FEAT Principles      │
│  NIST AI 600-1   │  GDPR Art. 22        │  MAS Notice 655           │
│  NIST SP 800-53  │  DORA 2022/2554      │  MAS TRM §4.2             │
│  NIST RMF        │                      │                           │
└──────────────────┴──────────────────────┴───────────────────────────┘
```

## Regional Applicability

Different regulatory frameworks apply to different deployment regions. The table below clarifies which frameworks are universal vs. region-specific:

| Framework | Regional Applicability | Deployment Region(s) |
| :-------- | :--------------------- | :------------------- |
| **ISO/IEC 42001:2023** | **Universal baseline** | `US_FED`, `EU_ECB`, `APAC_MAS` |
| **CSA AARM v1.0** | **Universal baseline** | `US_FED`, `EU_ECB`, `APAC_MAS` |
| **FIPS 140-2/3** | **Universal baseline** | `US_FED`, `EU_ECB`, `APAC_MAS` |
| **SR 26-2** (Federal Reserve, April 17, 2026) | **US_FED only** | `US_FED` |
| **NIST AI 600-1** | **US_FED only** | `US_FED` |
| **NIST SP 800-53 Rev 5** | **US_FED only** | `US_FED` |
| **NIST RMF (SP 800-37)** | **US_FED only** | `US_FED` |
| **EU AI Act** (Reg. 2024/1689) | **EU_ECB only** | `EU_ECB` |
| **DORA** (Reg. 2022/2554) | **EU_ECB only** | `EU_ECB` |
| **GDPR Article 22** | **EU_ECB only** | `EU_ECB` |
| **MAS FEAT Principles** | **APAC_MAS only** | `APAC_MAS` |
| **MAS Notice 655 / MAS TRM** | **APAC_MAS only** | `APAC_MAS` |

> **Note:** NIST SP 800-53 controls referenced in the crosswalk table below (e.g., `NIST Manage 2.4`, `NIST Map 1.5`) apply **only when `CAGE_DEPLOYMENT_REGION=US_FED`**. For `EU_ECB` deployments, equivalent obligations are satisfied via ISO 42001 and EU AI Act controls. For `APAC_MAS` deployments, equivalent obligations are satisfied via ISO 42001 and MAS FEAT controls. No US_FED, EU_ECB, or APAC_MAS obligation is imposed on deployments in other regions.

## The Crosswalk Table

| Governance Requirement (Source)            | Risk Category (NIST RMF)      | System Constraint (STPA)                                                       | Technical Implementation (Enforcement)                                                                                                                                                                                                        | Lula Validation                                                                                                          | OSCAL Evidence                                | Regional Applicability |
| :----------------------------------------- | :---------------------------- | :----------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------- | :-------------------- |
| **ISO A.5.2**: Social impact assessment.   | Map 1.1: Contextual analysis. | **SC-1**: Agent must not output content classified as 'Hate Speech' or 'Bias'. | **NeMo Output Rail** + **Aho-Corasick Tier-1** in [`text_filter.py`](../../../src/gateway/governance/text_filter.py) (**v3.0.0:** `safety.py` removed)                                                                                              | [`lula-validation-a52.yaml`](../../../compliance/lula/lula-validation-a52.yaml) — `safety_rate ≥ 99%`                          | OSCAL Finding, Langfuse compliance project    | **All regions** |
| **ISO A.9.2**: Data transfer to suppliers. | Govern 2.1: Data privacy.     | **SC-2**: Agent must not send PII to external Model APIs.                      | **NeMo Input Rail**: `presidio-anonymization` (in-process within NeMo); tagged `iso42001.control_id=A.9.2`                                                                                                                                    | [`lula-validation-a92.yaml`](../../../compliance/lula/lula-validation-a92.yaml) — `safety_rate = 100%` (zero tolerance)        | OSCAL Finding → Slack/PagerDuty alert on FAIL | **All regions** |
| **NIST Manage 2.4**: System security.      | Manage 2.4: Integrity.        | **SC-3**: Agent must not execute 'DROP' or 'DELETE' SQL commands.              | **OPA Policy (Rego)**: `deny { input.sql matches "DROP" }` (Generated by Transpiler).                                                                                                                                                         | —                                                                                                                        | —                                             | **US_FED only** |
| **Corporate Policy 1.4**: Fiscal limits.   | Govern 4.1: Risk tolerance.   | **SC-4**: Financial transfers > $10k require human approval.                   | **Safety Node + OPA**: [`trade_governance.rego`](../../../src/governed_financial_advisor/governance/policy/trade_governance.rego) `MANUAL_REVIEW` rule                                                                                              | [`lula-validation-sc4.yaml`](../../../compliance/lula/lula-validation-sc4.yaml) — k8s label `compliance.iso42001/enabled=true` | OSCAL Finding → Slack/PagerDuty alert on FAIL | **All regions** |
| **NIST Map 1.5**: Data Latency/Quality.    | Map 1.5: Data Quality.        | **SC-5**: Do not trade on stale data (>100ms latency).                         | **NeMo Action**: `check_data_latency` (Generated by Transpiler).                                                                                                                                                                              | —                                                                                                                        | —                                             | **US_FED only** |
| **EU AI Act**: Human Oversight.            | Governance.                   | **SC-6**: High-risk actions must have HITL.                                    | **LangGraph**: `interrupt_before=["human_review"]`.                                                                                                                                                                                           | —                                                                                                                        | —                                             | **EU_ECB only** |
| **ISO A.5.3**: Logging and monitoring.     | Govern 6.2: Auditability.     | **SC-7**: All AI governance events must be logged with control ID and outcome. | OTel spans tagged `iso42001.control_id` → Langfuse via [`langfuse_utils.py`](../../../src/governed_financial_advisor/utils/langfuse_utils.py) and [`nemo_exporter.py`](../../../src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py) | [`lula-validation-a53.yaml`](../../../compliance/lula/lula-validation-a53.yaml) — `safety_rate ≥ 98%`                          | OSCAL Finding, Langfuse compliance project    | **All regions** |
| **ISO A.4**: Resource Management.          | Govern 4.1: Risk tolerance.   | **SC-8**: Agent must not exceed per-session step-count or token quota.         | **Token Quota Proxy** (`CTRL_TQP_007`): [`token_quota_proxy.py`](../../../src/gateway/governance/token_quota_proxy.py) — Redis atomic Lua counters; fail-closed HTTP 429; two-phase commit (`check_and_increment` / `reconcile_actual_tokens`); `rollback_step()` on downstream failure | —                                                                                                                        | —                                             | **All regions** |
| **ISO A.6**: Data Lineage / PII Leak Mitigation. | Govern 2.1: Data privacy. | **SC-9**: PII must be redacted from UCA compliance records before WORM persistence. | **PII Sanitizer**: [`pii_sanitizer.py`](../../../src/gateway/governance/pii_sanitizer.py) — 15 NeMo-recognized entity types; compiled regex patterns applied sequentially before ledger write; thread-safe | —                                                                                                                        | —                                             | **All regions** |
| **ISO 42001 Clause 6.1**: Risk treatment.  | Govern 6.2: Auditability.     | **SC-10**: Unsafe Control Actions must be logged to a tamper-evident WORM audit trail. | **UCA Logger**: [`uca_logger.py`](../../../src/gateway/governance/uca_logger.py) — 16-field ISO 42001 Clause 6.1 UCA records; Cloud KMS signed (production) / HMAC-SHA256 stub (`CAGE_ENV=test`); persisted to region-gated WORM bucket (`OSCAL_S3_BUCKET_{REGION}`) | —                                                                                                                        | OSCAL Finding, WORM bucket (region-gated)     | **All regions** |

## Implementation Details

### 1. Automated Policy Derivation

The `src/governance/transpiler.py` module implements the automated derivation of SC-3 and SC-5. It converts `ProposedUCA` objects from the offline Risk Analyst into:

1.  **Python Actions** for NeMo Guardrails (e.g., `check_data_latency`).
2.  **Rego Rules** for Open Policy Agent (e.g., `decision = "DENY" if ...`).

### 2. Structural Enforcement

The **Safety Node** ([`src/governed_financial_advisor/graph/nodes/safety_node.py`](../../../src/governed_financial_advisor/graph/nodes/safety_node.py)) explicitly enforces SC-4. It acts as a domain-specific wrapper around the generic **LangGraph Governance Harness** (`create_opa_safety_node`), acting as a gatekeeper between the `execution_analyst` (Planner) and `governed_trader` (Executor) to query OPA for every proposed plan.

### 3. Continuous Compliance Audit (Lula)

The **Lula CronJob** ([`deployment/k8s/lula-cron.yaml`](../../../deployment/k8s/lula-cron.yaml)) runs every 6 hours and validates the **4 Active** Lula manifests (A.5.2, A.5.3, A.9.2, SC-4) against live cluster state and Langfuse evidence. There are 15 total manifests — 4 Active and 11 Stub (requiring cluster-specific configuration before activation). See [`compliance/lula/README.md`](../../../README.md) for the full status table with regional scope annotations. Findings are expressed as **OSCAL Assessment Results** and ingested back into Langfuse via the **compliance bridge audit workflow** ([`src/compliance_bridge/audit_workflow.py`](../../../src/compliance_bridge/audit_workflow.py)).

Key components:

- **compliance-bridge** (`src/compliance_bridge/`) — Python FastAPI service that aggregates Langfuse traces into a time-windowed `safety_rate` per ISO 42001 control, served via `/v1/metrics/{control_id}`.
- **Lula RBAC** ([`deployment/k8s/lula-rbac.yaml`](../../../deployment/k8s/lula-rbac.yaml)) — Least-privilege `lula-auditor` ServiceAccount with `get/list/watch` scoped to `governance-stack` and `default` namespaces only.
- **OSCAL Component Definition** ([`compliance/oscal/component-definition.yaml`](../../../compliance/oscal/component-definition.yaml)) — Machine-readable link between controls, implementations, and Lula validations.

### 4. Evidence-Age Staleness Guard

All Lula Rego policies assert `evidence_age_seconds < 172800` (48 hours). If the last Langfuse trace for a control is older than 48 hours, the audit fails with "Insufficient Evidence (Stale Data)" rather than silently passing — preventing "ghost compliance."
