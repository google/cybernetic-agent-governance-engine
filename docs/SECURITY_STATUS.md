# Security & Compliance Status — CAGE v2.0.0

**Date:** 2026-06-08
**Status:** Public disclosure of current security posture and compliance implementation state

---

## Summary

CAGE v2.0.0 provides a **production-grade AI governance enforcement runtime**. The AI-layer controls (NeMo Guardrails, OPA policy enforcement, Cloud KMS HSM-backed asymmetric signing with HMAC-SHA256 dev/CI fallback, HITL with TOCTOU remediation, LangGraph safety nodes, DEFER state machine, SHA-256 hash-chained context accumulator) are fully implemented and tested. However, the full **NIST Risk Management Framework (RMF) authorization process has not been completed**, and several infrastructure-level security controls have known gaps documented in [`docs/POAM.md`](POAM.md).

> [!IMPORTANT]
> This system has **not received an Authorization to Operate (ATO)** from a NIST-designated Authorizing Official. It has not undergone a formal Security Assessment. Deployers in regulated environments must complete their own risk assessment before production use.

> **⚠️ Regional Scoping Notice:** NIST RMF / NIST SP 800-53 compliance status reported in this document applies **exclusively to `US_FED` deployments**. `EU_ECB` deployments are governed by EU AI Act (Reg. 2024/1689), DORA, and GDPR — not NIST. `APAC_MAS` deployments are governed by MAS FEAT Principles, MAS Notice 655, and MAS TRM Guidelines — not NIST. See the [EU_ECB Compliance Status](#eu_ecb--eu-ai-act--dora-compliance-status) and [APAC_MAS Compliance Status](#apac_mas--mas-feat-compliance-status) sections below.

---

## What Is Fully Implemented

### AI Governance Enforcement (Strong)

| Control                          | Implementation                                                            | Status                  |
| -------------------------------- | ------------------------------------------------------------------------- | ----------------------- |
| NeMo Guardrails input gate       | Mandatory first LangGraph node; fail-closed on exception                  | ✅ Implemented & tested |
| NeMo Guardrails output rail      | Mandatory final LangGraph node; in-process Presidio PII egress filter    | ✅ Implemented & tested |
| OPA policy enforcement           | Direct REST; circuit breaker defaults to DENY on failure                  | ✅ Implemented & tested |
| STPA-to-Policy Compiler          | UCAs compiled from YAML to Rego + Colang + Python; no hand-edited policy  | ✅ Implemented & tested |
| Cloud KMS governance signature   | HSM-backed asymmetric signing via `kms_signer.py`; HMAC-SHA256 fallback in dev/CI | ✅ Implemented & tested |
| Human-in-the-loop gate           | `interrupt_before=["governed_trader"]`; Redis-persisted checkpoint; TOCTOU remediation via `post_hitl_rehydrate` + `post_hitl_revalidate` nodes | ✅ Implemented & tested |
| Safety check node                | Explicit OPA gate between evaluator and governed trader                   | ✅ Implemented & tested |
| Control Barrier Function         | Redis-backed cash/drawdown invariant enforcement; externally reconciled via AnchorageGrpcLedgerProvider | ✅ Implemented & tested |
| Aho-Corasick keyword scan        | O(n) prompt-injection detection; 14+ patterns                             | ✅ Implemented & tested |
| Multi-agent consensus            | Unanimity required for trades > $10k; ConsensusModelRegistry              | ✅ Implemented & tested |
| Presidio PII detection           | 15 entity types; input and output (in-process within NeMo Guardrails)      | ✅ Implemented & tested |
| W3C traceparent propagation      | Full OTel trace waterfall; 100% sampling for governance spans; direct Langfuse OTLP (OTel Collector deprecated 2026-05-31) | ✅ Implemented & tested |
| Recursion guard                  | `loop_count >= 3 → explainer` escape hatch                                | ✅ Implemented & tested |
| DEFER state machine (AARM-V7)    | Redis db=1 noeviction; SSE events; OTel metrics; closes AARM-V7 threat vector | ✅ Implemented (v2.0.0) |
| SHA-256 hash-chained context     | Context accumulator with hash-chain integrity; closes AARM-V1 threat vector | ✅ Implemented (v2.0.0) |
| External Normative Provider      | Adaptive FRIA gating (EU AI Act); stub mode until TrustLayers credentials provisioned (POAM-022) | ✅ Implemented (v2.0.0) |
| Linkerd mTLS (SC-8 / IA-3)       | SPIFFE/SVID identity; gateway↔OPA, gateway↔NeMo; closes POAM-007          | ✅ Implemented (v1.1.0) |
| Cilium L7 egress lockdown (SC-7) | FQDN allowlist (gateway); internal-only (agent pods)                      | ✅ Implemented (v1.1.0) |
| Cryptographic evidence chain     | SHA-256 hash-chained NDJSON; MiFID II / GDPR view-access log; KMS batch signing for OSCAL artifacts | ✅ Implemented (v1.1.0) |
| AgentSight UI Phase 1            | React/Vite frontend; eBPF kernel observability via `deployment/k8s/agentsight-daemon.yaml`; remote exporter active | ✅ Implemented (v2.0.0) |
| Token Quota Proxy (CTRL_TQP_007) | Per-session step-count (≤12) and token (≤100k) quota enforcement via Redis atomic Lua counters; fail-CLOSED; HTTP 429 on quota exceeded; two-phase commit (reserve → reconcile); rollback on downstream failure. ISO 42001 Annex A.4. | ✅ Implemented (fix/track-b-v2-release-gates) |
| PII Sanitizer                    | Pre-ledger regex sanitization pipeline (SSN, CC, email, phone, API key/Bearer token) applied to all UCA records before WORM persistence. ISO 42001 Annex A.6. | ✅ Implemented (fix/track-b-v2-release-gates) |
| UCA Logger                       | ISO 42001 Clause 6.1 UCA record builder; KMS-signed (HMAC-SHA256 stub in `CAGE_ENV=test`); region-gated WORM persistence (`CAGE_DEPLOYMENT_REGION` → `OSCAL_S3_BUCKET_{REGION}`); UCA types: `quota_exceeded`, `prompt_injection`, `pii_sanitization`. | ✅ Implemented (fix/track-b-v2-release-gates) |

### Compliance Automation (15 Lula Validation Manifests — 4 Active, 11 Stub)

Automated continuous compliance assessment covers **15 Lula validation manifests** in `compliance/lula/`. Of these, **4 are Active** (production-ready, enabled in the Lula CronJob) and **11 are Stubs** (logic complete but requiring cluster-specific namespace/resource name configuration before activation). See [`compliance/lula/README.md`](../compliance/lula/README.md) for the full status table and activation instructions.

| Control   | Standard        | Region Scope | Description                                       | Threshold            | Lula Validation              | Status |
| --------- | --------------- | ------------ | ------------------------------------------------- | -------------------- | ---------------------------- | ------ |
| ISO A.5.2 | ISO 42001       | ALL          | Social impact — hate speech / bias prevention     | `safety_rate ≥ 99%`  | `lula-validation-a52.yaml`   | ✅ **Active** |
| ISO A.5.3 | ISO 42001       | ALL          | Logging and monitoring — audit event completeness | `safety_rate ≥ 98%`  | `lula-validation-a53.yaml`   | ✅ **Active** |
| ISO A.9.2 | ISO 42001       | ALL          | Data privacy — no PII sent to external APIs       | `safety_rate = 100%` | `lula-validation-a92.yaml`   | ✅ **Active** |
| SC-4      | NIST SP 800-53  | US_FED       | Fiscal limits — human approval for trades > $10k  | OPA policy active    | `lula-validation-sc4.yaml`   | ✅ **Active** |
| AARM-V    | CSA AARM v1.0   | ALL          | 11-vector AI agent threat model coverage          | All vectors covered  | `lula-validation-aarm-vectors.yaml` | 🔶 **Stub** |
| AC-2      | NIST SP 800-53  | US_FED       | Account management — service account lifecycle    | Lifecycle validated  | `lula-validation-ac2.yaml`   | 🔶 **Stub** |
| AC-3      | NIST SP 800-53  | US_FED       | Access enforcement — OPA policy gate              | OPA circuit breaker  | `lula-validation-ac3.yaml`   | 🔶 **Stub** |
| AU-12     | NIST SP 800-53  | US_FED       | Audit record generation — OTel span completeness  | `safety_rate ≥ 98%`  | `lula-validation-au12.yaml`  | 🔶 **Stub** |
| CM-6      | NIST SP 800-53  | US_FED       | Configuration settings — governance config        | Config validated     | `lula-validation-cm6.yaml`   | 🔶 **Stub** |
| IA-3      | NIST SP 800-53  | US_FED       | Device identification — SPIFFE/SVID identity      | Identity verified    | `lula-validation-ia3.yaml`   | 🔶 **Stub** |
| IA-5      | NIST SP 800-53  | US_FED       | Authenticator management — KMS HSM key lifecycle  | Key lifecycle valid  | `lula-validation-ia5.yaml`   | 🔶 **Stub** |
| IR-6      | NIST SP 800-53  | US_FED       | Incident reporting — governance bypass alerts     | Alert pipeline valid | `lula-validation-ir6.yaml`   | 🔶 **Stub** |
| RA-5      | NIST SP 800-53  | US_FED       | Vulnerability scanning — Trivy/pip-audit CI       | CI scan passing      | `lula-validation-ra5.yaml`   | 🔶 **Stub** |
| SC-8      | NIST SP 800-53  | US_FED       | Transmission confidentiality — Linkerd mTLS       | mTLS enforced        | `lula-validation-sc8.yaml`   | 🔶 **Stub** |
| SI-2      | NIST SP 800-53  | US_FED       | Flaw remediation — CVE patching (pip-audit CI)    | CI scan passing      | `lula-validation-si2.yaml`   | 🔶 **Stub** |

Findings are expressed as OSCAL Assessment Results and ingested into Langfuse via direct OTLP (OTel Collector deprecated 2026-05-31; Langfuse native OTLP ingestion is now used). **Additional ISO 42001 Annex A controls and the full NIST SP 800-53 control baseline are not yet mapped or assessed.**

---

## What Is Not Yet Complete

### NIST RMF Authorization Process (`US_FED` only)

> **⚠️ US_FED ONLY:** The NIST RMF authorization process described below applies exclusively to **`US_FED` deployments**. `EU_ECB` and `APAC_MAS` deployments are not subject to NIST RMF and do not require an ATO. See the [EU_ECB](#eu_ecb--eu-ai-act--dora-compliance-status) and [APAC_MAS](#apac_mas--mas-feat-compliance-status) sections for their respective compliance status.

The NIST RMF is a six-step process. The table below reflects the current state for `US_FED` deployments:

| RMF Step              | Status         | Notes                                                                                              |
| --------------------- | -------------- | -------------------------------------------------------------------------------------------------- |
| **1 — Prepare**       | 🟡 In Progress | FIPS 199 categorization document created but unsigned (POAM-009)                                   |
| **2 — Categorize**    | 🟡 In Progress | Informal categorization only; no System Owner / AO signature                                       |
| **3 — Select**        | 🟡 Partial     | Controls selected per NIST SP 800-53 HIGH baseline; not formally documented in a signed SSP        |
| **4 — Implement**     | 🟡 Partial     | AI governance controls implemented (see above); infrastructure-layer controls have gaps (see POAM) |
| **5 — Assess**        | ❌ Not started | No Security Assessment Report (SAR); no independent Control Assessor engaged                       |
| **6 — Authorize**     | ❌ Not started | No Authorization to Operate (ATO) letter issued (POAM-005, Critical)                               |
| **Ongoing — Monitor** | 🟡 Partial     | Lula CronJob active for 4 Active validation manifests (11 Stub — require cluster configuration); DEFER queue monitoring active; broader continuous monitoring not yet operational |

### Infrastructure Security Gaps (from POA&M)

The following weaknesses are documented in [`docs/POAM_US_FED.md`](POAM_US_FED.md) (v2.0, 2026-06-08 — authoritative for US_FED). Items marked **Closed** were resolved; see POAM_US_FED.md for full closure evidence. For universal ISO 42001 AIMS weaknesses (all regions), see [`docs/POAM_ISO42001.md`](POAM_ISO42001.md). For the cross-region traceability matrix, see [`docs/POAM_INDEX.md`](POAM_INDEX.md):

| ID       | Control    | Weakness                                                              | Severity     | Status          | Target Date |
| -------- | ---------- | --------------------------------------------------------------------- | ------------ | --------------- | ----------- |
| POAM-001 | AC-2       | No account management procedures                                      | High         | Open            | 2026-04-30  |
| POAM-002 | AC-6       | Overly broad IAM role bindings in Terraform                           | High         | Open            | 2026-05-15  |
| POAM-003 | AU-12      | ~~`automated_auditor.py` uses synthetic mock traces~~ **✅ Closed** — live OSCAL assessment results generated from Langfuse compliance metrics via compliance-bridge REST API | High | **Closed** | 2026-06-05 |
| POAM-004 | CA-5       | No formal POA&M process (this document)                               | High         | In Progress     | 2026-03-31  |
| POAM-005 | CA-6       | **No Authorization to Operate (ATO) letter**                          | **Critical** | Open            | 2026-06-30  |
| POAM-006 | CM-8       | No SBOM in CI/CD pipeline                                             | High         | Open            | 2026-05-01  |
| POAM-007 | IA-3       | ~~No intra-cluster mTLS~~ **✅ Closed** — Linkerd SPIFFE/SVID deployed | High         | **Closed**      | 2026-05-17  |
| POAM-008 | IR-1       | No formal Incident Response Plan                                      | High         | Open            | 2026-04-30  |
| POAM-009 | RA-2       | FIPS 199 categorization unsigned                                      | **Critical** | In Progress     | 2026-03-31  |
| POAM-010 | RA-5       | ~~No vulnerability scanning in CI pipeline~~ **✅ Closed** — pip-audit, Trivy, Grype, CycloneDX SBOM in `security-scan.yml` | High | **Closed** | 2026-04-15 |
| POAM-011 | SC-8       | No TLS enforcement validation test — test suite does not assert TLS 1.2+ on all endpoints | Moderate | Open | 2026-05-15 |
| POAM-012 | SC-12      | `CAGE_ROUTING_SEAL_SECRET` bypass allows silent enforcement disable   | High         | Open            | 2026-04-01  |
| POAM-013 | SI-2       | Unpinned `>=` version specifiers across Python dependencies           | High         | Open            | 2026-04-15  |
| POAM-014 | SC-28      | No CMEK validation for Langfuse / CloudSQL encryption-at-rest         | Moderate     | Open            | 2026-05-31  |
| POAM-015 | PL-2       | **No System Security Plan (SSP)** — `compliance/oscal/system-security-plan.yaml` is an OSCAL draft; no AO-signed SSP exists | **Critical** | Open | 2026-06-30 |
| POAM-016 | SI-2       | ~~CVE-2025-69872 (diskcache) RCE~~ **✅ Closed** — `outlines` removed from gateway deps | Moderate | **Closed** | 2026-05-29 |
| POAM-017 | SI-2       | CVE-2026-4810 (google-adk): code injection; upgrade blocked by OTel SDK version conflict | Moderate | Open | 2026-07-31 |
| POAM-018 | AU-9       | Langfuse compliance project credentials fail silently when absent     | High         | Open            | 2026-07-15  |
| POAM-019 | AU-9, SC-7 | Terraform fallback silently collapses dual-project telemetry isolation | High        | Open            | 2026-07-15  |
| POAM-020 | CM-3       | ~~Technical report README version mismatch~~ **✅ Closed** — aligned to v2.0.0 | Moderate | **Closed** | 2026-06-15 |
| POAM-021 | SI-4       | ~~AgentSight eBPF exporter in console mode~~ **✅ Closed** — `exporter.type: "remote"` confirmed | High | **Closed** | 2026-07-15 |
| POAM-022 | SA-9, CA-7 | External Normative Provider operating in stub mode (TrustLayers credentials not provisioned) | Moderate | In Progress | 2026-08-31 |
| POAM-023 | SI-2       | CVE-2025-13462 in `libpython3.11` (python:3.12-slim-bookworm base layer) — 19 CRITICAL CVEs; gateway Dockerfile pinned to `python:3.12-slim-bookworm` with `apt-get upgrade -y` applied at build time; no Debian bookworm fix available as of 2026-06-08; residual CVEs suppressed via `.trivyignore`; Cilium egress lockdown reduces exploitability; risk accepted with review date 2026-09-08 | **Critical** | Open | 2026-09-08 |

### Testing Gaps

- **~~`automated_auditor.py` uses synthetic mock traces`~~** — POAM-003 closed 2026-06-05. Live OSCAL assessment results now generated from Langfuse compliance metrics via compliance-bridge REST API.
- **No SBOM** — no Software Bill of Materials is generated per build (POAM-006). Note: vulnerability scanning (POAM-010) is now closed — pip-audit, Trivy, and Grype are active in CI.
- **No TLS enforcement test** — `tests/test_gateway_connectivity.py` does not assert TLS 1.2+ on all endpoints (POAM-011).
- **Langfuse compliance credentials not validated at startup** — silent failure if compliance project keys are absent (POAM-018).

---

## EU_ECB — EU AI Act / DORA Compliance Status

> **EU_ECB deployments are gated on EU AI Act and DORA compliance — not NIST SP 800-53.** The following table reflects the current compliance posture for `CAGE_DEPLOYMENT_REGION=EU_ECB`.

| Framework / Obligation | Status | Notes |
| ---------------------- | ------ | ----- |
| **EU AI Act Art. 6 + Annex III §5(b)** — High-Risk AI classification | 🟡 Partial | 6 controls mapped in `EU_ECB_BASELINE.json`; EU AI Office registration pending |
| **EU AI Act Art. 9** — Risk management system | 🟡 Partial | Min. agentic confidence raised to 0.97; formal risk management documentation pending |
| **EU AI Act Art. 10** — Data governance | 🟡 Partial | Presidio PII masking active; data governance documentation pending |
| **EU AI Act Art. 12** — Record-keeping | 🟡 Partial | OTel + Langfuse audit trail active; GDPR-compliant retention schedule pending |
| **EU AI Act Art. 14** — Human oversight | ✅ Implemented | HITL gate (`interrupt_before=["governed_trader"]`); TOCTOU remediation active |
| **EU AI Act Art. 17** — Quality management | 🟡 Partial | ISO 42001 Clause 9 evidence loop active; formal QMS documentation pending |
| **EU AI Act Art. 29a** — FRIA (Step 8) | 🟡 Partial | FRIA attestation logging active (`CTRL_FRIA_006`); EU AI Office registration pending |
| **EU AI Act Art. 61** — Post-market monitoring | 🟡 Partial | Lula CronJob + OSCAL Assessment Results active; formal post-market plan pending |
| **DORA Art. 10** — ICT risk management | 🟡 Partial | Architecture mapped; full DORA compliance testing pending |
| **DORA Art. 11** — ICT-related incident management | 🟡 Partial | `GovernanceEventBus` + Slack/PagerDuty alerts active; formal DORA incident plan pending |
| **DORA Art. 12** — Digital operational resilience testing | ❌ Not started | No DORA resilience testing performed |
| **GDPR Art. 22** — Automated decision-making | 🟡 Partial | HITL gate enforced; DPIA integration pending |
| **EBA Guidelines (2023/02)** — Internal governance | 🟡 Partial | Model governance mapped; ECB SSM TRIM validation pending |
| **SR 26-2 telemetry** | ✅ Suppressed | US-specific SR 26-2 citations suppressed in EU OTel spans via sentinel mechanism (§15.5) |

---

## APAC_MAS — MAS FEAT Compliance Status

> **APAC_MAS deployments are gated on MAS FEAT compliance — not NIST SP 800-53.** The following table reflects the current compliance posture for `CAGE_DEPLOYMENT_REGION=APAC_MAS`.

| Framework / Obligation | Status | Notes |
| ---------------------- | ------ | ----- |
| **MAS FEAT — Fairness (F1)** — Non-discriminatory outcomes | 🟡 Partial | DoWhy causal gatekeeper mapped; quantitative fairness metrics (demographic parity, equalized odds) pending |
| **MAS FEAT — Fairness (F2)** — Quantitative fairness metrics | 🟡 Partial | Threshold mapped in `APAC_MAS_BASELINE.json`; formal F2 assessment pending |
| **MAS FEAT — Ethics (E1)** — Ethical AI use | 🟡 Partial | NeMo guardrails + Aho-Corasick bias detection active; ethics framework documentation pending |
| **MAS FEAT — Accountability (A1)** — Human oversight | ✅ Implemented | HITL gate active; consensus threshold $5,000 (MAS FEAT A1 human oversight) |
| **MAS FEAT — Transparency (T1)** — Explainability | 🟡 Partial | `explainer` agent node active; formal transparency report pending |
| **MAS Notice 655** — Audit certification | 🟡 Partial | OTel + Langfuse audit trail active; MAS Notice 655 certification pending |
| **MAS TRM Guidelines §6.3/6.4** — AI controls | 🟡 Partial | Architecture mapped; MAS ENRM validation pending |
| **SR 26-2 telemetry** | ✅ Suppressed | US-specific SR 26-2 citations suppressed in APAC OTel spans via sentinel mechanism (§15.5) |

---

## Deployment Guidance for Regulated Environments

Before deploying CAGE in a regulated financial environment:

1. **Complete the NIST RMF steps 1–6** — obtain an ATO from an Authorizing Official before processing live customer data
2. **Draft and sign the SSP** — use `compliance/ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md` as the scaffold; `compliance/oscal/system-security-plan.yaml` is an OSCAL draft but is not AO-signed (POAM-015)
3. **Set `CAGE_ROUTING_SEAL_SECRET`** — failure to set this in production silently disables governance routing seal enforcement (POAM-012)
4. **Configure Langfuse compliance credentials** — `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` must be set; absence silently drops all compliance audit traces (POAM-018)
5. **Add TLS enforcement test** — verify all REST and gRPC endpoints require TLS 1.2+ with a test assertion (POAM-011)
6. **Pin all dependencies** — replace `>=` specifiers with exact pinned versions to prevent uncontrolled updates (POAM-013)
7. **Provision TrustLayers credentials** — configure `CAGE_NORMATIVE_ENDPOINT` and `CAGE_NORMATIVE_API_KEY_SECRET` to activate External Normative Provider for EU AI Act FRIA gating (POAM-022)

---

## References

| Document                            | Location                                                                                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| POA&M Index (all regions)           | [`docs/POAM_INDEX.md`](POAM_INDEX.md)                                                                                                                              |
| POA&M — ISO 42001 universal (ALL)   | [`docs/POAM_ISO42001.md`](POAM_ISO42001.md)                                                                                                                        |
| POA&M — US_FED (NIST SP 800-53)     | [`docs/POAM_US_FED.md`](POAM_US_FED.md)                                                                                                                            |
| POA&M — EU_ECB (EU AI Act / DORA)   | [`docs/POAM_EU_ECB.md`](POAM_EU_ECB.md)                                                                                                                            |
| POA&M — APAC_MAS (MAS FEAT)         | [`docs/POAM_APAC_MAS.md`](POAM_APAC_MAS.md)                                                                                                                        |
| NIST RMF Current-State Inventory    | [`docs/NIST_RMF_CHUNK1_CURRENT_STATE.md`](NIST_RMF_CHUNK1_CURRENT_STATE.md)                                                                                        |
| NIST RMF Gap Analysis (Steps 2–5)   | [`docs/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md`](NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md) — [`NIST_RMF_CHUNK5_MONITOR_ROADMAP.md`](NIST_RMF_CHUNK5_MONITOR_ROADMAP.md) |
| ISO 42001 Compliance Detail         | [`docs/ISO_42001_COMPLIANCE.md`](ISO_42001_COMPLIANCE.md)                                                                                                          |
| Security Assessment Plan            | [`docs/SECURITY_ASSESSMENT_PLAN.md`](SECURITY_ASSESSMENT_PLAN.md)                                                                                                  |
| Governance Crosswalk                | [`docs/GOVERNANCE_CROSSWALK.md`](GOVERNANCE_CROSSWALK.md)                                                                                                          |
| SR 26-2 (Federal Reserve)           | Federal Reserve Supervisory Letter SR 26-2, April 17, 2026 — Agentic AI Governance                                                                                 |
| CSA AARM v1.0                       | Cloud Security Alliance AI Risk Management v1.0 — 11-vector threat taxonomy                                                                                        |
