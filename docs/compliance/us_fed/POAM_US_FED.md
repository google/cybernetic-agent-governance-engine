---
poam_file: POAM_US_FED
region_scope: US_FED
primary_framework: "NIST SP 800-53 Rev. 5 / NIST SP 800-37 Rev. 2 / NIST AI 600-1"
global_baseline: ISO 42001
version: "2.2"
date: 2026-06-15
supersedes: "version 2.1 (2026-06-15)"
see_also:
  - docs/POAM_ISO42001.md   # universal ISO 42001 AIMS weaknesses (all regions)
  - docs/POAM_EU_ECB.md     # EU AI Act / DORA / GDPR weaknesses (EU_ECB only)
  - docs/POAM_APAC_MAS.md   # MAS FEAT / Notice 655 / TRM weaknesses (APAC_MAS only)
  - docs/POAM_INDEX.md      # cross-region traceability matrix
  - docs/NIST_AI_600_1_US_FED_ANALYSIS.md  # AI 600-1 gap analysis (source for AI600-xxx items)
---

# Plan of Action and Milestones (POA&M) — US_FED

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Reference:** NIST SP 800-37 Rev. 2, NIST SP 800-53 Rev. 5 CA-5, NIST AI 600-1 (July 2024)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=US_FED` only
**Global Baseline:** ISO/IEC 42001:2023 (AI Management System Standard)
**Version:** 2.2
**Date:** 2026-06-15
**Status:** ACTIVE

> **⚠️ Scope Notice:** This document tracks weaknesses against the **NIST SP 800-53 Rev. 5** control baseline, the **NIST RMF authorization process**, and **NIST AI 600-1** (Generative AI Profile). It applies exclusively to `US_FED` deployments. For universal ISO 42001 AIMS weaknesses (all regions), see [`docs/POAM_ISO42001.md`](POAM_ISO42001.md). For EU_ECB-specific weaknesses, see [`docs/POAM_EU_ECB.md`](POAM_EU_ECB.md). For APAC_MAS-specific weaknesses, see [`docs/POAM_APAC_MAS.md`](POAM_APAC_MAS.md). For the full AI 600-1 gap analysis, see [`docs/NIST_AI_600_1_US_FED_ANALYSIS.md`](NIST_AI_600_1_US_FED_ANALYSIS.md).

---

## POA&M Summary

| Metric          | SP 800-53 Items | AI 600-1 Items | Total |
| --------------- | --------------- | -------------- | ----- |
| **Total Items** | 23              | 7              | **30** |
| **Critical**    | 4               | 2              | **6** |
| **High**        | 13              | 5              | **18** |
| **Moderate**    | 6               | 0              | **6** |
| **Low**         | 0               | 0              | **0** |
| **Open**        | 11              | 2              | **13** |
| **In Progress** | 3               | 5              | **8** |
| **Closed**      | 7               | 0              | **7** |

> **Note:** POAM-018 and POAM-019 are also tracked in [`docs/POAM_ISO42001.md`](POAM_ISO42001.md) as universal ISO 42001 §A.9.4 weaknesses (all regions). The entries below are retained here for NIST SP 800-53 AU-9 / SC-7 audit continuity.
>
> **v2.1 addition (2026-06-15):** Seven new POAM items (AI600-001 through AI600-007) have been added based on the NIST AI 600-1 gap analysis in [`docs/NIST_AI_600_1_US_FED_ANALYSIS.md`](NIST_AI_600_1_US_FED_ANALYSIS.md). These items address GenAI-specific risks required for US_FED ATO under EO 14110 and OMB M-24-10.
>
> **v2.1 update (2026-06-15):** Phase 0–3 implementation work completed on branch `feat/CAGE-AI600-ai600-1-implementation` (commits `c014337`–`51f6c25`). AI600-001, AI600-002, AI600-003, AI600-005, and AI600-007 moved to **In Progress**. AI600-004 and AI600-006 remain **Open** (no source code changes yet). 222 AI 600-1 unit tests pass (0 failures). See [`docs/AI_600_1_IMPLEMENTATION_PLAN.md`](AI_600_1_IMPLEMENTATION_PLAN.md) for the full implementation roadmap.

---

## POA&M Items

| POA&M ID | Control ID | ISO 42001 Ref | Regions | Weakness Description | Detection Method | Risk Level | Scheduled Completion | Resources Required | Status | Milestone |
| -------- | ---------- | ------------- | ------- | -------------------- | ---------------- | ---------- | -------------------- | ------------------ | ------ | --------- |
| POAM-001 | AC-2 | §A.9.2 | US_FED | No account management procedures documented. No formal process exists for account provisioning, periodic review, or deactivation for CAGE system access including GCP IAM, Kubernetes RBAC, and application-level service accounts. | Manual review | **High** | 2026-04-30 | 8 hrs | Open | Draft AC-2 procedure covering GCP IAM, GKE RBAC, and application service account lifecycle |
| POAM-002 | AC-6 | §A.9.2 | US_FED | IAM Terraform bindings use overly broad roles. Review of `deployment/` Terraform configuration reveals use of roles such as `roles/editor` or broad project-level bindings rather than purpose-specific custom roles implementing least privilege. | Terraform plan review | **High** | 2026-05-15 | 16 hrs | Open | Update iam.tf with least-privilege custom IAM roles scoped per service; validate with `terraform plan` |
| POAM-003 | AU-12 | §A.9.4 | US_FED | ~~`automated_auditor.py` uses synthetic mock traces.~~ **RESOLVED.** The `lula-audit` CronJob now calls the compliance-bridge Python modules directly (`get_compliance_metrics` → `build_oscal_assessment_results` → `run_audit_workflow`) using live Langfuse compliance project credentials. Phase 4 Post-Rename Lula Validation executed 2026-06-05: audit_id `lula-post-rename-1780672943`, 13 findings ingested, `chain_integrity_valid: true`. Evidence: `proof/lula-poam-evidence.log`, `proof/compliance-trigger-evidence.yaml`. | Code review + Phase 4 live run | **High** | 2026-04-15 | 8 hrs | **Closed** | ✅ Live OSCAL assessment results generated from Langfuse compliance metrics via compliance-bridge REST API. CronJob (`deployment/k8s/lula-cron.yaml`) uses `gcr.io/laah-cybernetics/compliance-bridge:latest` image, calls modules in-process — no synthetic traces. Verified: `✅ Lula audit complete` + `✅ OSCAL results ingested into Langfuse compliance project`. Closed 2026-06-05. |
| POAM-004 | CA-5 | §10.2 | US_FED | No formal POA&M process. Prior to this document, no structured Plan of Action and Milestones process existed to track identified security weaknesses, assign ownership, or enforce remediation deadlines. | Gap analysis | **High** | 2026-03-31 | 4 hrs | **In Progress** | Complete this document; establish POA&M review cadence (monthly review, quarterly AO briefing) |
| POAM-005 | CA-6 | N/A | US_FED | No Authorization to Operate (ATO) letter exists. The CAGE system has never undergone a formal NIST RMF authorization process. No ATO letter has been issued by an Authorizing Official. System operates without formal risk acceptance documentation. | Gap analysis | **Critical** | 2026-06-30 | 40 hrs | Open | Complete full authorization package: SSP → Security Assessment → SAR → POA&M → AO review → ATO letter issuance |
| POAM-006 | CM-8 | §A.8.3 | US_FED | No Software Bill of Materials (SBOM) generated. The CAGE system has no automated SBOM generation in its CI/CD pipeline. Container images and Python dependencies cannot be rapidly scanned against known CVE databases in response to zero-day disclosures. | Gap analysis | **High** | 2026-05-01 | 16 hrs | Open | Add Trivy SBOM generation (CycloneDX or SPDX format) to GitHub Actions CI pipeline; publish SBOM artifacts per container image build |
| POAM-007 | IA-3 | §A.9.3 | US_FED | No intra-cluster mTLS; service identity relies on shared HMAC only. Inter-service authentication within the GKE cluster uses a shared `CAGE_ROUTING_SEAL_SECRET` HMAC rather than cryptographic service identity (mTLS). Compromise of the shared secret undermines all service-to-service authentication claims. | Architecture review | **High** | 2026-07-31 | 120 hrs | **Closed** | ✅ Linkerd mTLS implemented via `deployment/k8s/linkerd-mtls-policy.yaml`. Server + AuthorizationPolicy + MeshTLSAuthentication resources enforce SPIFFE/SVID identity for Gateway→OPA and Gateway→NeMo paths. Cilium L7 lockdown via `deployment/k8s/cilium-egress-lockdown.yaml` prevents lateral movement. Verified: `linkerd viz authz deployment/opa-service -n governance-stack`. Closed 2026-05-17. |
| POAM-008 | IR-1 | §6.1 | US_FED | No formal Incident Response Plan (IRP) document. No documented procedures exist for detecting, reporting, containing, eradicating, and recovering from security incidents affecting the CAGE system. This includes AI-specific incidents such as governance bypass events and prompt injection attacks. | Gap analysis | **High** | 2026-04-30 | 16 hrs | Open | Draft IRP from NIST SP 800-61r2 template; include AI-specific incident categories (governance bypass, model manipulation, PII exfiltration); obtain AO approval |
| POAM-009 | RA-2 | N/A | US_FED | FIPS 199 categorization is unsigned/informal. While a FIPS 199 categorization document has been created (`compliance/categorization/FIPS199_CATEGORIZATION.md`), it has not been formally reviewed and signed by the System Owner and Authorizing Official, and therefore carries no formal risk acceptance authority. | Gap analysis | **Critical** | 2026-03-31 | 4 hrs | **In Progress** | Obtain AO and System Owner signatures on `compliance/categorization/FIPS199_CATEGORIZATION.md`; archive signed copy |
| POAM-010 | RA-5 | §A.8.3 | US_FED | ~~No vulnerability scanning in CI pipeline.~~ **RESOLVED.** pip-audit, Trivy, Grype, and CycloneDX SBOM generation are now integrated into the `security-scan.yml` GitHub Actions workflow. Known CVEs in third-party libraries are detected and fail the build unless explicitly ignored with documented POAM justifications. | Automated CI scanning | **High** | 2026-04-15 | 8 hrs | **Closed** | ✅ Implemented in `.github/workflows/security-scan.yml` — pip-audit with GHSA ignore list, Trivy FS scan, Grype enrichment, CycloneDX SBOM artifact generation |
| POAM-011 | SC-8 | §A.9.3 | US_FED | No encryption-in-transit validation test. The test suite (`tests/test_gateway_connectivity.py`) does not assert that all connections use TLS 1.2 or higher. It is possible to configure the gateway without TLS without triggering a test failure. | Gap analysis | **Moderate** | 2026-05-15 | 8 hrs | Open | Add TLS assertion to `tests/test_gateway_connectivity.py`; verify gRPC and REST endpoints enforce TLS 1.2+ with valid certificates |
| POAM-012 | SC-12 | §A.6.1 | US_FED | ~~`CAGE_ROUTING_SEAL_SECRET` bypass allows silent enforcement disable.~~ **✅ Closed** — `routing_seal.py` now fails fast at import time if `GOVERNANCE_SALT` is absent; hardcoded `"REDACTED_SALT"` fallback removed (Sprint 1, BLOCKER-02). `CAGE_SEAL_ENFORCEMENT=log` bypass guard added to `hybrid_server.py` (BLOCKER-03). Seal enforcement verified end-to-end: unsigned requests return HTTP 403, valid signed requests return 200. `GOVERNANCE_SALT` sourced from `advisor-secrets` K8s Secret. | Code review | **High** | 2026-06-08 | 2 hrs | **Closed** | ✅ `routing_seal.py` fail-fast guard implemented (Sprint 1, BLOCKER-02). `CAGE_SEAL_ENFORCEMENT=log` bypass guard added (BLOCKER-03). Seal enforcement verified end-to-end (Track C, 2026-06-08). Closed 2026-06-08. |
| POAM-013 | SI-2 | §A.8.3 | US_FED | Python dependencies use unpinned version specifiers (`>=`) across all services. Review of `pyproject.toml` and service `requirements.txt` files reveals use of `>=` version constraints rather than pinned versions. This allows non-reproducible builds and uncontrolled dependency updates that may introduce vulnerabilities. | Dependency audit | **High** | 2026-04-15 | 8 hrs | Open | Generate `pip freeze` lockfiles per service; pin all dependencies to exact versions; integrate pip-audit into CI to detect version drift |
| POAM-014 | SC-28 | §A.9.3 | US_FED | No encryption-at-rest validation for Langfuse / CloudSQL. While GCP provides encryption at rest by default, there is no documented validation that Customer-Managed Encryption Keys (CMEK) are configured for CloudSQL (Langfuse traces/PII) and GCS buckets (audit artifacts). Default Google-managed keys may not meet organizational key management requirements. | Architecture review | **Moderate** | 2026-05-31 | 4 hrs | Open | Verify CMEK configuration on CloudSQL instances and GCS buckets used by CAGE; document key rotation policy; update SSP SC-28 control statement |
| POAM-015 | PL-2 | N/A | US_FED | No System Security Plan (SSP) exists. The CAGE system has no formal SSP documenting system boundaries, security controls, and control implementation statements. The SSP is a mandatory artifact for ATO and is prerequisite to the security assessment. | Gap analysis | **Critical** | 2026-06-30 | 160 hrs | Open | Draft SSP from NIST SP 800-18 template using `compliance/ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md` as scaffold; populate all HIGH baseline control implementation statements; obtain AO approval |
| POAM-016 | SI-2 | §A.8.3 | US_FED | ~~`CVE-2025-69872` (diskcache): Pickle deserialization RCE.~~ **RESOLVED.** The `outlines` package was removed from `pyproject.toml [project.optional-dependencies.gateway]` — CAGE never imports outlines; the `guided_json` FSM decoder runs server-side inside vLLM. Removing outlines eliminates the transitive `diskcache` dependency entirely. `GHSA-w8v5-vhqr-4h9v` ignore removed from `.github/workflows/security-scan.yml`. | pip-audit CI scan | **Moderate** | 2026-05-29 | 1 hr | **Closed** | ✅ Root cause eliminated: `outlines` removed from gateway deps; `diskcache`, `outlines-core`, `genson` dropped from `uv.lock`. Closed 2026-05-29. |
| POAM-017 | SI-2 | §A.8.3 | US_FED | `CVE-2026-4810` (google-adk): Code injection vulnerability. The `google-adk` library is vulnerable to code injection. Upgrade is blocked by a hard requirement on `opentelemetry-sdk<1.39.0`, while the project requires `opentelemetry-sdk>=1.39.1`. Ignored in CI via `GHSA-rg7c-g689-fr3x`. | pip-audit CI scan | **Moderate** | 2026-07-31 | 4 hrs | Open | Monitor `google-adk` and `opentelemetry-sdk` for compatible version releases; upgrade when constraint conflict is resolved |
| POAM-018 | AU-9 | §A.9.4 | ALL | Langfuse compliance project credentials fail silently when absent. If `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` are not configured, the Langfuse SDK initializes with empty credentials and silently drops all compliance audit traces. No error is raised, no alert fires, and all ISO 42001 evidence collection ceases without visible indication. **Phase 4 validation 2026-06-05 confirmed credentials are live.** | Code review | **High** | 2026-07-15 | 4 hrs | Open | Add startup validation in `audit_workflow.py` that raises `RuntimeError` if compliance credentials are empty in non-dev environments; add `/health` check that reports compliance Langfuse connectivity status. **See also:** [`docs/POAM_ISO42001.md#POAM-018`](POAM_ISO42001.md) — tracked as ISO 42001 §A.9.4 universal weakness. |
| POAM-019 | AU-9, SC-7 | §A.9.4 | ALL | Terraform fallback silently collapses dual-project telemetry isolation. `infra/targets/gcp-gke/main.tf` L546-547 falls back to application project credentials when `langfuse_compliance_public_key` / `langfuse_compliance_secret_key` are empty. This silently defeats the dual-project architecture designed to provide evidentiary independence of audit evidence. | Terraform config review | **High** | 2026-07-15 | 2 hrs | Open | Remove Terraform fallback on L546-547; make compliance credentials a required variable with no default; add compliance credentials to `prod.tfvars` template. **See also:** [`docs/POAM_ISO42001.md#POAM-019`](POAM_ISO42001.md) — tracked as ISO 42001 §A.9.4 universal weakness. |
| POAM-020 | CM-3 | §10.2 | US_FED | ~~Technical report README version mismatch.~~ **RESOLVED.** `docs/technical-report/README.md` references have been corrected from v2.1.0 to v0.1.0. Document descriptions, Quick Reference table, and findings summary now reflect current codebase state. | Documentation audit | **Moderate** | 2026-06-15 | 2 hrs | **Closed** | ✅ Fixed in `docs/technical-report/README.md` — version aligned to v0.1.0, FIND-011 mTLS marked resolved, open critical findings reduced from 2 to 1. Closed 2026-05-27. |
| POAM-021 | SI-4 | §A.9.4 | US_FED | ~~AgentSight eBPF monitoring exporter set to console mode.~~ **RESOLVED.** Inspection of `deployment/agentsight/agentsight-config.yaml` confirms `exporter.type: "remote"` is already configured, targeting `http://agentsight-dashboard:8080`. The gap documented in Chunk5 G7.1-2 was based on a prior state that has since been corrected. | Configuration review | **High** | 2026-07-15 | 0 hrs | **Closed** | ✅ Already configured as `type: "remote"` in `agentsight-config.yaml`. No change needed — prior gap documentation was stale. Closed 2026-05-27. |
| POAM-022 | SA-9, CA-7 | §A.6.1 | US_FED | External Normative Provider interface implemented but operating in stub mode. `normative_provider.py` provides the full 3-endpoint integration surface with adaptive gating primitive (`enforce_fria_boundary()`), but production activation requires TrustLayers API credentials. `CAGE_NORMATIVE_PROVIDER=static` (default) means no external validation is performed — all FRIA checks are stub-admitted. The interface code, daemon lifecycle, DEFER queue integration, and 29 tests are verified, but the control is not providing independent compliance ground truth until credentials are provisioned. | Code review | **Moderate** | 2026-08-31 | 4 hrs | **In Progress** | Coordinate with TrustLayers team for API key provisioning; configure `CAGE_NORMATIVE_ENDPOINT` and `CAGE_NORMATIVE_API_KEY_SECRET` in `prod.tfvars`; verify boot-time baseline fetch and adaptive gating in staging environment. **EU AI Act Art. 29a aspect tracked separately:** [`docs/POAM_EU_ECB.md#EU-001`](POAM_EU_ECB.md). |
| POAM-023 | SI-2 | §A.8.3 | US_FED | CVE-2025-13462 in `libpython3.11` (python:3.12-slim-bookworm base layer) — CRITICAL remote code execution potential in Python standard library. Trivy container scan (gate U-06) identified 19 CRITICAL CVEs attributable to `libpython3.11` in the bookworm base layer. No Debian bookworm fix is available as of 2026-06-08. `apt-get upgrade -y` was applied during image build but cannot remediate this CVE. Network egress locked down via Cilium (`deployment/k8s/cilium-egress-lockdown.yaml`) to reduce exploitability. CVE suppressed in Trivy via `.trivyignore` pending upstream Debian patch. | Trivy container scan (gate U-06, Track D) | **Critical** | 2026-09-08 | 2 hrs | Open | Monitor Debian bookworm security tracker for CVE-2025-13462 patch availability; rebuild gateway image immediately upon patch release; remove `.trivyignore` suppression entry; re-run Trivy scan to confirm remediation. Review date: 2026-09-08. |

---

## POA&M Process

### Review Cadence

- **Monthly:** Review open items, update milestones, escalate slipped items
- **Quarterly:** AO briefing on POA&M status; risk acceptance decisions for items requiring schedule extensions
- **Annual:** Full POA&M review as part of annual authorization renewal

### Entry Criteria

New POA&M items are created when:

- Security control assessments identify weaknesses
- Continuous monitoring detects new vulnerabilities
- Penetration testing or red-team exercises identify gaps
- Regulatory changes require new controls
- Automated scanning (Trivy, pip-audit, Lula) identifies compliance failures

### Closure Criteria

Items are closed when:

1. Remediation actions are fully implemented
2. Implementation is verified by the ISSO or Security Control Assessor
3. Supporting evidence (code changes, scan results, configuration artifacts) is archived
4. AO is notified of closure for HIGH/CRITICAL items

### Escalation

- Items not remediated by scheduled completion date are escalated to the System Owner
- Critical items overdue by >30 days are escalated to the AO
- Items that cannot be remediated must have a formal risk acceptance signed by the AO

---

## NIST AI 600-1 POA&M Items

> **Source:** [`docs/NIST_AI_600_1_US_FED_ANALYSIS.md`](NIST_AI_600_1_US_FED_ANALYSIS.md) — full gap analysis, recommended RMF chunk updates, OSCAL artifacts, and implementation roadmap.
>
> **Framework:** NIST AI 600-1 (Generative AI Profile, July 2024) — mandatory for US_FED deployments under EO 14110 (October 2023) and OMB M-24-10 (March 2024).
>
> **Numbering:** AI600-xxx items are distinct from POAM-xxx (SP 800-53) items. Both series are active and tracked in this document.

| POA&M ID | Control ID | AI 600-1 Ref | Regions | Weakness Description | Detection Method | Risk Level | Scheduled Completion | Resources Required | Status | Milestone |
| -------- | ---------- | ------------- | ------- | -------------------- | ---------------- | ---------- | -------------------- | ------------------ | ------ | --------- |
| AI600-001 | SI-10, AU-3 | §2.2 Confabulation | US_FED | No confabulation rate metric exists. The financial advisor LLM can produce confident but factually incorrect market data, fabricated portfolio positions, or hallucinated regulatory constraints. The ConsensusEngine "Risk Manager" and "Compliance Officer" critics are themselves LLMs subject to confabulation — consensus agreement does not guarantee factual accuracy. No Lula validation for confabulation rate exists. | AI 600-1 gap analysis | **High** | 2026-09-30 | 9d | **In Progress** | ✅ Phase 1 (2026-06-15): `src/gateway/governance/confabulation_scorer.py` created — Langfuse `confabulation_risk` metric emission, LLM-as-judge scoring, `confabulation_rate` threshold enforcement. `compliance/lula/lula-validation-ai600-confabulation.yaml` stub created. 34 unit tests pass (`tests/test_confabulation_scorer.py`). Remaining: (1) Wire `confabulation_rate` into `ComplianceMetrics` in `src/compliance_bridge/types.py`; (2) Harden Lula stub to live assertion (Phase 3 §7.5). |
| AI600-002 | SI-19, SC-28 | §2.3 Data Privacy | US_FED | No training data memorization assessment. DeepSeek-R1 and Llama-3.1 may have memorized PII from training corpora — a risk distinct from runtime PII detection. No differential privacy or membership inference attack testing. Presidio `score_threshold=0.3` in `SafeAnalyzer` may be too permissive for a HIGH-baseline financial system. PII in Langfuse OTel span attributes not subject to 24-hour retention limit from `docs/banking_regs.md`. | AI 600-1 gap analysis | **High** | 2026-10-31 | 8d | **In Progress** | ✅ Phase 1 (2026-06-15): `pii_audit_log()` added to `src/gateway/governance/pii_sanitizer.py` — ISO 8601 UTC timestamps, FISMA AU-11 90-day retention field, entity-type counts, sanitized-text hash. `compliance/lula/lula-validation-ai600-data-privacy.yaml` stub created. 18 unit tests pass (`tests/test_pii_audit_log.py`). Remaining: (1) Conduct Carlini et al. extraction attack probe; (2) Raise Presidio `score_threshold` to ≥ 0.5; (3) Add Langfuse trace PII scrubbing policy; (4) Harden Lula stub (Phase 3 §7.5). |
| AI600-003 | SI-3, SI-10, CA-8 | §2.4 Data Poisoning / Prompt Injection | US_FED | Indirect prompt injection via MCP tool responses (market data API, portfolio data, news feeds) is unmitigated. The `get_market_data` MCP tool response is not sanitized before being passed to the LLM context window. Only 14 Tier-1 keywords cover direct injection — semantic obfuscation, Unicode homoglyphs, and multi-turn attacks are not detected. Red team pass threshold (`deflection_score >= 3`) is insufficient for HIGH baseline. No adversarial robustness metric. | AI 600-1 gap analysis | **Critical** | 2026-08-31 | 10d | **In Progress** | ✅ Phase 2 (2026-06-15): `src/gateway/governance/prompt_injection_detector.py` created — 8 structural injection patterns (instruction override, role-play bypass, delimiter injection, system prompt leak, jailbreak escalation, indirect injection, token smuggling, multi-turn persistence). `tests/fixtures/adversarial_prompts.json` created with 15 adversarial prompts. `compliance/lula/lula-validation-ai600-prompt-injection.yaml` stub created. 28 unit tests pass (`tests/test_prompt_injection_detector.py`). Remaining: (1) Add MCP tool response sanitization in `safety.py`; (2) Raise red team threshold to `deflection_score >= 4`; (3) Harden Lula stub (Phase 3 §7.5). |
| AI600-004 | RA-3, SI-12 | §2.6 Harmful Bias | US_FED | No fairness metric or demographic impact assessment exists. The financial advisor LLM may produce systematically different recommendations for different demographic groups — a potential ECOA (Equal Credit Opportunity Act) and Regulation B violation for US_FED financial institutions. No homogenization risk assessment per AI 600-1 §2.6. NRP entity detection in Presidio prevents demographic data from entering LLM context but does not prevent demographically correlated outputs from training data patterns. | AI 600-1 gap analysis | **High** | 2026-11-30 | 8d | Open | No source code changes yet. Remaining: (1) Create `docs/AI_FAIRNESS_ASSESSMENT.md` documenting fairness testing methodology per SR 11-7; (2) Extend `scripts/evaluate_langfuse_traces.py` with demographic fairness metrics; (3) Add quarterly fairness audit to ISCM strategy. |
| AI600-005 | AC-5, AU-3, CA-7 | §2.7 Human-AI Configuration | US_FED | No formal Human Oversight Scope Statement per AI 600-1 §2.5.4. No DEFER queue SLA documented — confidence-starved contexts may remain unresolved indefinitely. No automation bias assessment for the HITL approval interface. No human override audit trail separate from standard OTel spans. Trades below USD 10,000 have no human review option with no documented justification per AI 600-1 §2.5.2 ("actions with real-world consequences"). | AI 600-1 gap analysis | **High** | 2026-09-30 | 6d | **In Progress** | ✅ Phase 2 (2026-06-15): `src/gateway/governance/hitl_escalator.py` created — `EscalationReason` enum (7 reasons incl. `GOVERNANCE_CONFIDENCE_LOW`), `EscalationRequest`/`EscalationRecord` dataclasses, `escalate_to_human()` with Redis DeferQueue (db=1), `should_escalate_for_consensus()` (USD 10,000 threshold), `should_escalate_for_confidence()` (0.95 threshold). `src/gateway/governance/provenance_chain.py` created — SHA-256 cryptographic provenance chain. `docs/AGENTIC_SCOPE_STATEMENT.md` created (SR 26-2 §3.1, AI 600-1 §2.5). `compliance/lula/lula-validation-ai600-human-ai-config.yaml` stub created. 42 unit tests pass (`tests/test_hitl_escalator.py`, `tests/test_provenance_chain.py`, `tests/test_recursive_governance_risk.py`). Remaining: (1) Create `docs/HUMAN_OVERSIGHT_SCOPE.md`; (2) Add human override audit trail to OTel span schema; (3) Harden Lula stub (Phase 3 §7.5). |
| AI600-006 | CA-8, RA-5, SC-7 | §2.9 Information Security | US_FED | No model extraction attack testing in red team dataset. No advanced jailbreak testing (DAN prompts, role-play attacks, many-shot jailbreaking) beyond 14 Tier-1 keywords. vLLM inference API (`VLLM_BASE_URL`, `VLLM_REASONING_API_BASE`) accessible within cluster without authentication layer — an attacker with cluster access can query vLLM directly bypassing the governance pipeline. `CAGE_ROUTING_SEAL_SECRET` bypass (POAM-012) also constitutes an AI 600-1 §2.9 information security gap. | AI 600-1 gap analysis | **High** | 2026-09-30 | 8d | Open | No source code changes yet. Remaining: (1) Add `model_extraction`, `jailbreak_advanced`, `adversarial_financial` categories to `tests/red_team/adversarial_dataset.json`; (2) Add OPA-enforced authentication layer in front of vLLM endpoints; (3) Resolve POAM-012 (HMAC bypass) as prerequisite; (4) Add `control_ids` field to all red team dataset entries. |
| AI600-007 | SA-12, SR-3, SI-7 | §2.12 Value Chain | US_FED | No model weight integrity verification — `scripts/mirror_models.py` downloads DeepSeek-R1 and Llama-3.1 weights without SHA-256 hash verification against a signed manifest. A supply chain attack replacing model weights with a backdoored version would bypass all governance controls. No model card review for either model. Model licenses (DeepSeek-R1 custom license, Meta Llama 3.1 Community License) not formally reviewed for US_FED deployment compatibility. NeMo Guardrails integrity not verified at deployment. Langfuse compliance project is a SaaS single point of failure (see also POAM-018). | AI 600-1 gap analysis | **Critical** | 2026-08-31 | 10d | **In Progress** | ✅ Phase 3 (2026-06-15): `src/gateway/governance/nemo/colang/cbrn_rails.co` created — NeMo Guardrails Colang CBRN rail with 15 CBRN keyword patterns, `define flow cbrn safety check`, POAM AI600-007 annotation, `CAGE_DEPLOYMENT_REGION=US_FED` region guard. `config/governance_thresholds.json` extended with `tier1_keywords_cbrn` (15 terms) and `tier1_keywords_cbrn_enabled: true`. `src/gateway/governance/text_filter.py` extended with `ac_cbrn_keyword_scan()`. `compliance/lula/lula-validation-ai600-cbrn.yaml` stub created (**Cat-M** — requires AO pre-approval before cluster activation). 28 unit tests pass (`tests/test_text_filter_cbrn.py`, `tests/test_nemo_cbrn_rails.py`). Remaining: (1) Add SHA-256 verification to `scripts/mirror_models.py`; (2) Create `docs/MODEL_CARD_REVIEW.md`; (3) Review model licenses for US_FED compatibility; (4) Harden Lula stub (Phase 3 §7.5). |

---

## POA&M Process

### Review Cadence

- **Monthly:** Review open items, update milestones, escalate slipped items
- **Quarterly:** AO briefing on POA&M status; risk acceptance decisions for items requiring schedule extensions
- **Annual:** Full POA&M review as part of annual authorization renewal

### Entry Criteria

New POA&M items are created when:

- Security control assessments identify weaknesses
- Continuous monitoring detects new vulnerabilities
- Penetration testing or red-team exercises identify gaps
- Regulatory changes require new controls
- Automated scanning (Trivy, pip-audit, Lula) identifies compliance failures
- AI 600-1 gap analysis identifies GenAI-specific risk gaps

### Closure Criteria

Items are closed when:

1. Remediation actions are fully implemented
2. Implementation is verified by the ISSO or Security Control Assessor
3. Supporting evidence (code changes, scan results, configuration artifacts) is archived
4. AO is notified of closure for HIGH/CRITICAL items

### Escalation

- Items not remediated by scheduled completion date are escalated to the System Owner
- Critical items overdue by >30 days are escalated to the AO
- Items that cannot be remediated must have a formal risk acceptance signed by the AO

---

_This document is a living record and must be updated within 5 business days of any status change. Unauthorized modification of closed or in-progress items requires ISSO concurrence. This file supersedes `docs/POAM.md` (v1.7, 2026-06-08), POAM_US_FED v2.0 (2026-06-08), and POAM_US_FED v2.1 (2026-06-15). For the cross-region traceability matrix, see [`docs/POAM_INDEX.md`](POAM_INDEX.md). For the AI 600-1 gap analysis that generated AI600-xxx items, see [`docs/NIST_AI_600_1_US_FED_ANALYSIS.md`](NIST_AI_600_1_US_FED_ANALYSIS.md). For the full AI 600-1 implementation plan and phase roadmap, see [`docs/AI_600_1_IMPLEMENTATION_PLAN.md`](AI_600_1_IMPLEMENTATION_PLAN.md)._
