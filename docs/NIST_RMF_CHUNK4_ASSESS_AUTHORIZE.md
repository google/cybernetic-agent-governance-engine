# NIST RMF Steps 5–6 Gap Analysis & Refactoring Recommendations

## Cybernetic Governance Engine — Chunk 4 of 5: Assess & Authorize

**Document Date:** 2026-03-06
**System Categorization:** C=Moderate / I=High / A=Moderate → **NIST SP 800-53 Rev 5 HIGH Baseline**
**Prior Chunk Scores:** Step 1–2 Readiness: 28/100 | Step 3–4 Readiness: 29/100
**Scope:** RMF Steps 5 (Assess Controls) and 6 (Authorize System)

---

## Table of Contents

1. [5.1 — Security Assessment Plan (SAP)](#51--security-assessment-plan-sap)
2. [5.2 — Security Assessment Report / Evidence Collection](#52--security-assessment-report--evidence-collection)
3. [5.3 — Penetration Testing / Red Team Coverage](#53--penetration-testing--red-team-coverage)
4. [5.4 — Control Effectiveness Metrics](#54--control-effectiveness-metrics)
5. [5.5 — Third-Party and Supply Chain Assessment](#55--third-party-and-supply-chain-assessment)
6. [6.1 — Authorization Package Completeness](#61--authorization-package-completeness)
7. [6.2 — Risk Acceptance Decision Support](#62--risk-acceptance-decision-support)
8. [6.3 — Ongoing Authorization / Continuous ATO](#63--ongoing-authorization--continuous-ato)
9. [6.4 — Authorization Boundary Documentation](#64--authorization-boundary-documentation)
10. [Authorization Package Inventory Table](#authorization-package-inventory-table)
11. [Assessment Coverage Matrix](#assessment-coverage-matrix)
12. [cATO Readiness Checklist](#cato-readiness-checklist)
13. [Step 5–6 Readiness Score](#step-56-readiness-score)

---

## Step 5 — Assess Controls

### 5.1 — Security Assessment Plan (SAP)

**Current State:**

- [`compliance/oscal/component-definition.yaml`](compliance/oscal/component-definition.yaml) exists as an OSCAL Component Definition v1.0.4 linking 4 ISO 42001 controls (A.5.2, A.5.3, A.9.2, SC-4) to three components (TypeScript Gateway, OPA, NeMo+Presidio). Each `implemented-requirement` links via `rel: lula` to a corresponding Lula validation manifest. This is a **component definition**, not a Security Assessment Plan — it documents what is implemented, not a methodology for assessing whether controls are operating effectively.
- Four Lula validation files ([`compliance/lula/lula-validation-a52.yaml`](compliance/lula/lula-validation-a52.yaml), [`lula-validation-a53.yaml`](compliance/lula/lula-validation-a53.yaml), [`lula-validation-a92.yaml`](compliance/lula/lula-validation-a92.yaml), [`lula-validation-sc4.yaml`](compliance/lula/lula-validation-sc4.yaml)) implement automated control assertions using OPA Rego. These function as **automated assessment procedures** for their specific controls (e.g., `safety_rate >= 0.99` for A.5.2, `safety_rate == 1.0` zero-tolerance for A.9.2).
- [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py) implements a deterministic 5-step pipeline (persist → parse → ingest → alert → advise) that constitutes an automated assessment execution engine. Steps 1–4 are explicitly LLM-free to preserve audit integrity.
- [`src/compliance_bridge/oscal_parser.py`](src/compliance_bridge/oscal_parser.py) parses OSCAL Assessment Result YAML from `lula validate` output into typed `OscalFinding` objects, then ingests them into a separate Langfuse compliance project with per-control scores.

**Gaps Identified:**

1. **No formal SAP document exists.** A SAP for a HIGH-baseline system must include: assessment scope, assessment team roles and independence requirements, assessment schedule, control-by-control test methodology for all ~400 HIGH-baseline SP 800-53 controls, evidence collection procedures, and reporting format. None of these exist.
2. **4 Lula validations cover ISO 42001 controls only.** The Lula files assert A.5.2, A.5.3, A.9.2, and SC-4 (a custom system constraint). They have **zero coverage** of NIST SP 800-53 control families such as AC, IA, SC-8, AU, RA, CA, CM, IR, and SI. A HIGH baseline requires ~300+ automated or manual test procedures.
3. **No assessment methodology for non-automated controls.** There is no procedure for assessing AC-2 (Account Management), IA-5 (Authenticator Management), SC-8 (Transmission Confidentiality), IR-4 (Incident Handling), or RA-5 (Vulnerability Scanning). The Lula framework is not extended to SP 800-53.
4. **No assessor independence statement.** SP 800-53A requires an independent assessor or assessment team. Current automated assessments are performed by the same system that implements the controls — no separation of concerns is documented.
5. **`oscal/component-definition.yaml` source field points to ISO 42001, not SP 800-53.** The `source: "https://www.iso.org/standard/81230.html"` in every `control-implementation` block means the OSCAL toolchain has no linkage to NIST control catalogs.

**Refactoring Recommendations:**

1. Create `docs/SECURITY_ASSESSMENT_PLAN.md` (SAP) including: scope statement covering all SP 800-53 Rev 5 HIGH-baseline controls, assessment methodology (Lula for automated, manual interview/examination procedures for the remainder), assessor independence statement, schedule tied to the Lula CronJob cadence (every 6h automated; annual manual review), and evidence retention policy pointing to the `OSCAL_S3_BUCKET`.
2. Add a NIST SP 800-53 profile import to `compliance/oscal/component-definition.yaml`: change `source:` from the ISO URL to `"https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json"`. This unlocks OSCAL toolchain validation against the HIGH profile.
3. Create a `compliance/lula/` subdirectory `sp800-53/` and add initial Lula validations for the 5 highest-risk controls: `lula-au12.yaml` (AU-12 audit record generation — verify OTel spans are emitted), `lula-sc8.yaml` (SC-8 — verify TLS on ingress), `lula-ac3.yaml` (AC-3 — verify OPA allow/deny decisions are logged), `lula-ra5.yaml` (RA-5 — verify trivy scan job exists in CI), `lula-ia3.yaml` (IA-3 — verify mTLS policy is present).
4. Extend `compliance/oscal/component-definition.yaml` to add a fourth component representing the Lula audit infrastructure itself (the assessor), with its own `responsible-roles` entry carrying role-id `assessor` to establish documented assessor role separation.

---

### 5.2 — Security Assessment Report (SAR) / Evidence Collection

**Current State:**

- [`src/compliance_bridge/storage.py`](src/compliance_bridge/storage.py) implements durable OSCAL artifact persistence to S3-compatible GCS (`gs://<OSCAL_S3_BUCKET>/oscal-artifacts/<date>/<auditId>.yaml`). SHA-256 content digests are stored as object metadata (`x-content-sha256`). This is conditional on `OSCAL_S3_ENDPOINT` being set — without it, a `WARNING` log is emitted and persistence is silently skipped.
- [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py) Step 3 ingests `OscalFinding` records into a dedicated Langfuse **compliance project** (separate from the application metrics project) with per-control scores (`iso42001.<controlId>.compliant` scored 0.0 or 1.0). Audit metadata includes `audit_id`, `artifact_key`, `standard`, and UTC timestamp. This constitutes a **partial SAR** — it records control assessment results but lacks narrative findings, risk ratings, and recommendations sections required by SP 800-53A for a formal SAR.
- [`src/compliance_bridge/metrics.py`](src/compliance_bridge/metrics.py) maintains a 5-minute TTL cache of `ComplianceMetrics` per control, including `safety_rate`, `total_traces`, `blocked_traces`, `evidence_age_seconds`, and `startup_grace_active`. These are the live metrics that Lula OPA rules evaluate — direct evidence of control operation.
- [`src/compliance_bridge/sse_events.py`](src/compliance_bridge/sse_events.py) publishes `AUDIT_FINDING` and `GOVERNANCE_VIOLATION` events in real-time to SSE subscribers. These events carry `controlId`, `result`, `safetyRate`, and `auditId` — representing a real-time SAR stream rather than a persisted report artifact.
- The 28 test files in `tests/` produce pytest results, but there is **no mechanism linking test outcomes to SAR control assertions**. Test results are not mapped to SP 800-53 control IDs and are not ingested into the compliance project.

**Gaps Identified:**

1. **No formal SAR artifact exists.** A HIGH-baseline SAR requires a structured document with: executive summary, detailed findings per control, risk ratings (High/Moderate/Low/Not a Finding), assessor notes, and a reconciliation with the POA&M. Only control pass/fail scores exist in Langfuse.
2. **OSCAL artifact persistence is conditional and unverified.** Storage silently skips if `OSCAL_S3_ENDPOINT` is not set. There is no alerting or CI check to verify that artifact persistence is actually occurring — the evidence may not be durable.
3. **Test results are not linked to control assertions.** The 28 pytest test files have no `@pytest.mark` tags mapping tests to SP 800-53 control IDs. OSCAL Assessment Results cannot reference specific test execution evidence.
4. **Compliance Langfuse project is a separate credential from the main project.** `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` must be configured. If these env vars are absent, the compliance project fails silently — a critical evidence collection gap.
5. **Step 5 (LLM remediation) is in the audit pipeline.** While Steps 1–4 are deterministic, Step 5 injects an LLM call that writes to the Langfuse compliance project with `"human_review_required": True` metadata. This creates a risk that LLM-generated content could be mistaken for authoritative findings in a formal audit.

**Refactoring Recommendations:**

1. Create `compliance/sar/` directory and a formal `compliance/sar/SAR_TEMPLATE.md` that maps Langfuse compliance scores to the NIST SP 800-53A SAR format. Add a script `scripts/generate_sar.py` that pulls the last 30-day Langfuse compliance project scores and renders a Markdown SAR with per-control findings.
2. Add a startup health check in `src/compliance_bridge/main.py` that verifies `OSCAL_S3_ENDPOINT`, `OSCAL_S3_BUCKET`, `LANGFUSE_COMPLIANCE_PUBLIC_KEY`, and `LANGFUSE_COMPLIANCE_SECRET_KEY` are set — and exposes a `/v1/health/evidence-storage` endpoint returning `{"s3_configured": bool, "langfuse_compliance_configured": bool}`.
3. Add pytest markers to all test files mapping to SP 800-53 control families. Example for `tests/test_opa_client.py`: `@pytest.mark.sp800_53(["AC-3", "SC-7"])`. Generate an OSCAL Assessment Results file from pytest-xml output via a CI step.
4. Add a CI pipeline step (GitHub Actions / Cloud Build) that fails if `OSCAL_S3_ENDPOINT` is not configured in the deployment environment and the last 7 days contain no artifacts in `gs://<OSCAL_S3_BUCKET>/oscal-artifacts/`.
5. Separate `audit_workflow.py` Step 5 into a standalone `remediation_advisor.py` module invoked by a separate endpoint (`POST /v1/audit/advise`), keeping the core 4-step audit pipeline free of any LLM interaction and making the SAR evidence chain fully deterministic.

---

### 5.3 — Penetration Testing / Red Team Coverage

**Current State:**

- [`tests/red_team/adversarial_red_team.py`](tests/red_team/adversarial_red_team.py) is a comprehensive live-fire adversarial evaluation suite with 5 attack categories: `pii_injection`, `prompt_injection`, `rbac_escalation`, `harmful_financial`, `compound_attack`. It fires payloads at the gateway, uses an LLM judge (DeepSeek-R1) to score deflection (1–5 rubric), inspects Langfuse traces for PII leakage, and verifies NeMo Guardrails and OPA span markers. Scores are pushed back to Langfuse.
- [`tests/red_team/adversarial_dataset.json`](tests/red_team/adversarial_dataset.json) contains structured attack payloads (290 lines, metadata indicates v1.0.0 created 2026-02-23) including PII-001 through PII-004 (SSN, credit card, multi-PII, disguised SSN injection) and additional categories. Each payload carries `expected_behavior`, `severity` (critical/high), and PII ground truth values.
- [`tests/red_teaming/test_adversarial.py`](tests/red_teaming/test_adversarial.py) provides unit-level adversarial tests using `SymbolicGovernor` and `STPAValidator`: `test_red_agent_latency_attack` (UCA-2: stale data → trade block), `test_red_agent_authorization_attack` (UCA-1: missing approval_token → block), and `test_red_agent_random_attack_resilience` (5-iteration fuzzing). These use mocked OPA and consensus engines.
- [`tests/governance/test_automated_loop.py`](tests/governance/test_automated_loop.py) and [`test_nemo_refinements.py`](tests/governance/test_nemo_refinements.py) cover NeMo action unit tests: slippage blocking/allowing, drawdown limits, approval token signature validation, data latency freshness/staleness, and atomic execution audit trail checks.

**Gaps Identified:**

1. **Red team tests are not mapped to specific SP 800-53 controls.** The adversarial dataset has categories but no `control_id` field linking attacks to the controls they stress (e.g., PII injection → IA-3/SC-8, RBAC escalation → AC-3/AC-6, prompt injection → SI-10/SI-3).
2. **No infrastructure-level penetration testing.** All red team coverage is AI-specific (prompt injection, PII, RBAC in the application layer). There are no tests for: network-level attacks (port scanning, lateral movement), Kubernetes API server access, etcd access, container escape, supply chain compromise, or secrets exposure. This is a critical gap for a HIGH-baseline system.
3. **Red team is a standalone script, not integrated into CI.** `tests/red_team/adversarial_red_team.py` requires a live backend and is not run in CI (`--dry-run` mode exists but bypasses all actual testing). There is no CI gate that fails on red team regression.
4. **No formal penetration test methodology document exists.** SP 800-53A CA-8 requires a documented penetration testing approach including scope, rules of engagement, methodology, and frequency. None of these exist.
5. **LLM judge score threshold for pass/fail is `deflection_score >= 3`** — a 3/5 rubric score means the system may partially leak information and still pass. This threshold is insufficiently strict for a HIGH-baseline system handling financial PII.
6. **Mock-based unit tests in `test_adversarial.py` use mock OPA and consensus engines**, meaning they test the `SymbolicGovernor` orchestration logic but not the actual policy enforcement in the deployed OPA sidecar.

**Refactoring Recommendations:**

1. Add a `control_ids` field to each entry in `tests/red_team/adversarial_dataset.json` mapping attacks to SP 800-53 control IDs. Example: `"control_ids": ["SI-10", "SC-23", "IA-3"]` for prompt injection payloads. This enables test-to-control traceability in OSCAL Assessment Results.
2. Create `tests/red_team/README.md` as a formal penetration test methodology document covering: scope (AI application layer + Kubernetes API surface), rules of engagement, LLM-judge rubric justification, frequency (quarterly + after major releases), and out-of-scope items. This satisfies CA-8 documentation requirements.
3. Create `tests/infra/` directory with infrastructure-level security tests: `test_network_segmentation.py` (verify NetworkPolicy blocks disallowed traffic using `kubectl exec` and `curl`), `test_secrets_exposure.py` (verify secrets are not in environment variable logs), `test_rbac_k8s.py` (verify service account permissions are minimal using `kubectl auth can-i`).
4. Add a CI integration test stage (nightly) that runs `adversarial_red_team.py --dry-run` on every PR and the full live-fire suite weekly against a staging cluster. Fail the pipeline if `deflection_score < 4` (raise from 3) for any `severity: critical` payload.
5. Raise the pass threshold in `adversarial_red_team.py` line 605 from `deflection_score >= 3` to `deflection_score >= 4` for `severity: critical` payloads, and add a separate `pii_leaked_in_trace` hard fail that is independent of the deflection score.

---

### 5.4 — Control Effectiveness Metrics

**Current State:**

- [`src/compliance_bridge/metrics.py`](src/compliance_bridge/metrics.py) computes `ComplianceMetrics` per control from Langfuse traces: `safety_rate` (PASSED / total), `total_traces`, `blocked_traces`, `evidence_age_seconds`, and `startup_grace_active`. A 5-minute TTL cache prevents repeated DB scans. This is **the primary quantitative control effectiveness metric** in the system.
- [`fetch_langfuse_metrics.py`](fetch_langfuse_metrics.py) fetches GENERATION and SPAN observations to compute average TTFT (time-to-first-token) and overhead span latencies. This is a **latency/performance metric**, not a control effectiveness metric — no control IDs are referenced.
- [`scripts/evaluate_langfuse_traces.py`](scripts/evaluate_langfuse_traces.py) runs an LLM-as-Judge evaluation against production traces tagged `production`, scoring `llm_judge_quality` (0.0–1.0) and pushing scores back to Langfuse. This measures **response quality**, not security control effectiveness.
- Control-specific effectiveness metrics exist only for the 4 Lula-validated controls (A.5.2 safety_rate ≥ 0.99, A.5.3 safety_rate ≥ 0.98, A.9.2 safety_rate = 1.0, SC-4 ConfigMap label presence). There are no effectiveness metrics for AC, IA, RA, IR, CM, or SC families.

**Gaps Identified:**

1. **No false-positive rate metric.** The `safety_rate` metric only measures whether traces passed governance checks — it does not measure how many legitimate requests were incorrectly blocked (false positives). A system blocking 100% of requests would have a perfect `safety_rate` but zero utility.
2. **No audit coverage rate metric.** There is no metric measuring what percentage of all AI inference requests have a corresponding OTel span tagged with an ISO 42001 or SP 800-53 control ID. This is the `AU-12` coverage rate — critical for HIGH-baseline audit completeness.
3. **`fetch_langfuse_metrics.py` and `evaluate_langfuse_traces.py` produce no machine-readable output** — they print to stdout. There is no structured JSON or OSCAL-compatible output that could be fed into a compliance dashboard or SAR.
4. **Control effectiveness is measured only over 24-hour windows.** The `window_hours=24` default in `get_compliance_metrics()` provides no trend analysis (weekly, monthly, quarterly) — required for demonstrating control stability over time for ATO.
5. **No policy enforcement rate metric for OPA.** There is no metric counting the total number of OPA policy evaluations vs. DENY decisions — the OPA decision log is captured but not aggregated into a control effectiveness score for AC-3/AC-6.

**Refactoring Recommendations:**

1. Add `false_positive_rate` to `ComplianceMetrics` in [`src/compliance_bridge/types.py`](src/compliance_bridge/types.py): query traces tagged with both `iso_42001_outcome=BLOCKED` AND `user_feedback=legitimate` (or a similar signal). Expose via `/v1/metrics/<controlId>?include_fp=true`.
2. Add an `audit_coverage_rate` endpoint to `src/compliance_bridge/main.py`: `GET /v1/metrics/coverage` returning `{"total_traces_24h": int, "traced_with_control_id": int, "coverage_pct": float}`. This directly measures AU-12 compliance.
3. Add `window_hours` parameter to all Lula validation manifests and the compliance-bridge metrics endpoint, supporting 7-day (`168h`) and 30-day (`720h`) windows. Store historical snapshots in the S3 bucket as `oscal-artifacts/trends/<year-month>/<controlId>.json`.
4. Add OPA decision log aggregation: configure OPA's `decision_logs` plugin to POST to a `src/compliance_bridge/` endpoint (`POST /v1/opa-decisions`), aggregating `allow/deny` ratios per policy rule into a `PolicyEffectivenessMetric` and scoring it in the compliance Langfuse project as `sp800_53.AC-3.enforcement_rate`.
5. Refactor `fetch_langfuse_metrics.py` and `evaluate_langfuse_traces.py` to emit structured JSON output to files in `compliance/evidence/` (e.g., `compliance/evidence/quality_scores_<date>.json`) to enable traceability in the SAR.

---

### 5.5 — Third-Party and Supply Chain Assessment

**Current State:**

- [`src/governed_financial_advisor/requirements.txt`](src/governed_financial_advisor/requirements.txt) uses **unpinned ranges**: `langgraph>=0.4.0`, `langchain>=0.3.0`, `nemoguardrails>=0.17.0`, `pydantic>=2.0.0`, `opentelemetry-api>=1.39.1`. No lockfile (`requirements.lock` or `poetry.lock`) is referenced in this file — version drift is possible with every fresh install.
- [`src/compliance_bridge/requirements.txt`](src/compliance_bridge/requirements.txt) exists separately (referenced in Dockerfile). The compliance bridge has its own dependency tree not consolidated with the main project.
- No `pyproject.toml` was found at project root — the project uses standalone `requirements.txt` files. This means no centralized dependency management tool (Poetry, PDM, pip-tools) is enforcing lock files.
- The vLLM model supply chain (DeepSeek-R1-Distill-Llama-8B, Meta-Llama-3.1-8B-Instruct) is pulled via `scripts/mirror_models.py` to MinIO/GCS. There is no SBOM, model card verification, or cryptographic integrity check for the model weights.
- [`deployment/docker/`](deployment/) contains build configs (referenced in `deploy_all.sh`). No `cloudbuild.vllm.yaml` was found; the build config is `deployment/opa_config.yaml` and deploy scripts. No Trivy, Grype, or Snyk scan step was found in any CI/CD config.
- [`deployment/terraform/`](deployment/terraform/) manages GKE, IAM, networking, and secrets infrastructure. No SBOM or `terraform-providers-lock.hcl` pinning was observed in the file listing.

**Gaps Identified:**

1. **No Software Bill of Materials (SBOM).** Neither CycloneDX nor SPDX SBOMs exist for any container image. This is required by NIST SP 800-161r1 (Supply Chain Risk Management) and increasingly mandated for federal systems.
2. **No container vulnerability scanning in CI.** There is no Trivy, Grype, Snyk, or equivalent scan in any CI/CD pipeline. For a HIGH-baseline system, RA-5 requires automated vulnerability scanning of all components.
3. **Dependency versions are unpinned ranges** (`>=`). This permits automatic inclusion of newly released (potentially malicious or broken) package versions. Lock files (`requirements.lock` or `poetry.lock`) do not exist.
4. **Model supply chain is undocumented.** The vLLM model weights (DeepSeek-R1-Distill-Llama-8B) are mirrored via `scripts/mirror_models.py` with no hash verification, model card reference, or attestation. A malicious model weight file would bypass all governance controls.
5. **No third-party component risk assessment.** There is no documented assessment of the risk posed by critical third-party dependencies: NeMo Guardrails (NVIDIA), OPA (CNCF), Langfuse (startup), LangGraph (LangChain Inc.). For a HIGH-baseline system, SA-9 requires documented third-party component risk.

**Refactoring Recommendations:**

1. Add a `scripts/generate_sbom.sh` script using `syft` to generate CycloneDX SBOMs for all Docker images post-build. Store SBOMs in `compliance/sbom/` (e.g., `compliance/sbom/compliance-bridge-<version>.json`). Reference SBOM URIs in `compliance/oscal/component-definition.yaml` `back-matter.resources`.
2. Add a Trivy scan step to the CI/CD pipeline (`.github/workflows/security-scan.yml` or `deployment/cloudbuild.yaml`): `trivy image --exit-code 1 --severity CRITICAL,HIGH <image>`. Block deployment on CRITICAL CVEs with no available fix.
3. Convert `src/governed_financial_advisor/requirements.txt` and `src/compliance_bridge/requirements.txt` to pinned lockfiles using `pip-compile` (pip-tools). Add a CI step that fails if `requirements.txt` differs from the generated lockfile.
4. Add SHA-256 verification to `scripts/mirror_models.py`: after downloading model weights, verify against a hardcoded expected hash in `config/model_hashes.json`. Log the verification result as an OTel span with attribute `supply_chain.model_integrity_verified=true/false`.
5. Create `docs/SUPPLY_CHAIN_RISK_ASSESSMENT.md` documenting: the 5 highest-risk third-party dependencies (NeMo, OPA, Langfuse, LangGraph, vLLM), the risk rating for each, the mitigating controls (version pinning, SBOM, vulnerability scanning), and the escalation procedure if a critical CVE is found in a dependency.

---

## Step 6 — Authorize System

### 6.1 — Authorization Package Completeness

**Current State:**

- [`docs/SYSTEM_DESCRIPTION_ISO_42001.md`](docs/SYSTEM_DESCRIPTION_ISO_42001.md) provides a systems-theoretic description mapping CAGE components to the Viable System Model and ISO 42001 clauses. It contains an informal component description and control telemetry mapping but **is not a NIST-format System Security Plan (SSP)**. No security control summary tables, FIPS 199 categorization, or inheritance designations are present.
- [`docs/DEPLOYMENT_DECISION_RECORD.md`](docs/DEPLOYMENT_DECISION_RECORD.md) contains two Architecture Decision Records (ADR-001: MinIO tensorizer, ADR-002: portability improvements) and infrastructure deployment decisions. This documents _implementation decisions_ but is not a risk assessment or authorization artifact.
- [`docs/proposals/004_risk_remediation_plan.md`](docs/proposals/004_risk_remediation_plan.md) describes three proposed architectural improvements (dynamic policy injection, stateful risk memory, GitOps workflow). This is a _proposal document_ — it identifies risks (latency, statelessness, race conditions) but does not constitute a POA&M with tracking IDs, milestones, or resource estimates.
- **No SSP exists.** No FIPS 199 categorization document exists. No POA&M with formal tracking exists. No Risk Assessment Report (RAR) exists. No authorization letter exists.
- The `compliance/` directory contains OSCAL Component Definition and Lula validations — these support the SSP but are not substitutes for the full authorization package.
- [`deployment/k8s/oscal-artifact-secrets.yaml`](deployment/k8s/oscal-artifact-secrets.yaml) exists — this manages secrets for OSCAL storage but is a deployment artifact, not an authorization artifact.

**Gaps Identified:**

1. **System Security Plan (SSP) — Missing.** The SSP is the foundational authorization artifact. It must include: system identification (name, version, purpose), FIPS 199 categorization, system boundary, network diagram, user types and access, hardware/software inventory, SP 800-53 control implementation statements for all ~300 HIGH-baseline controls, and control inheritance designations.
2. **FIPS 199 Categorization Document — Missing.** The categorization (C=Moderate, I=High, A=Moderate → HIGH overall) is inferred from Chunk 2 analysis but has never been formally documented and signed by a System Owner.
3. **POA&M — Missing as formal artifact.** `docs/proposals/004_risk_remediation_plan.md` identifies 3 risks informally. A formal POA&M requires: unique finding IDs, weakness descriptions, responsible POC, scheduled completion dates, milestones with interim dates, required resources, and status tracking.
4. **Security Assessment Plan (SAP) — Missing** (see §5.1).
5. **Security Assessment Report (SAR) — Missing as formal artifact** (see §5.2); only Langfuse scores exist.
6. **Risk Assessment Report (RAR) — Missing.** No document performs threat modeling, likelihood/impact analysis, or residual risk determination against SP 800-53 HIGH-baseline requirements.

**Refactoring Recommendations:**

1. Create `compliance/ssp/SYSTEM_SECURITY_PLAN.md` using the FedRAMP SSP template as a baseline. Minimum viable SSP sections: system overview (from `SYSTEM_DESCRIPTION_ISO_42001.md`), FIPS 199 categorization, authorization boundary diagram (from `ARCHITECTURE.md`), control summary table referencing Lula validations for the 4 automated controls, and "planned" or "inherited" designations for remaining ~296 HIGH-baseline controls.
2. Create `compliance/categorization/FIPS199_CATEGORIZATION.md` with: system name, mission/business function, information types (financial data → I=High, audit logs → A=Moderate), NIST SP 800-60 Vol II mapping, and the resulting overall categorization. This must be signed by System Owner.
3. Convert `docs/proposals/004_risk_remediation_plan.md` to a formal POA&M at `compliance/poam/POA_AND_M.md` using NIST SP 800-18 Appendix A format: finding ID (e.g., CAGE-2026-001 through CAGE-2026-010 covering all Chunk 3 identified gaps), weakness, responsible POC, scheduled completion, milestones, and resources.
4. Create `compliance/rar/RISK_ASSESSMENT_REPORT.md` documenting: threat sources (insider threat, supply chain, adversarial AI prompt injection), threat events, vulnerabilities (the gaps from Chunks 1–4), likelihood determinations (L/M/H), impact determinations referencing FIPS 199 categorization, and overall risk ratings.
5. Once the above artifacts exist, create `compliance/authorization/AUTHORIZATION_MEMO.md` as a placeholder ATO letter template for the Authorizing Official (AO) signature.

---

### 6.2 — Risk Acceptance Decision Support

**Current State:**

- [`config/governance_thresholds.json`](config/governance_thresholds.json) is the single source of truth for operational risk thresholds: `drawdown.limit=0.05` (5% max portfolio drawdown), `stpa.uca5_drawdown_threshold_pct=4.5`, `stpa.uca6_max_order_volume_fraction=0.01` (1% daily volume), `stpa.max_latency_ms=200`, `confidence.min_trade_confidence=0.95`, `consensus.threshold_usd=10000`. This file is Pydantic-validated at gateway startup via [`src/gateway/governance/schemas/thresholds.py`](src/gateway/governance/schemas/thresholds.py) — missing or invalid values abort startup with `sys.exit(1)`.
- [`src/gateway/governance/schemas/thresholds.py`](src/gateway/governance/schemas/thresholds.py) implements `load_and_validate_thresholds()` with `@lru_cache(maxsize=1)` — the threshold singleton is loaded once at startup. Validation logs are emitted confirming `drawdown=5%, confidence=0.95, consensus_usd=$10,000`. These thresholds map to specific STPA Unsafe Control Actions (UCA-1 through UCA-6).
- Risk thresholds are **technically enforced** via OPA Rego policies (`trade_governance.rego`), NeMo actions (`check_drawdown_limit`, `check_slippage_risk`), and the CBF (`min_cash_balance=1000`, `gamma=0.5`).
- **No traceability exists from threshold values to an authorization decision.** The values in `governance_thresholds.json` were chosen by engineers but are not traced to a formal risk acceptance statement, AO decision, or regulatory mapping (e.g., FINRA Rule 4370, SR 11-7 supervisory expectations for AI models in financial services).
- No residual risk statement exists. The system does not document what risk remains after controls are applied — the AO cannot make an informed authorization decision without this.

**Gaps Identified:**

1. **Risk thresholds are not traceable to an authorization decision.** The 5% drawdown limit and $10,000 consensus threshold appear to be engineering decisions. There is no documented risk acceptance rationale connecting these values to the AO's risk tolerance or regulatory requirements.
2. **No residual risk statement.** After applying all controls (OPA, NeMo, CBF, STPA), the system does not compute or document residual risk — the risk remaining after controls are factored. This is essential for AO decision-making.
3. **CAGE_ROUTING_SEAL_SECRET bypass (from Chunk 3).** The HMAC seal can be silently disabled. This is an unmitigated risk that is not formally captured in any risk acceptance document.
4. **No connection between `governance_thresholds.json` values and SR 11-7 / FINRA requirements.** The system handles financial advisory AI — SR 11-7 (Federal Reserve guidance on AI models in financial services) has specific model risk management requirements that these thresholds should map to.

**Refactoring Recommendations:**

1. Add a `_rationale` comment to each threshold in `governance_thresholds.json` explaining the risk basis. Example: `"drawdown.limit": 0.05, "_rationale": "SR 11-7 model risk: 5% drawdown limit is consistent with FINRA Rule 4370 catastrophic loss thresholds for retail accounts. AO-accepted 2026-QQ."`.
2. Create `compliance/risk_acceptance/RISK_ACCEPTANCE_STATEMENT.md` documenting: each residual risk, its likelihood and impact (using the FIPS 199 impact levels), the mitigating control(s), the AO's acceptance decision, and the acceptance date. This converts the engineering threshold values into an auditable authorization artifact.
3. Create `compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md`: a table mapping each `governance_thresholds.json` value → STPA UCA → SP 800-53 control → SR 11-7 requirement → AO acceptance.
4. Fix the HMAC seal bypass gap (from Chunk 3): make `CAGE_ROUTING_SEAL_SECRET` absence a hard failure at gateway startup (not a warning), and add this as finding CAGE-2026-003 in the formal POA&M with `IMMEDIATE` urgency classification.

---

### 6.3 — Ongoing Authorization / Continuous ATO

**Current State:**

- [`deployment/k8s/lula-cron.yaml`](deployment/k8s/lula-cron.yaml) **exists** and implements a Kubernetes CronJob (`schedule: "0 */6 * * *"` — every 6 hours) running `lula validate` against all 4 ISO 42001 control manifests, writing OSCAL Assessment Result YAML, and POSTing to `POST /v1/audit/ingest` on the compliance-bridge. This is a **functional cATO triggering mechanism** for the 4 automated controls.
- A second Kubernetes Deployment `lula-sc4-watch` performs **real-time continuous monitoring** for SC-4 (OPA ConfigMap label), polling every 60 seconds with a liveness probe. This demonstrates near-event-driven continuous monitoring for a structural control.
- The CronJob uses `concurrencyPolicy: Forbid` (prevents overlapping runs), `successfulJobsHistoryLimit: 3`, and `failedJobsHistoryLimit: 5`. The audit ID is the Unix timestamp, providing idempotency via the storage layer HEAD check.
- [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py) Step 3b publishes `AUDIT_FINDING` events via SSE in real time — the KernelDashboard receives continuous audit state updates without polling.
- The Kubeflow Pipelines `green_stack_pipeline.py` (referenced in `ARCHITECTURE.md`) provides a continuous governance evaluation loop: fetch compliance metrics → evaluate ISO 42001 thresholds → trigger NeMo Guardrails refinement. This is a **feedback control loop** for cATO.

**Gaps Identified:**

1. **Continuous monitoring covers only 4 of ~300 HIGH-baseline controls.** The Lula CronJob provides meaningful cATO evidence for A.5.2, A.5.3, A.9.2, and SC-4. The remaining ~296 controls have no continuous monitoring — they are assessed only once during initial authorization (if at all).
2. **No cATO boundary or scope document exists.** NIST SP 800-137 requires a documented Information Security Continuous Monitoring (ISCM) strategy defining: monitoring objectives, monitoring tiers (organization/mission/information system), monitoring frequencies, and reporting mechanisms. None exists.
3. **Lula CronJob image uses a `${REGISTRY_URL}` template variable** — the actual image `${REGISTRY_URL}/lula:0.9.5` must be resolved at deployment time. If this variable is not substituted, the CronJob will fail silently. No CI check validates this substitution.
4. **No alert escalation SLA is defined.** When `_step4_alert_on_critical_fail()` fires, alerts go to Slack/PagerDuty via `create_notifier()`. There is no documented SLA for alert acknowledgment, triage, and remediation — required for cATO.
5. **The `lula-auditor` ServiceAccount RBAC** is defined in `deployment/k8s/lula-rbac.yaml` (referenced in lula-cron.yaml) — this grants Kubernetes API access for SC-4 validation. The actual RBAC permissions were not read — if over-privileged, this represents an IA-5/AC-6 gap.

**Refactoring Recommendations:**

1. Create `docs/CONTINUOUS_MONITORING_STRATEGY.md` per NIST SP 800-137 Section 3: monitoring objectives (maintain ATO, detect control degradation), monitoring frequencies (Tier 3: every 6h for critical AI controls, daily for k8s runtime controls, quarterly for IAM/CM), reporting mechanisms (Langfuse compliance project + SSE dashboard), and ISCM program roles.
2. Extend the Lula CronJob to cover SP 800-53 controls by adding new validation manifests for the top 10 automatable controls (AU-12, SC-8, AC-3, CM-6, RA-5, SI-4, IA-3, SC-7, CM-7, SA-9) to `compliance/lula/sp800-53/` and referencing them in the CronJob's `lula-validation-manifests` ConfigMap.
3. Add a CI step that validates `${REGISTRY_URL}` substitution in `lula-cron.yaml` before deployment: `envsubst < deployment/k8s/lula-cron.yaml | kubectl apply --dry-run=client -f -`.
4. Define alert response SLAs in `docs/CONTINUOUS_MONITORING_STRATEGY.md`: CRITICAL control failures (A.9.2 PII leak, SC-4 OPA offline) → acknowledge within 15 minutes, remediate within 4 hours; HIGH control failures → acknowledge within 1 hour, remediate within 24 hours.
5. Audit `deployment/k8s/lula-rbac.yaml` to ensure the `lula-auditor` ServiceAccount has only `get` and `list` permissions on ConfigMaps in the `default` namespace (for SC-4) — not cluster-wide read access — implementing least privilege (AC-6).

---

### 6.4 — Authorization Boundary Documentation

**Current State:**

- [`ARCHITECTURE.md`](ARCHITECTURE.md) (Revision 8, 2026-03-05) provides an extensive Mermaid component diagram showing: Frontend (agentsight-ui), governed-financial-advisor (LangGraph + FastAPI), green-stack-pipeline (KFP v2), gateway (MCP + OPA + NeMo), compliance-bridge (OSCAL pipeline), and infrastructure (Redis, OPA Server, NeMo, NGINX Gateway, vLLM pools, Langfuse, MinIO/GCS, Lula, OTel). Data flows are documented with protocol labels (REST+SSE, gRPC, HTTP, OTel traces, Langfuse SDK, boto3).
- [`deployment/k8s/network-policy.yaml`](deployment/k8s/network-policy.yaml) implements a default-deny ingress+egress policy for the `governance-stack` namespace with explicit allowlists: gateway port 8080 from `ingress-nginx` and orchestrators only; OPA port 8181 from governance-stack; Redis port 6379; OTLP ports 4317/4318; DNS port 53; vLLM port 8000. This is machine-readable boundary enforcement — **the strongest authorization boundary evidence in the system**.
- [`deployment/k8s/ingress.yaml`](deployment/k8s/ingress.yaml) defines a single ingress: `/agent` → `governed-financial-advisor:80`, `/` → `langfuse-web:80`. HSTS headers and CSP (`default-src 'self'`) are set. Note: `kubernetes.io/ingress.class: "gce"` conflicts with ADR-002 which mandates `nginx` — this is a staleness gap.
- [`deployment/terraform/networking.tf`](deployment/terraform/networking.tf) defines NAT router and NAT config for GKE egress (`ALL_SUBNETWORKS_ALL_IP_RANGES` → `AUTO_ONLY` NAT). NAT log config is enabled (`filter: ERRORS_ONLY`). This is minimalist — no VPC firewall rules, no private cluster configuration, no VPC Service Controls are defined in this file. The full network boundary relies on GKE's default network and the k8s NetworkPolicy.

**Gaps Identified:**

1. **No formal Authorization Boundary Document exists.** SP 800-18 requires a dedicated authorization boundary description with: a boundary diagram, boundary description (narrative), list of external interfaces with their protocols and data types, and clear delineation of what is in-scope vs. leveraged external services. `ARCHITECTURE.md` is an engineering document, not a formal authorization boundary artifact.
2. **External interfaces are not enumerated as a list.** The system communicates with: Langfuse Cloud (if not self-hosted), Google Cloud APIs (Secret Manager, GCS, GKE), HuggingFace (model downloads via `mirror_models.py`), financial data APIs (via MCP tools), and optionally Slack/PagerDuty (alerts). These external interfaces are not formally documented with protocol, authentication, data sensitivity, and risk assessment.
3. **`ingress.yaml` uses `kubernetes.io/ingress.class: "gce"` (GKE-proprietary)** despite ADR-002 mandating migration to NGINX. This inconsistency means the ingress TLS termination configuration is undefined for non-GKE deployments.
4. **No mTLS boundary enforcement** between services within the `governance-stack` namespace. The NetworkPolicy restricts layer-3/4 traffic but does not enforce mutual authentication at layer-7. This is a SC-8(1)/IA-3 gap identified in Chunk 3.
5. **NAT logging is set to `ERRORS_ONLY`** in `networking.tf` — this means successful egress connections to external services are not logged, creating a blind spot for data exfiltration detection (AU-14, SC-7 monitoring).

**Refactoring Recommendations:**

1. Create `compliance/boundary/AUTHORIZATION_BOUNDARY.md` as a formal boundary document: include the `ARCHITECTURE.md` Mermaid diagram (or a simplified version), a narrative boundary description, a numbered list of all external interfaces (Langfuse Cloud API, GCS/GCS S3-compat, HuggingFace CDN, financial data APIs, Slack/PagerDuty), each with protocol, port, authentication mechanism, data sensitivity, and whether data crosses the authorization boundary.
2. Update `deployment/k8s/ingress.yaml` to align with ADR-002: change `kubernetes.io/ingress.class: "gce"` to `kubernetes.io/ingress.class: "nginx"` (or use the `IngressClass` resource). Add TLS configuration with a certificate reference so the boundary's external interface is explicitly TLS-terminated.
3. Create `deployment/k8s/mtls-policy.yaml` using Istio `PeerAuthentication` (if Istio is present) or add mutual TLS configuration to the nginx ingress for service-to-service communication. At minimum, document the mTLS gap in the POA&M as finding CAGE-2026-004.
4. Update `deployment/terraform/networking.tf` to add `filter: "ALL"` to the NAT log config and add GCP VPC firewall rules explicitly allowing only the ports documented in `network-policy.yaml` — creating defense-in-depth at both the VM network layer and the Kubernetes network policy layer.
5. Add an external interface inventory to `compliance/oscal/component-definition.yaml` using the `back-matter.resources` section with `type: external-interface` entries for each external dependency — this gives the OSCAL toolchain visibility into supply chain dependencies at the authorization package level.

---

## Authorization Package Inventory Table

| Artifact                              | Required for ATO    | Status     | Location or Recommended Path                                                             |
| ------------------------------------- | ------------------- | ---------- | ---------------------------------------------------------------------------------------- |
| System Security Plan (SSP)            | ✅ Required         | ❌ Missing | `compliance/ssp/SYSTEM_SECURITY_PLAN.md`                                                 |
| FIPS 199 Categorization               | ✅ Required         | ❌ Missing | `compliance/categorization/FIPS199_CATEGORIZATION.md`                                    |
| Security Assessment Plan (SAP)        | ✅ Required         | ❌ Missing | `docs/SECURITY_ASSESSMENT_PLAN.md`                                                       |
| Security Assessment Report (SAR)      | ✅ Required         | ⚠️ Partial | Langfuse compliance project scores; `compliance/sar/SAR_<date>.md`                       |
| Plan of Action & Milestones (POA&M)   | ✅ Required         | ⚠️ Partial | `docs/proposals/004_risk_remediation_plan.md` (informal); `compliance/poam/POA_AND_M.md` |
| Risk Assessment Report (RAR)          | ✅ Required         | ❌ Missing | `compliance/rar/RISK_ASSESSMENT_REPORT.md`                                               |
| Authorization Boundary Document       | ✅ Required         | ⚠️ Partial | `ARCHITECTURE.md` (informal); `compliance/boundary/AUTHORIZATION_BOUNDARY.md`            |
| Authorization Letter / ATO Memo       | ✅ Required         | ❌ Missing | `compliance/authorization/AUTHORIZATION_MEMO.md`                                         |
| OSCAL Component Definition            | Supporting          | ✅ Exists  | `compliance/oscal/component-definition.yaml`                                             |
| OSCAL Assessment Results (automated)  | Supporting          | ✅ Exists  | Lula CronJob → `gs://<OSCAL_S3_BUCKET>/oscal-artifacts/`                                 |
| Lula Validation Manifests (ISO 42001) | Supporting          | ✅ Exists  | `compliance/lula/lula-validation-a52/a53/a92/sc4.yaml`                                   |
| Lula Validation Manifests (SP 800-53) | Supporting          | ❌ Missing | `compliance/lula/sp800-53/`                                                              |
| Supply Chain Risk Assessment          | Supporting          | ❌ Missing | `docs/SUPPLY_CHAIN_RISK_ASSESSMENT.md`                                                   |
| SBOM (CycloneDX/SPDX)                 | Supporting          | ❌ Missing | `compliance/sbom/<image>-<version>.json`                                                 |
| Continuous Monitoring Strategy        | ✅ Required (cATO)  | ❌ Missing | `docs/CONTINUOUS_MONITORING_STRATEGY.md`                                                 |
| Risk Acceptance Statement             | ✅ Required         | ❌ Missing | `compliance/risk_acceptance/RISK_ACCEPTANCE_STATEMENT.md`                                |
| Threshold Traceability Matrix         | Supporting          | ❌ Missing | `compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md`                            |
| System Description (ISO 42001)        | Supporting          | ✅ Exists  | `docs/SYSTEM_DESCRIPTION_ISO_42001.md`                                                   |
| Deployment Decision Records (ADRs)    | Supporting          | ✅ Exists  | `docs/DEPLOYMENT_DECISION_RECORD.md`                                                     |
| Network Policy (machine-readable)     | Supporting          | ✅ Exists  | `deployment/k8s/network-policy.yaml`                                                     |
| Privacy Impact Assessment             | ⚠️ If PII processed | ❌ Missing | `compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md`                                            |

**Authorization Package Completeness: 5 of 21 artifacts exist (24%)**

---

## Assessment Coverage Matrix

| Control Family                 | Automated Test Coverage                                   | Manual Assessment Coverage | Red Team Coverage                       | Overall Assessment % |
| ------------------------------ | --------------------------------------------------------- | -------------------------- | --------------------------------------- | -------------------- |
| AU — Audit & Accountability    | 35% (OTel span emission; A.5.3 Lula)                      | 0% (no manual review)      | 0%                                      | **12%**              |
| SI — System & Info Integrity   | 15% (NeMo/Presidio unit tests)                            | 0%                         | 10% (prompt injection payloads)         | **8%**               |
| CM — Configuration Management  | 10% (OPA ConfigMap label SC-4 Lula)                       | 0%                         | 0%                                      | **3%**               |
| SC — System & Comms Protection | 10% (NetworkPolicy; TLS headers in ingress)               | 0%                         | 5% (RBAC escalation payloads)           | **5%**               |
| IR — Incident Response         | 5% (SSE alert pipeline Step 4)                            | 0%                         | 0%                                      | **2%**               |
| AC — Access Control            | 20% (OPA RBAC; trade_governance.rego; approval token tests) | 0%                         | 15% (RBAC escalation payloads)          | **12%**              |
| CA — Security Assessment       | 25% (Lula 4-control automated; compliance project)        | 0%                         | 0%                                      | **8%**               |
| IA — Identification & Auth     | 5% (approval token check_approval_token test)             | 0%                         | 5% (auth bypass in test_adversarial.py) | **3%**               |
| RA — Risk Assessment           | 5% (governance_thresholds.json Pydantic validation)       | 0%                         | 0%                                      | **2%**               |
| AI/ISO 42001 Controls          | 80% (4 Lula validations + red team)                       | 0%                         | 30% (adversarial_dataset.json)          | **37%**              |
| **OVERALL**                    | **21%**                                                   | **0%**                     | **8%**                                  | **~16%**             |

> **Note:** ISO 42001 controls are assessed separately from SP 800-53 controls. The 4 Lula validations and comprehensive red team coverage provide strong coverage of the AI-specific control surface (A.5.2, A.5.3, A.9.2, SC-4), but SP 800-53 HIGH-baseline requires coverage of ~300 controls across the families above.

---

## cATO Readiness Checklist

| #   | Checklist Item                                                                  | Status                                           |
| --- | ------------------------------------------------------------------------------- | ------------------------------------------------ |
| 1   | Formal ISCM strategy document exists per SP 800-137                             | ❌                                               |
| 2   | Continuous monitoring scope covers all HIGH-baseline controls (not just 4)      | ❌                                               |
| 3   | Lula CronJob runs every 6h and has been validated in production                 | ✅                                               |
| 4   | Lula SC-4 real-time watch deployment is running                                 | ✅                                               |
| 5   | OSCAL artifact persistence to S3/GCS is configured and verified                 | ⚠️ (conditional on OSCAL_S3_ENDPOINT)            |
| 6   | Compliance Langfuse project is configured with separate credentials             | ⚠️ (env vars required, not validated at startup) |
| 7   | Alert escalation SLAs are defined and documented                                | ❌                                               |
| 8   | Critical control failure alerts are wired to PagerDuty/Slack                    | ✅ (via `create_notifier()`)                     |
| 9   | SSE real-time governance events stream to KernelDashboard                       | ✅                                               |
| 10  | Control effectiveness metrics include trend analysis (7-day, 30-day)            | ❌                                               |
| 11  | False-positive rate is measured and within acceptable bounds                    | ❌                                               |
| 12  | Audit coverage rate (% of traces tagged with control IDs) is measured           | ❌                                               |
| 13  | SP 800-53 controls are included in continuous monitoring scope                  | ❌                                               |
| 14  | Vulnerability scanning runs on every container image build (CI)                 | ❌                                               |
| 15  | Dependency lockfiles exist for all Python services                              | ❌                                               |
| 16  | SBOMs are generated and stored for all container images                         | ❌                                               |
| 17  | Model weight integrity verification (SHA-256) is implemented                    | ❌                                               |
| 18  | Authorization boundary is formally documented with all external interfaces      | ❌                                               |
| 19  | POA&M is formally tracked with finding IDs, milestones, and responsible POCs    | ❌                                               |
| 20  | AO has received and reviewed a continuous monitoring report in the past 30 days | ❌                                               |

**cATO Readiness: 5 of 20 items met (25%)**

---

## Step 5–6 Readiness Score

### Score: **22 / 100**

**Justification:**

The cybernetic-governance-engine demonstrates genuine technical sophistication in its continuous compliance automation infrastructure — the Lula CronJob with 6-hour assessment cadence, the real-time SC-4 watch deployment, the 5-step deterministic OSCAL audit pipeline, and the SSE-based real-time governance event stream are all production-ready components that represent the foundation of a continuous ATO capability. The red team adversarial dataset (290+ payloads across 5 attack categories with LLM judging and Langfuse trace inspection) is particularly strong for an AI system of this type. The `governance_thresholds.json` single-source-of-truth pattern with Pydantic startup validation is excellent engineering practice.

However, the gap between what exists and what is required for a formal authorization decision on a HIGH-baseline system is severe. The authorization package is 24% complete (5 of 21 required artifacts). The most critical missing artifacts — SSP, FIPS 199 categorization, SAP, SAR, POA&M, and RAR — are all absent. Without an SSP, the Authorizing Official has no formal basis for an authorization decision. Without a FIPS 199 document, the HIGH baseline designation is not legally binding. Without a formal POA&M, the identified gaps (mTLS absence, mock trace source, HMAC seal bypass, no vulnerability scanning) have no tracked remediation path.

The assessment coverage is 16% overall — driven upward by strong ISO 42001 AI-control coverage (37%) but dragged down by near-zero coverage of all SP 800-53 control families that would govern a HIGH-baseline federal or regulated-financial system. There is no manual assessment component at all, which is typically required for a HIGH baseline (interviews with system owners, examination of supporting documentation, observation of system operations).

The path to authorization requires: (1) completing the 7 missing authorization package artifacts, (2) extending Lula validations to cover SP 800-53 controls, (3) establishing formal assessor independence, (4) remediating the top 5 control gaps identified in Chunk 3, and (5) an AO signature. These are significant but achievable tasks given the strong technical foundation already in place.

**Score Breakdown:**

- Assessment Methodology (SAP quality): 5/20 (Lula automated procedures exist; no formal SAP)
- Evidence Collection (SAR completeness): 8/20 (Langfuse compliance project exists; no formal SAR)
- Red Team Coverage: 6/20 (strong AI coverage; no infra testing; not in CI)
- Control Effectiveness Metrics: 4/15 (safety_rate exists; no FP rate, coverage rate, trending)
- Supply Chain Assessment: 1/10 (no SBOM, no CVE scanning, unpinned deps)
- Authorization Package Completeness: 4/20 (5 of 21 artifacts; 24%)
- Continuous ATO Infrastructure: 7/15 (CronJob + watch + SSE exist; ISCM strategy missing)

---

_This document is Chunk 4 of 5. Chunk 5 will cover Step 7 (Monitor) and the consolidated implementation roadmap._
