# Changelog

All notable changes to the CAGE reference implementation are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `.github/CODEOWNERS` — single-maintainer review enforcement for architectural paths
- `.github/pull_request_template.md` — reference implementation verification checklist
- `.github/workflows/ref_impl_signoff.yml` — CI gate and release tagging workflow
- `.github/branch-protection-rules.md` — canonical specification for all GitHub
  repository-level protection settings (branch protection, tag protection, GHAS,
  workflow permissions)
- `CHANGELOG.md` — this file

### Changed
- `.github/workflows/dependency-review.yml` — removed `continue-on-error: true` from
  the `Dependency Review` step; the GHAS-backed gate is now a hard block; GHAS
  enablement instructions documented inline
- `.github/workflows/compliance-matrix.yml` — documented rationale for
  `continue-on-error: true` on the regional matrix test step (live-cluster
  dependency); hardening path tracked in workflow comment
- `CONTRIBUTING.md` — added "Repository Protection Setup" section with quick-reference
  GitHub UI settings and link to `.github/branch-protection-rules.md`

---

## [v2.1.1] — 2026-07-30

> 9 commits since v2.1.0 (2026-07-27). Patch release: jurisdiction-aware
> compliance fixes, two production HITL bug fixes, documentation completeness
> audit, and no new features.

### Fixed

- Made `sla_monitor.py` region-aware, closing FINDING-05: jurisdictional SLA
  controls (SC-7/SC-8 for US_FED, Article 12 for EU_ECB, MAS-FEAT-1 for
  APAC_MAS) are now correctly monitored for evidence staleness in their
  applicable region instead of being silently skipped (`fix(compliance)`)
- Removed dead `ftra_reachability.py` scaffold that gave a false impression of
  FTRA test coverage; added 30 direct tests for the real
  `src/gateway/governance/ftra/` implementation, which surfaced and fixed two
  production defects that silently disabled the entire DeferQueue
  human-in-the-loop pathway: `DeferQueue()` instantiated without a required
  `redis_client`, and `NodeInterrupt` unconditionally caught before it could
  suspend the graph for human review (`fix(governance)`)
- Added jurisdiction-aware HITL SLA and PII audit retention citations,
  closing FINDING-07/08/09: `GovernanceThresholds.pii_audit_retention_authority`,
  `pii_audit_log()`, `hitl_escalator.py`, and `prompt_injection_detector.py`
  previously hardcoded US_FED citations (FISMA AU-11, SR 26-2) with no
  runtime region check; now resolve `CAGE_DEPLOYMENT_REGION` at call time to
  the correct GDPR Art. 5(1)(e) / DORA Art. 10 / MAS Notice 655 / MAS FEAT
  citation (`fix(governance)`)
- Resolved a duplicate `POAM-2026-023` ID collision in `docs/POAM.md`
  (`fix(compliance)`)
- Documented `SECURITY.md` GHSA-hfqj-24cj-693g and GHSA-v3h4-8458-5ww3 as
  resolved with implementation detail, matching the fixes already present in
  `inference_proxy.py` and `governance_middleware.py` (`fix(docs)`)

### Changed

- Corrected pipeline tier numbering (CBF=2, Fiscal=3, OPA=4) across ~25 docs
  that had swapped or stale tier references; removed stale references to the
  retired SLM tier and the fictional `governed_tool` decorator (`docs`)
- Removed fictional v0.1.0/rc-v0.1.0 version references across ~40 files in a
  v2.0.0/v2.1.0 codebase (`docs`)
- Deleted superseded planning and process-fiction documents (implementation
  plans, roadmaps, merge plans) and fixed the dangling cross-references left
  by those deletions (`docs`)
- Consolidated Roo/Cline agent rules into a single tool-agnostic `AGENTS.md`
  (`docs`)
- Corrected governance verdict vocabulary to the canonical 4-state enum
  (`CLEAR` / `HITL_REQUIRED` / `BLOCKED` / `ESCALATED`) (`docs(governance)`)
- Corrected fabricated FTRA architecture description across 5 docs to reflect
  the actual implementation wired into `governed_financial_advisor/graph.py`
  (`docs(governance)`)

---

## [v2.1.0] — 2026-07-27

> 113 commits since v2.0.0 (2026-06-14). This release leads with 15 new
> capabilities spanning gateway governance, multi-jurisdiction compliance,
> observability, and reference implementations.

### Added — Gateway & Governance

- FTRA Commencement Reachability Gate: graph-based transaction reachability
  analysis for FTRA commencement decisions (`feat(governance)`) —
  `src/gateway/governance/ftra/` (classifier, graph_analyzer, models,
  node_factory), `src/gateway/governance/ftra_reachability.py`
- CAGE-003 Agent Registry Integration: SPIFFE trust-domain agent catalog
  adapter (`feat(governance)`) —
  `src/gateway/governance/ingress/agent_registry_adapter.py`
- Phase A Ingress Adapters: AAIF, ACS, OSCAL, Lula, AGP policy uploader, and
  policy translator for multi-standard policy ingestion (`feat(gateway)`) —
  `src/gateway/governance/ingress/`
- Phase B AGW Absorption: agw_adapter and agent_gateway_adapter server-side
  integration (`feat(gateway)`) —
  `src/gateway/governance/ingress/agw_adapter.py`,
  `src/gateway/server/agent_gateway_adapter.py`
- NeMo Guardrails Integration: CBRN rails, NeMo manager, and vllm_client
  (`feat(governance)`) — `src/gateway/governance/nemo/`
- LangGraph Harness: NeMo and OPA node factories for governed graph execution
  (`feat(governance)`) — `src/gateway/governance/langgraph_harness/`

### Added — Compliance & Audit

- NIST AI 600-1 Compliance Gates phases 0–3: CBRN, confabulation, data
  privacy, and prompt injection (`feat(compliance)`)
- Three-Region Compliance Matrix: EU_ECB, APAC_MAS, and US_FED with separate
  Lula manifests and pytest jurisdiction matrix (`feat(compliance)`)
- CBF External Reconciliation Worker: POAM-023 closed; async external
  reconciliation loop (`feat(compliance)`) —
  `src/compliance_bridge/reconciliation_worker.py`
- AARM Profile Mapper: AARM profile mapping and report generation
  (`feat(compliance)`) —
  `src/compliance_bridge/aarm_mapper.py`,
  `src/compliance_bridge/aarm_report_generator.py`
- Evidence Chain Metadata Binding: evidence_stream with cryptographic
  provenance anchoring for audit trails (`feat(compliance)`) —
  `src/compliance_bridge/evidence_stream.py`

### Added — Observability & Infrastructure

- AgentSight UI: React/TypeScript real-time governance dashboard
  (`feat(agentsight)`) — `src/agentsight-ui/`
- Langfuse Native OTLP: replaced standalone OTel Collector with Langfuse-native
  OTLP export (`feat(infra)`)
- Region-Aware Kubernetes Templates: `deployment/k8s/*.yaml.tpl` with
  `CAGE_DEPLOYMENT_REGION` guards for EU_ECB, APAC_MAS, and US_FED
  (`feat(infra)`)

### Added — Reference Implementations

- Governed Financial Advisor: full multi-agent reference implementation with
  policy enforcement, PII sanitization, and audit trail (`feat(advisor)`) —
  `src/governed_financial_advisor/`

### Added — Other

- Background deployment wrapper script and make targets (`feat(ci)`)
- Multi-jurisdiction matrix validation suite (`feat(compliance)`)
- Governance kernel hardening with named constants and guards (`feat(governance)`)

### Fixed

- Resolved all GKE integration test failures (`fix(tests)`)
- Awaited webhook dispatch tasks with `asyncio.gather` (`fix(compliance)`)
- Resolved 9 test failures on main branch (`fix(governance)`)
- Added SPIFFE trust-domain agent entries to catalog (`fix(governance)`)
- Escaped mrkdwn special characters in Slack alerts (`fix(gateway)`)
- Added audit-id to content-disposition header (`fix(gateway)`)
- Replaced vulnerable ReDoS email regex with linear-time alternative (`fix(gateway)`)
- Added routing seal enforcement to validate-action endpoint (`fix(gateway)`)
- Enforced input governance for all message roles in inference proxy (`fix(gateway)`)
- Added `detect_indirect_injection` alias to prompt injection detector (`fix(gateway)`)
- Promoted `agentic_scope_statement` to full control mapping (`fix(governance)`)
- Fixed `ControlRegistry` filter and storage defaults (`fix(governance)`)
- Resolved 55 test failures across unit and integration suites (`fix(tests)`)
- Registered `eu_ecb` pytest marker in `pytest.ini` (`fix(tests)`)
- Caught all import errors from dowhy probe (`fix(governance)`)
- Raised compliance-bridge memory limit to prevent OOMKill (`fix(infra)`)
- Added PSA-restricted security context to redis-stack-fresh (`fix(infra)`)
- Fixed OPA path, added dowhy skip guards, upgraded langchain CVEs (`fix(ci)`)
- Fixed dowhy/numpy2, OPA rego.v1, dependency-review conflicts (`fix(ci)`)
- Suppressed pre-existing mypy violations to unblock CI (`fix(ci)`)
- Resolved EU_ECB, APAC_MAS, ISO 42001, and AI 600-1 Lula CI failures (`fix(ci)`)
- Applied ruff auto-fixes and restored corrupted agent file (`fix(ci)`)
- Regenerated STPA artifacts after `currency_denylist` rename (`fix(governance)`)
- Corrected section ordering in open interop spec (`fix(docs)`)
- Added `CAGE_ENV=ci` to AI 600-1 job and upgraded cryptography (`fix(ci)`)

### Changed

- Moved financial-advisor service account out of governed_advisor module
  (`refactor(infra)`)
- Changed storage default to S3, generalized labels (`refactor(compliance)`)
- Restructured `CONTROL_META` with region-keyed accessor (`refactor(compliance)`)
- Hardened audit workflow and OSCAL exporter (`refactor(compliance)`)
- Applied ruff format to posture check scripts (`style(compliance)`)
- Bumped PyTorch to 2.13 (`chore(infra)`)
- Bumped GitHub Actions dependencies (`chore(ci)`)
- Removed unused imports from `stpa_compiler` (`chore(ci)`)
- Regenerated stale STPA artifacts (`chore(governance)`)
- Regenerated `uv.lock` to fix numpy version inconsistency (`chore(deps)`)
- Migrated agent rules from `.clinerules` to `.roo/rules/` (`chore(docs)`)
- Replaced GKE-specific k8s resources with agnostic defaults (`chore(infra)`)
- Removed GCP region default, generalized CI comments (`chore(governance)`)
- Added lint job, gitleaks scan, and default storage to S3 (`chore(ci)`)
- Added three-region pytest matrix and activated jurisdiction workflows (`ci(ci)`)
- Fixed Lula install to use `defenseunicorns-labs/lula1 v0.16.0` (`ci(ci)`)
- Added APAC_MAS residency tests and parametrized normative provider (`test(tests)`)
- Added EU_ECB bias eval pipeline for AI Act Art.10 (`test(compliance)`)
- Added US_FED OPA unit tests and policy vectors (`test(compliance)`)
- Applied OSS readiness remediation: license headers, inclusive language (`chore`)
- Scrubbed sensitive references for public OSS release (`chore(docs)`)
- Rewrote internal-facing docs for public OSS release (`docs(docs)`)
- Added public OSS release documentation (`docs(docs)`)
- Added comprehensive OpenAPI and gRPC endpoint map (`docs(docs)`)
- Added CAGE open interoperability specification developer preview (`docs(docs)`)
- Added US-FED dev GKE deployment execution plan (`docs(docs)`)
- Documented mathematical formalism and added Lula assessment results (`docs`)
- Added platform-agnostic framing for NonProduct classification (`docs(docs)`)

---

## [v2.0.0] — 2026-06-14

First stable reference implementation with full security hardening scope.

---

[Unreleased]: https://github.com/google/cybernetic-governance-engine/compare/v2.1.1...HEAD
[v2.1.1]: https://github.com/google/cybernetic-governance-engine/compare/v2.1.0...v2.1.1
[v2.1.0]: https://github.com/google/cybernetic-governance-engine/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/google/cybernetic-governance-engine/releases/tag/v2.0.0
