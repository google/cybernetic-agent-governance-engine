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

## [v2.1.0] — 2026-07-27

> 113 commits since v2.0.0 (2026-06-14). Covers multi-jurisdiction compliance
> gates, Phase A/B gateway absorption, AgentSight UI, NeMo Guardrails integration,
> three-region Kubernetes manifests, and public OSS readiness remediation.

### Added

- CAGE-003 agent registry integration with SPIFFE trust-domain entries
  (`feat(governance)`)
- FTRA commencement reachability gate (`feat(governance)`)
- Phase B AGW absorption: agent catalog, OPA bridge, AGW adapter (`feat(gateway)`)
- Phase A ingress adapters: AAIF, ACS, OSCAL, Lula, AGP policy uploader
  (`feat(gateway)`)
- CBF external reconciliation worker implementing POAM-023 (`feat(compliance)`)
- Evidence chain metadata binding (`feat(compliance)`)
- NIST AI 600-1 compliance gates phases 0–3 (`feat(compliance)`)
- Three-region compliance matrix: EU_ECB, APAC_MAS, US_FED (`feat(compliance)`)
- EU_ECB and APAC_MAS Lula validation manifests (`feat(compliance)`)
- Region-aware Kubernetes manifest templates with `CAGE_DEPLOYMENT_REGION` guards
  (`feat(infra)`)
- Langfuse native OTLP integration replacing standalone OTel Collector (`feat(infra)`)
- Background deployment wrapper script and make targets (`feat(ci)`)
- Governed Financial Advisor: extended checkpointer and data analyst graph
  (`feat(advisor)`)
- Multi-jurisdiction matrix validation suite (`feat(compliance)`)
- AARM profile mapper and report generator (`feat(compliance)`)
- AgentSight UI (React/TypeScript dashboard) (`feat(agentsight)`)
- NeMo Guardrails integration with vLLM client and CBRN rails (`feat(governance)`)
- LangGraph harness: NeMo and OPA node factories (`feat(governance)`)
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

[Unreleased]: https://github.com/google/cybernetic-governance-engine/compare/v2.1.0...HEAD
[v2.1.0]: https://github.com/google/cybernetic-governance-engine/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/google/cybernetic-governance-engine/releases/tag/v2.0.0
