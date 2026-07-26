# Changelog

All notable changes to the CAGE reference implementation are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with a `-ref` suffix
to distinguish reference implementation snapshots from production releases.

---

## [Unreleased]

### Added
- `.github/CODEOWNERS` — single-maintainer review enforcement for architectural paths
- `.github/pull_request_template.md` — reference implementation verification checklist
- `.github/workflows/ref_impl_signoff.yml` — CI gate and release tagging workflow
- `.github/branch-protection-rules.md` — canonical specification for all GitHub repository-level protection settings (branch protection, tag protection, GHAS, workflow permissions)
- `CHANGELOG.md` — this file

### Changed
- `.github/workflows/dependency-review.yml` — removed `continue-on-error: true` from the `Dependency Review` step; the GHAS-backed gate is now a hard block; GHAS enablement instructions documented inline
- `.github/workflows/compliance-matrix.yml` — documented rationale for `continue-on-error: true` on the regional matrix test step (live-cluster dependency); hardening path tracked in workflow comment
- `CONTRIBUTING.md` — added "Repository Protection Setup" section with quick-reference GitHub UI settings and link to `.github/branch-protection-rules.md`

---

## [v2.0.0-ref] — TBD

> First stable reference implementation snapshot covering CAGE-002 (AARM profiles)
> and CAGE-003 (FTRA integration). Tag this release after feat/CAGE-002 and
> feat/CAGE-003 PRs are merged and CI is green on `main`.

### Added
- AARM profile mapper (`src/compliance_bridge/aarm_mapper.py`)
- FTRA classifier and graph analyzer (`src/gateway/governance/ftra/`)
- STPA compiler and validator (`src/gateway/governance/stpa_compiler.py`, `stpa_validator.py`)
- NeMo Guardrails integration (`src/gateway/governance/nemo/`)
- AGP policy ingress adapters (`src/gateway/governance/ingress/`)
- AgentSight UI (`src/agentsight-ui/`)
- Governed Financial Advisor reference agent (`src/governed_financial_advisor/`)

---

<!-- Add new entries above this line in the format:
## [vX.Y.Z-ref] — YYYY-MM-DD
### Added / Changed / Fixed / Removed
-->
