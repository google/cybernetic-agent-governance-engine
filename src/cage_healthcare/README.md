# `cage_healthcare` — Healthcare Reference Domain Plugin

`HealthcareCagePlugin` (`maturity = "stub"`) is a reference domain for clinical
dosing governance (`CAGE_DOMAIN=healthcare`). It shows that a second domain
plugs into the kernel without kernel edits. It is not a governed clinical
system.

Because it declares `stub` maturity, `assemble_governor()` refuses it in every
enforcing posture (`staging`, `production`, `local`). It runs in permissive
postures only: `dev`, `test` and `ci`, which includes Docker Compose. The
controls below are wired and tested, but the domain lacks the evidence a
production domain needs: it has no domain STPA hazard file, its ground truth is
a simulated assay provider, and no Gate W run has exercised it. Raise the
maturity only together with that evidence.

## Wired Runtime Controls (permissive postures)

- **FTRA Terminal Classification**: [`config/ftra/terminal_registry.json`](config/ftra/terminal_registry.json)
- **OPA Policy (`dosing.governance`)**: [`opa/dosing_governance.rego`](opa/dosing_governance.rego) and unit suite [`opa/dosing_governance_test.rego`](opa/dosing_governance_test.rego), mounted dynamically in GKE via `infra/targets/gcp-gke/main.tf` and verified at startup by `OPAClient.verify_domain_policy()`.
- **Control Barrier Function (CBF)**: `SerumConcentrationBarrier` (`safety:serum_concentration` vs. `domains.healthcare.min_therapeutic_concentration`) enforced by `DoseBarrierTier`.
- **Clinical Consensus Tier**: `ClinicalConsensusTier` (`build_healthcare_consensus_contribution()`).
- **Conversational Rail**: `HealthcareRailProvider` (`CheckContraindicationAction`).

## STPA Scope Status

- **Core Kernel STPA UCAs**: Active (`config/stpa/core_system.yaml` + kernel `ServerInputResolver` bindings).
- **Domain-Specific Healthcare STPA Hazard YAML / Compiled `uca_rules`**: **Planned** (domain STPA hazard compilation under `config/stpa/` is currently implemented for `cage_finance` only; `HealthcareCagePlugin.contribute()` contributes `uca_rules=()` until clinical hazard tables are authored).
