# `cage_healthcare` — Healthcare Domain Plugin

`HealthcareCagePlugin` (`maturity = "production"`) is CAGE's clinical dosing
governance plugin (`CAGE_DOMAIN=healthcare`).

## Active Runtime Controls (Compose & GKE)

- **FTRA Terminal Classification**: [`config/ftra/terminal_registry.json`](config/ftra/terminal_registry.json)
- **OPA Policy (`dosing.governance`)**: [`opa/dosing_governance.rego`](opa/dosing_governance.rego) and unit suite [`opa/dosing_governance_test.rego`](opa/dosing_governance_test.rego), mounted dynamically in GKE via `infra/targets/gcp-gke/main.tf` and verified at startup by `OPAClient.verify_domain_policy()`.
- **Control Barrier Function (CBF)**: `SerumConcentrationBarrier` (`safety:serum_concentration` vs. `domains.healthcare.min_therapeutic_concentration`) enforced by `DoseBarrierTier`.
- **Clinical Consensus Tier**: `ClinicalConsensusTier` (`build_healthcare_consensus_contribution()`).
- **Conversational Rail**: `HealthcareRailProvider` (`CheckContraindicationAction`).

## STPA Scope Status

- **Core Kernel STPA UCAs**: Active (`config/stpa/core_system.yaml` + kernel `ServerInputResolver` bindings).
- **Domain-Specific Healthcare STPA Hazard YAML / Compiled `uca_rules`**: **Planned** (domain STPA hazard compilation under `config/stpa/` is currently implemented for `cage_finance` only; `HealthcareCagePlugin.contribute()` contributes `uca_rules=()` until clinical hazard tables are authored).
