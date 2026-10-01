# FTRA Scope — One Enforcement Point per Rule

**Status:** current as of the `refactor/ftra-scope` change (Phase 7, step 1).
**Code:** [`FtraStage`](../../src/gateway/governance/governor/stages/ftra.py),
[`ftra/autonomy.py`](../../src/gateway/governance/ftra/autonomy.py),
[`ftra/classifier.py`](../../src/gateway/governance/ftra/classifier.py),
[`ftra/models.py`](../../src/gateway/governance/ftra/models.py).

The Forward-Looking Trajectory Reachability Analyzer (FTRA, Tier 0.5) answers
one question: **is this action irreversible, and if so may it proceed without a
human?** It does not judge whether a parameter *value* is acceptable. That is
owned by STPA unsafe-control-action (UCA) rules and OPA policy, and input
sanitisation is owned by the rails.

Before this change, `FtraStage` also called a schema-driven "semantic
validator" (`validate_tool_input`). No domain plugin ever registered a schema,
so in production it let every input through. Only tests exercised it, and the
rules it could express duplicated checks that already have an owner. It has
been **deleted**, not moved (see [Decision per former rule](#decision-per-former-rule)).

---

## What FTRA owns

| Responsibility | Where | Fail-closed behaviour |
|---|---|---|
| **Irreversibility classification** against the active domain's terminal registry. The registry digest (`manifest_sha256`) covers both the terminals and the autonomous envelope. | `IrreversibilityClassifier.classify_with_provenance` in [`classifier.py`](../../src/gateway/governance/ftra/classifier.py); registries [`config/ftra/terminal_registry.json`](../../config/ftra/terminal_registry.json), [`src/cage_healthcare/config/ftra/terminal_registry.json`](../../src/cage_healthcare/config/ftra/terminal_registry.json) | Unregistered, invalid or unreadable entries all fall back to `IRREVERSIBLE_TERMINAL`. |
| **Provenance codes**: one violation code per `RegistryState`, so a reviewer can tell "the registry says irreversible" from "the registry is silent". | `FtraBoundaryResult.from_classification` and `_provenance_violation` in [`models.py`](../../src/gateway/governance/ftra/models.py) | `FTRA_REGISTERED_IRREVERSIBLE`, `FTRA_REGISTERED_EXTERNALLY_REVERSIBLE`, `FTRA_UNREGISTERED_ACTION`, `FTRA_REGISTRY_ENTRY_INVALID` → HITL. `FTRA_REGISTRY_UNAVAILABLE` → HARD. |
| **Autonomous envelope predicate**: a registered terminal clears without a human iff `0 < magnitude <= max_magnitude` and confidence is at least the ALLOW floor. | `conditional_clear_reason` in [`autonomy.py`](../../src/gateway/governance/ftra/autonomy.py) | An unregistered action never clears (`UNREGISTERED_NEVER_AUTO_CLEARS`). |
| **Magnitude shape**: the only input shape FTRA depends on. | `safe_magnitude` in [`autonomy.py`](../../src/gateway/governance/ftra/autonomy.py), fed by the domain's `MagnitudeExtractor` (e.g. `extract_field_magnitude` in [`consensus/engine.py`](../../src/gateway/governance/consensus/engine.py)) | A missing, `None`, bool, non-numeric, NaN, ±inf, negative or zero magnitude, or an extractor that raises, means "unknown". Unknown never clears, so the HITL violation stays. The span attribute `cage.ftra.magnitude_known` records whether a finite magnitude was read. |
| **Classifier failure** | `FtraStage._ftra_boundary_check` | Any exception becomes a HARD `FTRA_ERROR` and the action is classified `IRREVERSIBLE_TERMINAL`. |

The magnitude shape is tested hermetically through `FtraStage.run` in
[`tests/test_ftra_magnitude_shape.py`](../../tests/test_ftra_magnitude_shape.py)
and [`tests/test_ftra_conditional_clearance.py`](../../tests/test_ftra_conditional_clearance.py).

> [!NOTE]
> `extract_field_magnitude` coerces with `float()`, so a *numeric string*
> such as `"50"` reads as `50.0`. A non-numeric string raises and is treated
> as unknown. Whether a numeric string is an acceptable *value* is a
> value-policy question for the owners below, not for FTRA.

## What FTRA does not own

| Concern | Owner |
|---|---|
| **Value policy**: limits, thresholds, role and currency rules, preconditions. | STPA UCAs, authored in [`trade_hazards.yaml`](../../src/cage_finance/config/stpa/trade_hazards.yaml), generated into [`uca_rules.py`](../../src/cage_finance/stpa/uca_rules.py) and run by [`StpaStage`](../../src/gateway/governance/governor/stages/stpa.py). Every STPA finding is HARD: `StpaStage` promotes any non-HARD kind a validator returns. OPA policy is [`trade_governance.rego`](../../src/cage_finance/opa/trade_governance.rego) (package `trade.governance`, declared at [`src/cage_finance/plugin.py`](../../src/cage_finance/plugin.py)), evaluated by [`OpaStage`](../../src/gateway/governance/governor/stages/opa.py). It is default-deny (`default allow = "DENY"`). |
| **Cash-amount sanity**: a negative or non-finite trade amount. | `finance_cost_resolver` in [`src/cage_finance/invariants.py`](../../src/cage_finance/invariants.py). It raises inside the `cbf` / `fiscal` tiers, and the pipeline turns the raise into a HARD `TIER_EXCEPTION`. |
| **Input sanitisation and injection**: prompt injection, control-override payloads. | NeMo rails ([`config/rails/generated_stpa_rails.co`](../../config/rails/generated_stpa_rails.co), [`src/integrations/nemo/manager.py`](../../src/integrations/nemo/manager.py)) and the AGP semantic policy ([`config/agp/generated_semantic_policy.txt`](../../config/agp/generated_semantic_policy.txt)). Both are generated from STPA UCA-7 in [`config/stpa/core_system.yaml`](../../config/stpa/core_system.yaml). |

## Decision per former rule

Each rule below was expressible in the deleted `ActionSchema` /
`ParameterConstraint` model. None was active in production, because no domain
registered a schema.

| Former semantic-validator rule | Decision | Owning enforcement point at HEAD |
|---|---|---|
| **Required parameters** (`MISSING_REQUIRED_PARAMETER`) | Deleted from FTRA. | STPA UCA evaluators fail closed on a missing required param (e.g. UCA-2 `latency_ms`, UCA-5 `drawdown` in [`uca_rules.py`](../../src/cage_finance/stpa/uca_rules.py)). OPA is default-deny. A missing envelope magnitude never clears FTRA. |
| **Type** (`TYPE_MISMATCH`) | Deleted from FTRA, except for the magnitude. | Magnitude type: FTRA magnitude shape (above). Every other parameter: the STPA UCA or OPA rule that reads it. A value that matches no OPA ALLOW rule is denied. |
| **Numeric bounds** (`min_value` / `max_value`) | Deleted from FTRA. | Lower bound and finiteness of the cash amount: `finance_cost_resolver`. Upper limits: OPA RBAC limits in [`trade_governance.rego`](../../src/cage_finance/opa/trade_governance.rego) (mirrored by `rbac_rules` in [`trade_hazards.yaml`](../../src/cage_finance/config/stpa/trade_hazards.yaml)), the fiscal tier's daily limit, and the UCA-6 volume fraction. Autonomous ceiling: `conditional_clear_reason`. |
| **Enum / allowed values** (`INVALID_ENUM_VALUE`) | Deleted from FTRA. | OPA: the role allow-list (`allowed_roles`) and the currency denylist in [`trade_governance.rego`](../../src/cage_finance/opa/trade_governance.rego). |
| **Regex pattern** (`pattern`) | Deleted, no replacement. No schema ever declared one. | A domain that needs a format rule adds it as an STPA UCA or an OPA rule, where its owner already lives. |
| **Forbidden payload patterns** (null byte, path traversal, `eval(`/`exec(`, `__import__`, SQL comment / `DROP TABLE`, `override_governance`, `bypass_ftra`) | Deleted from FTRA. They applied only to *extra* params of a registered schema, so they never ran. | Rails (UCA-7) for injection. The kernel never interprets a parameter as code, a path or SQL, and no code path reads a parameter named `override_governance` / `bypass_ftra`, so such a key is inert. |
| **Extra parameters** (`allow_extra_parameters=False`) | Deleted, no replacement. | None, by design. STPA and OPA read only the fields they name, and unknown fields are inert. A domain that wants a closed world expresses it as an OPA rule. |

## Deviation from the plan text

The Phase 7 plan proposed moving value-policy checks into
[`config/opa/generated_stpa_policy.rego`](../../config/opa/generated_stpa_policy.rego).
That file is **not queried by the kernel**: `OpaStage` evaluates the active
domain's package (`trade.governance` for finance). The generated Rego is a
compiler artefact checked by `scripts/check_stpa_freshness.py` and
`scripts/check_policy_drift.py`, not a live decision point. Moving rules there
would have created dead policy. Value rules therefore stay where they are
already enforced: the domain's STPA UCAs and its OPA package.

## Removed surface

- The FTRA `semantic_validator` module (`validate_tool_input`,
  `ActionSchema`, `ParameterConstraint`, `register_action_schema`,
  `ACTION_SCHEMAS`, `SemanticValidationResult`, `ValidationFailureCode`).
- `FtraBoundaryResult.from_semantic_breach`, the `FTRA_SEMANTIC_BREACH` /
  `FTRA_VALIDATION_ERROR` codes and the `<CLASSIFICATION>_SEMANTIC_BREACH`
  classification strings.
- Span attributes `cage.ftra.semantic_validation_passed`,
  `cage.ftra.semantic_failure_code`, `cage.ftra.semantic_failed_parameter`.
  Added: `cage.ftra.magnitude_known`.
