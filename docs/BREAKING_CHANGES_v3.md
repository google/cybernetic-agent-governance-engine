# CAGE v3.x Breaking Changes

> **Status:** Released. Covers the v3 line — v3.0.1 (2026-09-07) and v3.1.0 (2026-09-22).
> The v3.1.0 clean breaks are collected in
> [v3.1.0 Clean Breaks — Zero-Trust Identity & Egress](#v310-clean-breaks--zero-trust-identity--egress-2026-09-22) at the end of this document.
> See [`CHANGELOG.md`](../CHANGELOG.md) for the full release notes. The sections below
> describe the breaking changes included in v3.0.1. Item IDs (`SR-#`,
> `MR-#`, `CR-#`, `FF-#`, `EV-#`) match
> ``local/plans/remediation/MAJOR_VERSION_CLEANUP_PLAN.md`` 1:1
> so the two documents can be cross-referenced.
>
> **Release Scope:** `AGWEnvelope`/`AGWEnvelopeBuilder` removal, legacy provider
> signing method removal, RFC 8785 JCS canonicalization migration (POAM-2026-060),
> schema sentinels (`cage-evidence-stream/2.0` / `cage-context-accumulator/2.0`),
> canonical 6 governance decision set, and `KMS_BATCH_ENABLED` default-value
> confirmation (`"false"`).

## Overview

CAGE `v3.0.1` removes deprecated shims, backward-compatibility aliases, and
ad hoc environment-variable configuration that have been carrying
`DeprecationWarning`s since `v2.x`. It also graduates (or explicitly declines
to graduate) two feature flags to their stable default, and consolidates
scattered `os.getenv()` threshold reads into versioned `config/thresholds/`
files.

**Scope at a glance:**

| Category | Count | Risk |
|---|---|---|
| Safe Removals (deprecated shims/aliases) | 7 (SR-1–SR-7) | Low |
| Migration-Required Removals (region-aware accessor migration) | 4 (MR-1–MR-4); MR-5 reclassified into CR-2 | Medium |
| Coordinated Removals (compliance-critical, sign-off gated) | 3 (CR-1–CR-3) | High |
| Feature Flag Graduations | 2 (FF-1, FF-2) | Medium–High if graduated |
| Environment Variable Consolidations | 6 (EV-1–EV-6) | Low–Medium |
| Backward-Compatibility Remediation (canonicalization + legacy-path removal) | 8 (BC-01–BC-08; BC-06 deliberately unchanged) | High |

**Who is affected:** Any consumer that (a) imports directly from the
deprecated modules/aliases listed below, (b) calls the legacy
`check_safety_constraints` MCP tool name, (c) passes `registry_path`/`plan_key`
directly to `create_ftra_node()`, (d) reads the flat/universal-only
`CONTROL_META` / `EVIDENCE_SLA_SECONDS` / `ISO_CONTROL_MAP` dicts instead of
the region-aware accessor functions, (e) imports module-level names directly
from [`config/settings.py`](../config/settings.py:137), or (f) sets any of
the environment variables listed under [Configuration Changes](#configuration-changes).

**Not affected:** Consumers already using the canonical replacement
symbols/accessors/config files listed in each table below experience no
behavior change in `v3.0.1`.

---

## PR A — Domain Pipeline Extraction (Capability-Driven Tier Dispatch)

> **Status:** Completed / Merged
> Part of the four-PR domain extraction refactoring sequence (A → B → C → D).
> This is a **hollowing refactor** — the kernel intentionally loses functionality
> until PR C restores it as domain plugins.

### Overview

PR A establishes the capability-driven tier dispatch architecture, replacing
hardcoded inline governance blocks with a plugin-based tier loop. The kernel
becomes domain-agnostic: it no longer knows about trades, consensus, CBF, or
fiscal limits. Those mechanisms are deleted and will be restored in PR C as
`GovernanceTierPlugin` implementations registered at runtime.

**Three-Layer Split Rule:** Layer 1 (kernel) provides tier dispatch infrastructure,
Layer 2 (domain plugins like `src/cage_finance/`) provides domain-specific tiers,
Layer 3 (rails like Langfuse) provides external integrations.

### Breaking Changes

#### Legacy Inline Dispatch Removed

**Breaking Change:** the consensus gate, causal gatekeeper, FRIA/normative
provider, and CBF/fiscal blocks have been deleted from
[`src/gateway/governance/governor/governor.py`](../src/gateway/governance/governor/governor.py)
`_run_checks()` method.

| Deleted block | Lines removed | Replacement |
|---|---|---|
| Consensus gate | ~45 lines | Deleted; replaced by tier dispatch loop (restores in PR C as plugin) |
| Causal gatekeeper | ~30 lines | Deleted; replaced by tier dispatch loop (restores in PR C as plugin) |
| FRIA/normative provider | ~50 lines | Deleted; replaced by tier dispatch loop (restores in PR C as plugin) |
| CBF/fiscal limit guard | ~160 lines | Deleted; replaced by tier dispatch loop (restores in PR C as plugin) |

**Who is affected:** any deployment relying on trade execution governance. Until
PR C lands, the kernel **denies all actions by default** because no tier plugins
are registered. This is the intended "hollowing" design — the kernel is
functionally incomplete until domain plugins are promoted.

**Migration:** none until PR C. This is a **reference architecture refactoring**,
not a production-continuity migration. Adopters should wait for the full PR
sequence to land before upgrading.

#### RefusalReceipt Schema v3

**Breaking Change:** [`RefusalReceipt.schema_version`](../src/gateway/governance/contracts.py:80)
default changed from `"v1"` to `"v3"`.

| Schema version | Additions |
|---|---|
| v1 | Original fields (thread_id, action, violated_tier, violated_rule, proof_hash) |
| v2 | 5-part Terry Snyder proof chain (attempted_params, standing_snapshot, control_id, protected_consequence, non_formation_proof) |
| v3 | `tier_failures` tuple (list of `GovernanceTierFailure` for multi-tier dispatch) |

**Who is affected:** consumers parsing `RefusalReceipt` instances or verifying
`proof_hash` values.

**Migration:** `proof_hash` computation now includes `tier_failures` when
`schema_version != "v1"`. Existing receipt consumers must handle both v1/v2
legacy receipts and v3 receipts. The hash algorithm is unchanged (JCS
canonicalization per POAM-2026-060), only the payload content changed.

#### Domain Literals Removed from Kernel

**Breaking Change:** hardcoded domain action references (`"execute_trade"`,
`"reverse_trade"`) removed from kernel Layer 1 code per the Three-Layer Split Rule.

| File | Change |
|---|---|
| [`src/gateway/server/hybrid_server.py`](../src/gateway/server/hybrid_server.py:108) | OPA warmup changed from `"execute_trade"` to `"system_warmup_test"` |
| [`src/gateway/governance/telemetry_provider.py`](../src/gateway/governance/telemetry_provider.py:242) | Langfuse trace fetch changed from filtering by `name="execute_trade"` to fetching all traces |
| [`src/gateway/governance/ontology.py`](../src/gateway/governance/ontology.py:183) | FIN-2 constraint (`execute_trade` latency) deleted (moves to domain plugin in PR C) |

**Who is affected:** any code expecting domain-specific warmup actions, telemetry
filtering, or ontology constraints in the kernel.

**Migration:** domain-specific warmup, telemetry, and constraints move to domain
plugins in PR C. Until then, warmup uses a generic test action, telemetry
fetches all traces, and FIN-2 is not enforced.

**CI enforcement:** Gate G6 ([`scripts/check_domain_literals.py`](../scripts/check_domain_literals.py))
now scans `src/gateway/` for forbidden domain literals and fails CI on violations.

#### Method Signature Changes

**Breaking Change:** [`SymbolicGovernor.revalidate_post_hitl()`](../src/gateway/governance/governor/governor.py)
and `pre_check()` no longer accept `tool_name` with a default value. (`pre_check()`
was later removed entirely, together with the dead NeMo pre-check path — see #261.)

| Method | Old signature | New signature |
|---|---|---|
| `revalidate_post_hitl()` | `async def revalidate_post_hitl(self, action: str, params: dict[str, Any], tool_name: str = "execute_trade") -> str` | `async def revalidate_post_hitl(self, action: str, params: dict[str, Any]) -> str` |
| `pre_check()` | `async def pre_check(self, action: str = "execute_trade", params: dict[str, Any]) -> str` | `async def pre_check(self, action: str, params: dict[str, Any]) -> str` |

**Who is affected:** callers relying on the `tool_name` default value.

**Migration:** explicitly pass the `action` parameter. No default is provided —
the kernel is domain-agnostic and cannot assume a default action name.

#### Deleted Adapters and Protocols

**Breaking Change:** [`_LegacyConsensusAdapter`](../src/gateway/governance/contracts.py)
class deleted from `src/gateway/governance/contracts.py`.

**Who is affected:** any code instantiating or importing `_LegacyConsensusAdapter`.

**Migration:** the consensus mechanism is deleted in PR A and restored as a tier
plugin in PR C. No interim adapter is provided.

### New Infrastructure

- **Tier Dispatch Loop** — [`run_pipeline()`](../src/gateway/governance/governor/pipeline.py)
  executes registered `GovernanceTierPlugin` instances for a given phase (1 or 2).
- **Helper Methods** — `_is_governed_action()`, `_violations_to_strings()`,
  `_violations_to_failures()`, `_build_standing()` provide tier dispatch utilities.
- **GovernanceTierPlugin Protocol** — [`contracts.py:217`](../src/gateway/governance/contracts.py:217)
  defines the tier interface (`tier_name`, `phase`, `order`, `claims_action()`,
  `check_action()`).
- **Domain Literal Gate** — [`scripts/check_domain_literals.py`](../scripts/check_domain_literals.py)
  AST-based CI gate enforcing kernel domain-agnosticism.

### Acceptance Criteria

Per ``plans/domain_extraction_implementation_plan.md``:

- [x] G1: Tier dispatch loop executes and honors phase/order
- [x] G2: Capability predicate (`claims_action()`) replaces hardcoded literals
- [x] G6: No domain action names in `src/gateway/` executable code (CI gate passes)
- [ ] G4, G5: Test coverage (28 tests across 6 test files) — pending Stage 8

### Compliance Impact

- **OSCAL component update required** within 2 business days of PR A merge (per
  [`AGENTS.md`](../AGENTS.md) Compliance Artifact Obligations).
- **Lula validation updates** — any validation files referencing deleted inline
  blocks must be updated to reflect the tier dispatch architecture.
- **Region-gated CI** — must be run for all three postures (`US_FED`, `EU_ECB`,
  `APAC_MAS`) before considering PR A complete.

---

## API Changes

### Removed Modules

| Module | Replacement | Migration |
|--------|-------------|-----------|
| [`src/gateway/governance/generated_stpa_validator.py`](../src/gateway/governance/generated_stpa_validator.py) (`STPAValidator` class) | [`src/gateway/governance/generated_stpa_validator.py`](../src/gateway/governance/generated_stpa_validator.py:38) (`GeneratedSTPAValidator`) | Replace `from src.gateway.governance.stpa_validator import STPAValidator` with `from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator`; replace `.validate(action_name, params)` calls with `.validate_generated(action_name, params)`. |
| [`src/gateway/governance/safety/cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) (entire file) <br><br>**Correction:** `cbf_engine.py` remains in the kernel at `src/gateway/governance/safety/cbf_engine.py` (1,114 lines). Only financial-specific CBF barrier calculations moved to `cage_finance/tiers/cbf_tier.py`. | [`src/gateway/governance/text_filter.py`](../src/gateway/governance/text_filter.py) (`ac_keyword_scan`); [`src/gateway/governance/safety/cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) (`ControlBarrierFunction`, `safety_filter`) | Replace `from src.gateway.governance.safety import ac_keyword_scan` with `from src.gateway.governance.text_filter import ac_keyword_scan`; replace `from src.gateway.governance.safety import ControlBarrierFunction, safety_filter` with `from src.gateway.governance.cbf import ControlBarrierFunction, safety_filter`. |
| `src/gateway/governance/agw_envelope.py` (entire file — `AGWEnvelope`, `AGWEnvelopeBuilder` backward-compatibility aliases) | [`src/gateway/governance/governance_envelope.py`](../src/gateway/governance/governance_envelope.py) (`GovernanceEnvelope`, `GovernanceEnvelopeBuilder`) | Replace `from src.gateway.governance.agw_envelope import AGWEnvelope` with `from src.gateway.governance.governance_envelope import GovernanceEnvelope`; replace `AGWEnvelopeBuilder` with `GovernanceEnvelopeBuilder` (same module). `tests/test_agw_envelope.py` (the backward-compatibility test suite for these aliases) is also deleted — see [`tests/test_governance_envelope.py`](../tests/test_governance_envelope.py) for the canonical coverage. **(Completed post-tag, `fix/v3-breaking-changes-completion`.)** |

### Removed Classes/Functions

| Symbol | Module | Replacement | Migration |
|--------|--------|-------------|-----------|
| `GovernanceClient` (alias) | [`src/governed_financial_advisor/infrastructure/governance_client.py:323`](../src/governed_financial_advisor/infrastructure/governance_client.py:323) | `StructuredLLMClient` (same module) | Replace `GovernanceClient(...)` with `StructuredLLMClient(...)`; update any type hints from `GovernanceClient` to `StructuredLLMClient`. See [`docs/examples/governed-financial-advisor/ARCHITECTURE.md`](examples/governed-financial-advisor/ARCHITECTURE.md) for Layer 4 reference application context. |
| `RedisClient` (alias) | [`src/governed_financial_advisor/infrastructure/redis_client.py:268`](../src/governed_financial_advisor/infrastructure/redis_client.py:268) | `AsyncRedisClient` (same module) | Replace `RedisClient()` with `AsyncRedisClient()`. **Note:** do not confuse with the unrelated `_AsyncRedisClient`/`_SyncRedisClient` pair in [`src/gateway/infrastructure/redis_client.py`](../src/gateway/infrastructure/redis_client.py) — that module is untouched by this removal. |
| `HybridClient` (alias) | ``src/governed_financial_advisor/infrastructure/llm_client.py:23`` | `GatewayClient` from [`src/gateway/core/llm.py`](../src/gateway/core/llm.py) | Replace `from src.governed_financial_advisor.infrastructure.llm_client import HybridClient` with `from src.gateway.core.llm import GatewayClient`. |
| `check_safety_constraints` (tool alias) | [`src/governed_financial_advisor/agents/evaluator/agent.py:193`](../src/governed_financial_advisor/agents/evaluator/agent.py:193); [`src/gateway/server/mcp_tool_server.py:483`](../src/gateway/server/mcp_tool_server.py:483); [`src/governed_financial_advisor/tools/api.py:87-88`](../src/governed_financial_advisor/tools/api.py:87); [`src/governed_financial_advisor/graph/nodes/evaluator_node.py:22,147`](../src/governed_financial_advisor/graph/nodes/evaluator_node.py:22) | `simulate_governance_check` | Rename every reference to the tool/function name `check_safety_constraints` to `simulate_governance_check` across all 4 call sites (they must land in one atomic PR). |
| `create_ftra_node(registry_path=..., plan_key=...)` deprecated params | [`src/gateway/governance/ftra/node_factory.py:145-149`](../src/gateway/governance/ftra/node_factory.py:145) | `config: FtraNodeConfig` parameter (same function) | Replace `create_ftra_node(registry_path="x", plan_key="y")` with `create_ftra_node(config=FtraNodeConfig(registry_path="x", plan_key="y"))`. See `Migration Guide` for the full before/after. |
| `CONTROL_META` (module-level dict alias) | [`src/compliance_bridge/types.py:340`](../src/compliance_bridge/types.py:340) | `get_control_meta(region)` | Replace `from src.compliance_bridge.types import CONTROL_META` + direct iteration with `from src.compliance_bridge.types import get_control_meta` and call `get_control_meta(CAGE_DEPLOYMENT_REGION)`. **Behavior note:** `CONTROL_META` contained universal (ISO 42001) controls only — `get_control_meta(region)` returns universal + jurisdictional controls merged for the given region. Passing `"universal"` (or any unrecognized region string) reproduces the old universal-only subset. |
| `EVIDENCE_SLA_SECONDS` (module-level dict alias) | [`src/compliance_bridge/types.py:446`](../src/compliance_bridge/types.py:446) | `get_sla_seconds(region)` | Replace direct dict access with `get_sla_seconds(region)`. Same universal-only → region-merged behavior note as `CONTROL_META` applies. |
| `ISO_CONTROL_MAP` (module-level dict alias — **two distinct symbols**) | [`src/compliance_bridge/types.py:512`](../src/compliance_bridge/types.py:512) **and** [`src/gateway/governance/ontology.py:197-234`](../src/gateway/governance/ontology.py:197) (`TradingKnowledgeGraph.ISO_CONTROL_MAP` class attribute) | `get_iso_control_map(region)` (types.py); `get_control_map(region)` (ontology.py) | These are **two unrelated symbols with the same name in two different modules** — migrate each independently. `src/compliance_bridge/types.py` callers use `get_iso_control_map(region)`; `TradingKnowledgeGraph` callers use `get_control_map(region)`. |
| `update_state()` (public API) | [`src/gateway/governance/safety/cbf_engine.py:907-998`](../src/gateway/governance/safety/cbf_engine.py:907) | `atomic_verify_and_commit()` (same module) | **Completed (CR-3)**: `update_state()` was renamed to `_update_state_unsafe()` (internal-only) to eliminate TOCTOU race conditions. External callers must call `atomic_verify_and_commit()`, which performs the CBF safety check and state commit atomically within a single Redis Lua execution. |
| `sign_actuator_01_digest()` (legacy method) | [`src/gateway/governance/kms_signer.py`](../src/gateway/governance/kms_signer.py) (`KMSSigner` class) | `sign()` (same class) | Replace legacy digest signing with `kms_signer.sign(payload)`; `sign()` is the canonical signing entry point and covers the same code path. **(Completed post-tag, `fix/v3-breaking-changes-completion`.)** |

### Removed Endpoints

No CAGE HTTP endpoint is removed in v3.0.1. `POST /v1/nemo/apply-refinement`
(the legacy NeMo auto-apply route) **stays** — only its
`NEMO_AUTO_APPLY_ENABLED=true` internal code branch is removed (see CR-2
below). No consumer-facing route signature changes.

| Endpoint | Replacement | Migration |
|----------|-------------|-----------|
| `POST /v1/nemo/apply-refinement` with `NEMO_AUTO_APPLY_ENABLED=true` (legacy auto-apply branch) | `POST /v1/nemo/propose-refinement` → `POST /v1/nemo/approve-refinement/{proposal_id}` (human-gated flow, already available in v2.x) | Consumers relying on `NEMO_AUTO_APPLY_ENABLED=true` for automatic, unattended refinement application must switch to the propose/approve flow: call `propose-refinement` to stage a change, then have a human risk officer call `approve-refinement/{id}` with `approved`, `reviewer`, and `rationale`. See [`server.py:844-934`](../src/governed_financial_advisor/server.py:844) for the full staged-proposal contract. |

### Changed Signatures

| Function | Old Signature | New Signature |
|----------|--------------|---------------|
| `create_ftra_node()` | `create_ftra_node(config=None, registry_path=None, plan_key=None)` | `create_ftra_node(config: FtraNodeConfig | None = None)` — `registry_path` and `plan_key` keyword arguments are removed; pass them as fields of a `FtraNodeConfig` instance instead. |
| `ControlBarrierFunction.update_state()` | `async def update_state(self, cost: float, governance_signature: str | None = None) -> None` (public) | **Completed (CR-3)**: Renamed to `_update_state_unsafe()` (internal-only) to eliminate TOCTOU race conditions. External callers must call `atomic_verify_and_commit()`. |

---

## Configuration Changes

### Removed Environment Variables

None of the following are hard-deleted in Wave 1–3 of the cleanup plan —
they are **consolidated into `config/thresholds/` JSON files** and their
direct `os.getenv()` reads are removed from source. Setting these
environment variables in `v3.0.1` will have **no effect** once the
corresponding module is migrated; use the config file instead.

| Variable | Replacement | Migration |
|----------|-------------|-----------|
| `FRIA_ZONE_ALLOW`, `FRIA_ZONE_DEFER` | *(renamed in P6-1)* `AGENT_CONFIDENCE_THRESHOLD`, `CONFIDENCE_DEFER_FLOOR` → `confidence.agent_threshold` / `confidence.defer_floor` in [`config/governance_thresholds.json`](../config/governance_thresholds.json) | See P6-1 below. |
| `AGENT_CONFIDENCE_THRESHOLD` | `config/thresholds/*.json` | Move the value into config; the two independent read sites in [`src/gateway/governance/governor/stages/confidence.py`](../src/gateway/governance/governor/stages/confidence.py) are consolidated into a single read via `get_agent_confidence_threshold()`. |
| `CAUSAL_LOCK_P_VALUE_THRESHOLD`, `CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE`, `CAUSAL_LOCK_RISK_BOUNDARY` | `config/thresholds/*.json` | Move MRM/ISO 42001 §A.9.4-governed threshold values from env vars ([`src/gateway/governance/causal/gatekeeper.py:80-110`](../src/gateway/governance/causal/gatekeeper.py:80)) into the versioned config file. This also gives an audit trail for threshold changes. |
| `NEMO_AUTO_APPLY_ENABLED` | *(deleted, not migrated)* | This variable is removed entirely as part of CR-2 (the legacy auto-apply code path is deleted). Setting it in v3.0.1 has no effect regardless of value. |
| `KMS_BATCH_MAX_SIZE`, `KMS_BATCH_ENABLED` | `config/thresholds/*.json` | **Resolved:** The default is standardized to `"false"` across `kms_batch_signer.py` and `main.py`. Batch configuration is loaded via schema thresholds. |
| `CAUSAL_MIN_SAMPLES`, `CAUSAL_CACHE_TTL_SECONDS`, `TELEMETRY_MAX_STALENESS_SECONDS` | `config/thresholds/*.json` | Consolidated to `config/thresholds/*.json` via accessor functions like `get_telemetry_max_staleness_seconds()`. |

### New Required Configuration

| Config | Purpose | Default |
|--------|---------|---------|
| `config/governance_thresholds.json` — `confidence.agent_threshold`, `confidence.defer_floor` | Replaced `FRIA_ZONE_ALLOW`/`FRIA_ZONE_DEFER` (renamed again in P6-1) | `0.95` / `0.70` |
| `config/thresholds/<REGION>_BASELINE.json` — `agent_confidence_threshold` key | Replaces `AGENT_CONFIDENCE_THRESHOLD` | Matches current env var default (confirm exact value in [`src/gateway/governance/governor/stages/confidence.py`](../src/gateway/governance/governor/stages/confidence.py) before upgrading) |
| `config/thresholds/<REGION>_BASELINE.json` — `causal_lock_*` keys | Replaces the three `CAUSAL_LOCK_*` env vars | Matches current env var defaults; confirm with MRM/ISO 42001 owner before upgrading |
| `config/thresholds/<REGION>_BASELINE.json` — `kms_batch_*` keys | Replaces `KMS_BATCH_MAX_SIZE`/`KMS_BATCH_ENABLED` | `32` / `false` (standardized across modules) |
| `config/thresholds/<REGION>_BASELINE.json` — `causal_min_samples`, `causal_cache_ttl_seconds`, `telemetry_max_staleness_seconds` keys | Replaces the three misc causal/telemetry env vars | Matches current defaults (`30`, `300`, `300`) |

### Feature Flags Graduated

| Flag | New Behavior |
|------|--------------|
| `CAGE_DEFER_ENABLED` | **Not graduated in v3.0.1** (explicit recommendation in the cleanup plan §2.4). The flag remains, still defaulting to `"true"`. If your deployment currently sets this to `"false"` to force the DENY-fallback path, that behavior is **unchanged** in v3.0.1. This is a deliberate deviation from the "graduate stable flags" theme of this release — flagged here so consumers do not assume removal. |
| `KMS_BATCH_ENABLED` | **Resolved.** The Wave 0 discrepancy is closed: the confirmed default is `"false"` (disabled), matching [`KmsBatchThresholds.enabled`](../src/gateway/governance/schemas/thresholds.py:277) (`Field(default=False, ...)`) and [`config/governance_thresholds.json`](../config/governance_thresholds.json:56) (`"enabled": false`). The flag is **not graduated** — `KMS_BATCH_ENABLED` remains a valid env-var override of the config default via `get_kms_batch_enabled()`. **Known documentation debt (not yet code-fixed):** the startup comment at [`main.py:213`](../src/compliance_bridge/main.py:213) still incorrectly states "The signer is enabled by default (kms_batch.enabled=true..." — this comment is stale and requires a follow-up code change (out of scope for this documentation-only correction) to align with the verified `false` default. |

---

## Behavioral Changes

- **Region-aware control/SLA/event-map lookups become mandatory.** Any code
  path that previously read the flat `CONTROL_META`, `EVIDENCE_SLA_SECONDS`,
  or `ISO_CONTROL_MAP` dicts saw **universal (ISO 42001) entries only**. After
  migrating to `get_control_meta(region)` / `get_sla_seconds(region)` /
  `get_iso_control_map(region)`, callers that pass a recognized
  `CAGE_DEPLOYMENT_REGION` value (`US_FED`, `EU_ECB`, `APAC_MAS`) will now see
  **additional jurisdictional entries merged in** that were previously
  invisible to universal-only consumers. If your integration relied on the
  old universal-only behavior (e.g., counting exactly 4 SLA entries), that
  count will change once you pass a real region instead of an unrecognized
  placeholder.
- **`create_ftra_node()` no longer emits `DeprecationWarning` for
  `registry_path`/`plan_key`** — because those parameters no longer exist,
  attempting to pass them raises `TypeError: unexpected keyword argument`
  instead of a warning.
- **NeMo refinement can no longer be applied without human approval**, even
  in environments that previously set `NEMO_AUTO_APPLY_ENABLED=true`. All
  refinement changes must go through the `propose-refinement` →
  `approve-refinement` flow. This closes the "recursive self-authentication"
  loop flagged in [`server.py:849-851`](../src/governed_financial_advisor/server.py:849).
- **`CBF.update_state()` is renamed to `_update_state_unsafe()` (CR-3).**
  All external callers must call `atomic_verify_and_commit()`. Direct calls to
  `update_state()` will raise `AttributeError`. Calling `atomic_verify_and_commit()`
  closes the MED-5 TOCTOU window by executing the barrier check and balance deduction
  atomically within Redis.
- **Threshold overrides via environment variable stop taking effect** for
  every variable listed under [Removed Environment Variables](#removed-environment-variables).
  Any CI/CD pipeline, Helm chart, or Terraform variable that injects these as
  env vars will silently have no effect post-migration — the values must be
  moved into the corresponding `config/thresholds/*.json` file instead. This
  is the single most likely "silent" breaking change in this release since
  no exception is raised; verify with the `Migration Guide's test
  verification step`.

---

## Compliance Impact

Per [`AGENTS.md`](../AGENTS.md) Architecture & Design Standards, changes to
`src/compliance_bridge/`, `config/compliance/`, and `config/thresholds/` are
shared cross-region modules deployed simultaneously to all three regional
postures. The following items affect compliance posture:

- **MR-1 (`CONTROL_META`), MR-2 (`EVIDENCE_SLA_SECONDS`), MR-3
  (`ISO_CONTROL_MAP`)** — impact **all three regions** (`US_FED`, `EU_ECB`,
  `APAC_MAS`) because the accessor functions these aliases are replaced by
  are the mechanism through which jurisdictional controls (NIST SP 800-53,
  EU AI Act/DORA, MAS FEAT/Notice 655) become visible to consumers. No
  control is *removed* from any framework mapping — the change is purely in
  how much of the merged view a given caller sees. Confirm your OSCAL SSP
  export ([`src/gateway/governance/oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py:436))
  and Lula validation manifests (`compliance/lula/`) do not reference the
  deprecated symbol names directly.
- **CR-1 (Evidence Stream dual-schema v1.0/v1.1)** — **US_FED, EU_ECB,
  APAC_MAS all impacted.** This is the cryptographic hash-chain integrity
  mechanism for the audit evidence trail. **Superseded — see
  [Backward-Compatibility Remediation](#backward-compatibility-remediation)
  below.** The "data-migration completeness gate" and retained archival
  read-only path described in earlier revisions of this document were
  artifacts of a production-deployment framing that does not apply to this
  repository. The entire dual-schema apparatus — including the archival
  migration helpers — has now been **deleted**, and the schema sentinel
  advanced to `cage-evidence-stream/2.0`. No v1.0 or v1.1 read path remains.
- **CR-2 (NeMo auto-apply removal)** — governance-integrity concern, not a
  region-specific compliance-framework change; affects the audit trail for
  NeMo Guardrails refinement across all regions equally.
- **CR-3 (CBF `update_state()`)** — financial-invariant/concurrency-safety
  concern; not itself a compliance-framework mapping change, but flagged to
  Security given the CBF's role in fiscal control enforcement (`SC-4`).
- **SR-1 (`stpa_validator.py`)** — confirm Lula validation manifests in
  `compliance/lula/` do not reference the deleted module path; confirm the
  OSCAL SSP export still resolves STPA control evidence via
  `generated_stpa_validator.py` post-removal.
- **EV-3/EV-6 (Causal Lock / telemetry threshold consolidation)** — MRM- and
  ISO 42001 §A.9.4-governed thresholds; migrating them into a versioned
  config file is a compliance **improvement** (adds an audit trail for
  threshold changes) but requires coordination with the same compliance
  owner as CR-1 given the shared governance surface.

**Action required for compliance-touching PRs:** per [`AGENTS.md`](../AGENTS.md)
Compliance Artifact Obligations, an OSCAL component update in
`compliance/oscal/` is required within 2 business days of merge for any PR
implementing MR-1–3 or CR-1. Region-gated CI must be run explicitly for all
three postures (`CAGE_DEPLOYMENT_REGION=US_FED|EU_ECB|APAC_MAS`) before
considering these items complete — see the `Migration Guide's test
verification step`.

---

## Evidence Hash Canonicalization (FlowSignal Phase 2)

**Breaking Change:** Evidence and attestation hash computation in [`normative_provider.py`](../src/gateway/governance/normative_provider.py) migrated from `json.dumps(sort_keys=True)` to RFC 8785 JCS canonicalization.

| Function/Method | Old Algorithm | New Algorithm | Impact |
|---|---|---|---|
| async FRIA attestation (removed in P6-2) | `hashlib.sha256(json.dumps(action_context, sort_keys=True).encode()).hexdigest()` | `hashlib.sha256(jcs_canonicalize_plan(action_context)).hexdigest()` | Evidence hash values will differ for payloads containing floats (e.g., `1.0` → `"1"` in JCS vs `"1.0"` in json.dumps) |
| [`NormativeProviderDaemon.boot_fetch()`](../src/gateway/governance/normative_provider.py:756) cached profile hash | `hashlib.sha256(json.dumps(cached, sort_keys=True, separators=(",", ":")).encode()).hexdigest()` | `hashlib.sha256(jcs_canonicalize_plan(cached)).hexdigest()` | Cached baseline change-detection hash now matches [`NormativeBaseline.profile_hash`](../src/gateway/governance/normative_provider.py:209) property (already using JCS) |

**Who is affected:** External systems that independently recompute evidence hashes for verification, or stored evidence records that reference pre-migration digest values. No such external integrations are currently known in this reference architecture.

**Migration:** Hash values computed pre-migration are not backward-compatible. This is an accepted breaking change in the v3.x reference architecture release to achieve deterministic cross-language canonicalization. See FlowSignal integration plan §5.3 and the float-divergence test in [`tests/test_jcs_canonicalizer.py`](../tests/test_jcs_canonicalizer.py:136).

---

## Backward-Compatibility Remediation

> **Governing posture change.** [`AGENTS.md`](../AGENTS.md) was amended during
> this work: the "data already at rest" backward-compatibility exception was
> **deactivated** and relocated verbatim to a new
> *Dormant Rules — Reactivate When CAGE Begins Real Deployments* section. The
> active posture is now unconditional — breaking changes are preferred, with
> **no carve-out for any category of change**, including persisted, signed
> artifacts. This is why the WORM/KMS signing path below was migrated without
> a compatibility shim.

This release completes the RFC 8785 JCS canonicalization migration and removes
every remaining backward-compatibility shim, legacy fallback, and duplicated
legacy field identified by a full code-inspection sweep. Tracking IDs
`BC-01`–`BC-08` match the analysis in
[`plans/poam_backward_compat_remediation_plan.md`](../plans/poam_backward_compat_remediation_plan.md);
the corresponding closed POAM findings are `POAM-2026-060` and
`POAM-2026-062`–`POAM-2026-068` in [`docs/POAM.md`](POAM.md).

### Hash-chain canonicalization and `/2.0` schema sentinels

**Breaking Change:** the `ContextAccumulator` and `EvidenceStreamSink` audit
hash chains now canonicalize with RFC 8785 JCS (`jcs_canonicalize_plan()`)
instead of `json.dumps(..., sort_keys=True)`. Write and verify paths were
migrated **atomically in the same change**, so a build is never in a state
where it fails to verify records it just wrote.

| Module | Old sentinel | New sentinel |
|---|---|---|
| [`src/gateway/governance/evidence/stream.py`](../src/gateway/governance/evidence/stream.py) | `cage-evidence-stream/1.1` | `cage-evidence-stream/2.0` |
| [`src/compliance_bridge/context_accumulator.py`](../src/compliance_bridge/context_accumulator.py) | `cage-context-accumulator/1.1` | `cage-context-accumulator/2.0` |

**Who is affected:** any deployment holding evidence or context-accumulator
records written before this change.

**Migration:** records written pre-change **will fail verification** under the
new algorithm. No dual-read path is provided. These chains are self-verifying —
the verifier recomputes each digest with the same function the writer used, and
no independently-stored ground-truth digest exists — so writer and verifier
migrate together and the break is confined to pre-existing records. The `/2.0`
sentinel makes the break self-identifying: a record carrying a `/1.1` sentinel
is unambiguously pre-migration. Adopters holding pre-change chains should
archive them alongside the CAGE version that produced them and start a fresh
chain; there is no in-place upgrade.

**Note on `default=str`.** `jcs_canonicalize_plan()` has no `default=` escape
hatch, so payloads that previously relied on `default=str` for `datetime` and
`Decimal` values now receive explicit pre-normalization — `_normalize_for_jcs()`
in the compliance-bridge modules, and an inline `_normalize()` elsewhere. If you
have subclassed or wrapped these writers, ensure your payloads contain only
JSON-native types before canonicalization or `jcs_canonicalize_plan()` will
raise rather than silently coerce.

### WORM / KMS signing algorithm

**Breaking Change:** `_sign_record()` in
[`src/gateway/governance/uca_logger.py`](../src/gateway/governance/uca_logger.py)
now builds its KMS signing payload with RFC 8785 JCS instead of
`json.dumps(..., sort_keys=True)`.

**Who is affected:** any deployment with UCA records already written to a WORM
bucket and signed under the previous algorithm.

**Migration:** **no compatibility shim is provided.** Previously-signed WORM
records will not verify against a re-serialization produced by the new code,
and WORM semantics mean they cannot be re-signed in place. An auditor verifying
a pre-change record must use a CAGE build from before this change. Adopters who
require continuous verifiability of an existing WORM archive should pin the
prior release for their verification tooling and cut over new records only.
This break is accepted under the amended [`AGENTS.md`](../AGENTS.md) posture
described in the callout above.

### `EvidenceRecord.schema_version` and dual-schema function removal (BC-01)

**Breaking Change:** the evidence-stream dual-schema apparatus is deleted.

| Removed symbol | Module | Replacement |
|---|---|---|
| `_detect_schema_version()` | [`src/gateway/governance/evidence/stream.py`](../src/gateway/governance/evidence/stream.py) | *(none — all records are `/2.0`; there is nothing to detect)* |
| `migrate_record_1_0_to_1_1()` | same | *(none — v1.0 read support was already removed; the helper had zero production callers)* |
| `get_last_v1_0_hash()` | same | *(none)* |
| `_link_hash_v1_1()` | same | Collapsed into `_link_hash()`, whose header fields are now unconditional |
| `EvidenceRecord.schema_version` field | same | *(none — removed from the dataclass, from `verify_record()`, and from `VerifyResult`)* |

**Migration:** stop reading `record.schema_version` — the attribute no longer
exists and access raises `AttributeError`. Any consumer branching on schema
version should be simplified to the single `/2.0` shape. `tests/test_dual_schema_verification.py`
was deleted; its still-relevant hash-determinism and tamper-detection assertions
were folded into [`tests/test_evidence_stream.py`](../tests/test_evidence_stream.py).

### TTL-bounded artifacts — tokens, seals, and signed balances

These formats changed because their canonicalization changed. All are bounded
by a short TTL, so the disruption is time-boxed rather than permanent.

| Artifact | Module | TTL | Impact during rolling deploy |
|---|---|---|---|
| ConsequenceToken JWS header + payload | [`src/gateway/governance/consequence_token.py`](../src/gateway/governance/consequence_token.py) | 60 s | Tokens minted by a pre-migration pod are rejected by a post-migration pod. Brief 401/`ConsequenceTokenError` rate during cutover, self-clearing within the TTL. |
| Routing seal (v2 HMAC `_canonical_payload()` and v3 JWT claims) | [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) | 30 s | Seals issued pre-cutover fail verification post-cutover. Single-use burn semantics are unchanged. Self-clearing within 30 s. |
| Reconciliation signed balance | [`src/gateway/governance/reconciliation/daemon.py`](../src/gateway/governance/reconciliation/daemon.py) | 300 s | A balance signed pre-cutover will not verify post-cutover. The CBF **fails closed** on an unverifiable or expired balance, so a deployment may see up to 5 minutes of conservative DENY behavior until the reconciliation worker writes a freshly-signed balance. |

**Migration:** none required for correctly-behaving clients — retry after the
relevant TTL. Do **not** attempt a partial rollout that leaves pre- and
post-migration pods serving the same seal or token population for longer than
the TTL; drain rather than trickle. Note that the ConsequenceToken *verify*
path decodes the transmitted JWS segments rather than re-serializing them, so
only mint-time output changed — RFC 7515 exact-bytes verification is preserved.

### Cache-key changes

Canonicalization changes also altered the digest inputs used as cache keys:

| Cache | Module | Effect |
|---|---|---|
| OPA decision cache key | [`src/gateway/core/policy.py`](../src/gateway/core/policy.py) | One-time full cache miss on deploy; 10 s TTL repopulates immediately |
| Query cache key | [`src/governed_financial_advisor/infrastructure/query_cache.py`](../src/governed_financial_advisor/infrastructure/query_cache.py) | One-time full cache miss; default 3600 s TTL repopulates on demand |
| Control-registry profile hash | [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py) | Recomputed on every registry load; a one-time drift-detection delta is expected on first startup after upgrade |
| Provider receipt / state digests | [`src/integrations/provider_03/provider.py`](../src/integrations/provider_03/provider.py), [`src/integrations/provider_02/adapter.py`](../src/integrations/provider_02/adapter.py) | Digest values returned to callers change; CAGE does not persist them |
| `policy_version_id` fallback input | [`src/gateway/governance/ingress/policy_translator.py`](../src/gateway/governance/ingress/policy_translator.py) | Recomputed on every translation run |

**Migration:** no action required. Expect one cold-cache interval and a
transient latency increase immediately after deployment. If you assert on
specific cache-key strings or profile-hash values in your own tests, regenerate
those fixtures.

### FlowSignal / Provider 01 — `decision` is now mandatory (BC-03)

**Breaking Change:** [`src/integrations/provider_01/provider.py`](../src/integrations/provider_01/provider.py)
no longer accepts the legacy binary `admitted`/`findings` response shape. The
FlowSignal tri-state `decision` field is now **required**.

| Response contains | Old behavior | New behavior |
|---|---|---|
| A recognized `decision` value | Tri-state mapping via `_map_flowsignal_decision()`, ConsequenceToken minted | Unchanged |
| No `decision`, but `admitted: true` | **Admitted** — governance mapping skipped entirely | **Fails closed** — `ValidationResult(admitted=False)` with a structured finding carrying `code="cage.endpoint_error"` |
| No `decision`, `admitted: false` | Rejected | Fails closed with the same structured finding |
| An unrecognized `decision` value | Fell through to the legacy branch | Fails closed with the same structured finding |

**Why this matters.** The old fallback was a latent fail-open: any response
that lost its `decision` key — including a proxy error page that happens to
parse as JSON with a truthy `admitted` — was admitted without ever passing
through tri-state governance mapping or token minting. Two tests in the
Universal Protocol Conformance Suite were locking that behavior in; they have
been **inverted** so the fail-closed contract is now the asserted one.

**The three valid values.** Provider 01's tri-state vocabulary is exactly
`ALLOW`, `REFUSE`, `ESCALATE`, matched case-insensitively
([`provider.py`](../src/integrations/provider_01/provider.py:74)). Any other
string — including `REVIEW`, which belongs to Provider 06's unrelated
`PASS`/`REVIEW`/`BLOCKED` vocabulary — raises inside
`_map_flowsignal_decision()` and is returned as a fail-closed
`PARSE_ERROR` finding.

| `decision` | `admitted` | Finding code | Severity | Effect |
|---|---|---|---|---|
| `ALLOW` | `True` | `CONSEQUENCE_TOKEN` | `info` | ConsequenceToken JWS minted and attached |
| `REFUSE` | `False` | `FLOWSIGNAL_REFUSE` | `blocked` | Hard deny |
| `ESCALATE` | `False` | `FLOWSIGNAL_HOLD` | `review` | `needs_human_review: true` → parks in `DeferQueue` |
| Unrecognized | `False` | `PARSE_ERROR` | `blocked` | Fail-closed |
| *(absent)* | `False` | `cage.endpoint_error` | `blocked` | Fail-closed (this BC-03 change) |

**Migration:** vendor endpoints must emit `decision` on every response. If you
operate a FlowSignal-compatible endpoint that still returns the binary shape,
add the `decision` field before upgrading — CAGE will otherwise reject all its
responses. Map upstream non-binary verdicts (`REVIEW`, `ESCALATE`) per the
tri-state guidance in [`AGENTS.md`](../AGENTS.md) so they park in the
`DeferQueue` rather than failing. Note the direction of that mapping for this
provider specifically: an upstream `REVIEW` must be emitted to CAGE as
`ESCALATE`, because `REVIEW` is not in Provider 01's accepted set.

### FlowSignal / Provider 01 — `authority_record_id` is required on `ALLOW`

**Companion requirement — a separate failure mode from BC-03, and not part of
it.** BC-03 covers a response that omits `decision` entirely. This covers a
response that is well-formed, carries `decision: "ALLOW"`, and is *still*
rejected.

On `ALLOW`, CAGE mints a ConsequenceToken before admitting the action. The mint
requires `authority_record_id` in the same `POST /validate/fria` response body;
[`_mint_consequence_token()`](../src/integrations/provider_01/provider.py:128)
raises when it is absent. A mint failure does not degrade to a warning — it
produces a `CONSEQUENCE_TOKEN_MINT_FAILED` finding with severity `blocked`, and
[`validate_fria()`](../src/integrations/provider_01/provider.py:357) then
overrides `admitted` back to `False`.

| Response on `ALLOW` | Outcome |
|---|---|
| `decision: "ALLOW"` **+** `authority_record_id` | `admitted=True`, `CONSEQUENCE_TOKEN` finding carrying the JWS |
| `decision: "ALLOW"`, no `authority_record_id` | **`admitted=False`**, `CONSEQUENCE_TOKEN_MINT_FAILED` (severity `blocked`) |

`authority_state_version` is read from the same body but is nullable — its
absence does not block. The other two mint inputs, `actor_id` and `thread_id`,
come from the CAGE-side FRIA request payload rather than from the vendor
response.

**Migration:** endpoints emitting `decision: "ALLOW"` must also emit
`authority_record_id`. An endpoint that satisfies BC-03 but omits this field
will see every `ALLOW` converted to a denial, which is the intended
fail-closed behavior: CAGE will not admit a consequential action it cannot
bind to an authority record.

### Provider 03 — compatibility aliases removed (BC-02)

**Breaking Change:** three dict-returning shadow methods on
`Provider03NormativeProvider` are deleted from
[`src/integrations/provider_03/provider.py`](../src/integrations/provider_03/provider.py).

| Removed method | Replacement | Return type change |
|---|---|---|
| `fetch_legal_baseline()` | `fetch_baseline()` | `dict` → `NormativeBaseline` |
| `validate_external_fria()` | `validate_fria()` | `dict` → `ValidationResult` |
| `submit_evidence_chain()` | `submit_evidence()` | `dict` → `EvidenceSeal` |

**Migration:** call the canonical `NormativeProvider` protocol methods and read
the dataclass fields instead of dictionary keys. Note that
`validate_external_fria()` returned a hardcoded `APPROVED` verdict — any caller
relying on its return value was not receiving a real governance decision, so
switching to `validate_fria()` may surface rejections that were previously
invisible. This is the intended behavior.

### `VALID_DECISIONS` narrowed to the canonical six (BC-04)

**Breaking Change:** `VALID_DECISIONS` in
[`src/gateway/governance/provenance_chain.py`](../src/gateway/governance/provenance_chain.py)
drops the two execution-phase statuses and now contains exactly:
`ALLOW`, `DENY`, `DEFER`, `NARROW`, `PAUSE`, `REQUIRE_APPROVAL`
(since P4-1 below, `PAUSE` is gone too and the set is derived from the
`GovernanceDecision` enum).

| Removed value | Canonical replacement |
|---|---|
| `BLOCK` | `DENY` |
| `ESCALATE` | `REQUIRE_APPROVAL` |

**Migration:** every emitter writing into the provenance chain must stop
sending `BLOCK` and `ESCALATE`. `build_provenance_record()` now raises
`ValueError` for either value rather than accepting it. If you translate
LangGraph execution-phase statuses (`APPROVED`/`BLOCKED`/`ESCALATED`) into
provenance records, perform the remap at your gateway boundary — the canonical
vocabulary must not be widened again, since `BLOCK` and `DENY` were previously
indistinguishable to a downstream auditor.

### DEFER response fields removed (BC-05)

**Breaking Change:** duplicated legacy keys are removed from every DEFER
response body and from the `DeferResponse` model.

| Removed field | Canonical replacement | Emitted by (before) |
|---|---|---|
| `verdict` | `decision` | [`decisions.py`](../src/gateway/governance/decisions.py), [`agent_gateway_adapter.py`](../src/gateway/server/agent_gateway_adapter.py) |
| `defer_id` | `defer_token` | [`src/gateway/governance/governor/governor.py`](../src/gateway/governance/governor/governor.py) |
| `missing_input_reason` | `classification_reason` | [`decisions.py`](../src/gateway/governance/decisions.py), [`agent_gateway_adapter.py`](../src/gateway/server/agent_gateway_adapter.py) |

**Migration:** clients parsing DEFER responses must read `decision`,
`defer_token`, and `classification_reason`. The removed keys are absent from the
JSON body entirely — a client using `body["verdict"]` will raise `KeyError`
rather than silently degrading, which is deliberate. This affects the
`/validate-action` DEFER path and the `/v1/defer/*` polling responses.

### `rollback()` requires an explicit window (BC-07)

**Breaking Change:** `rollback()` in
[`src/gateway/governance/safety/resource_guard.py`](../src/gateway/governance/safety/resource_guard.py)
now raises `ValueError` when called with neither `window_key` nor `token`.

**Why this matters.** The removed legacy fallback silently targeted the
*current* window rather than the window the reservation was made against. That
guaranteed `target == current`, so the cross-window guard immediately below it
could never fire — nullifying the control added under POAM-2026-058.

**Migration:** pass the `ReservationToken` returned at reservation time
(`rollback(token=reservation_token)`), or supply an explicit `window_key`.
Calls relying on the implicit fallback now fail loudly instead of rolling back
against the wrong window.

### Missing regional baseline now fails at startup (BC-08)

**Breaking Change:** [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py)
no longer falls back to `config/control_mappings.json` with `region="LEGACY"`
when the regional compliance profile is absent. `_LEGACY_PATH` is deleted and
`ControlRegistry` raises `RuntimeError` at startup.

**Why this matters.** A region-guarded system that silently degrades to a
non-regional profile emits audit spans with jurisdictionally wrong citations —
the defect class closed by POAM-2026-034, -035 and -036. The fallback
reintroduced it through the back door.

**Migration:** every deployment must provision the baseline file for its region
before startup:

```
config/compliance/US_FED_BASELINE.json
config/compliance/EU_ECB_BASELINE.json
config/compliance/APAC_MAS_BASELINE.json
```

Provide the file matching `CAGE_DEPLOYMENT_REGION`. A deployment that
previously started successfully by falling through to the legacy mappings will
now fail fast with `RuntimeError: Cannot start governance engine without a
valid profile`. Treat this as a configuration prerequisite of the upgrade, not
a runtime error to be caught.

### Explicitly unchanged

The **routing seal v2 HMAC-SHA256 signing mode** is retained. Despite the
`v2`/`v3` naming it is not a version-negotiation shim for older clients — it is
the KMS-free signing mode required for local development, CI, and the offline
`local`/`unit` test markers. It is already fail-closed in production
(`SymbolicGovernorViolation` with a `[DOWNGRADE_ATTACK]` log under
`CAGE_SEAL_STRICT_MODE`). Only its canonicalization changed, as described under
[TTL-bounded artifacts](#ttl-bounded-artifacts--tokens-seals-and-signed-balances).
Recorded as a deliberate no-change decision (BC-06) in [`docs/POAM.md`](POAM.md).

---

## Architectural Decoupling Clean Breaks (AW-1 through AW-8)

Per the Core Architectural Principle in [`AGENTS.md`](../AGENTS.md), CAGE is a reference architecture that prioritizes clean, legible architecture and modular layer separation over backward compatibility. The following clean breaks decouple CAGE from vendor-specific leaks:

| Item | Wave | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **AW-1** | W1.5 | Implicit GCS activation eliminated. Cold storage now requires explicit `EVIDENCE_COLD_STORE` ∈ `{gcs, s3, null}`, defaulting to `null`. | Backend selection becomes an explicit architectural decision instead of an emergent property of which bucket env var happens to be set. | Unset → `null` backend, startup WARNING, and Prometheus metric `cage_evidence_cold_store_available{backend="null"}`. |
| **AW-2** | W1.4 | `EVIDENCE_STREAM_GCS_BUCKET*` removed. Replaced by `EVIDENCE_COLD_STORE_BUCKET*` and `config/compliance/residency.json`. **No alias is read.** | The `GCS` infix was a vendor leak in adopter-facing configuration. Residency policy moved from Python code to declarative config. | Loud `MissingBucketConfigError` raised on startup if unconfigured. |
| **AW-3** | W1.5 | `STORAGE_BACKEND` and duplicate OSCAL S3 dispatcher in `storage.py` removed. Consolidated into unified `EvidenceColdStore`. | Satisfies invariant I-3: one unified cold store interface across all subsystems. Fixes applied once. | Stale helper calls fail at import; callers use `put_oscal_artifact_atomic()` or `EvidenceColdStore`. |
| **AW-4** | W2.1 | `src.compliance_bridge.evidence_stream` promoted to `src.gateway.governance.evidence.stream`. Lazy kernel→bridge imports severed. **No compatibility shim.** | Enforces strict Three-Layer Architecture: Layer 1 (kernel) must never import from Layer 3 (bridge). Enforced by Gate G3. | `ModuleNotFoundError` on any stale import or patch path. |
| **AW-5** | W1.7 | `src.cage_finance.safety.cbf` shim deleted. | Eliminates forbidden shim in domain package; canonical CBF engine lives in kernel. | `ModuleNotFoundError` at collection. |
| **AW-6** | W1.6 | Raw `"langfuse.*"` string literals banned outside `attributes.py`. Enforced by CI Gate G7. | Enforces OTLP wire format neutrality. Kernel attributes imported from `src.gateway.observability.attributes`. | CI Gate G7 fails with file and line number. |
| **AW-7** | W1.5 | Silent tolerance of `CAGE_ENV=prod` + `EVIDENCE_COLD_STORE=null` blocked. | Refuses to run production posture without durable cold storage unless explicitly overridden. | Fails fast with `RuntimeError` on startup unless `CAGE_ALLOW_NONBLOCKING_PROD=true`. |
| **AW-8** | W1.6 | `LangfuseTelemetryProvider.from_env()` silent fallback to `MockTelemetryProvider` eliminated. | Prevents causal gatekeeper from governing on fabricated synthetic data when credentials are missing. | Raises explicit `ConfigurationError` when credentials are missing. |

---

## Post-v3.0.1 Seam Contracts & Provider Conformance Clean Breaks (2026-09-09)

Following the v3.0.1 major release, 19 feature branches were implemented to complete seam decoupling, remediate contract drift, and stabilize the test suite across 3,921 passing tests (4,148 collected tests):

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **SC-1** | Seams | Seam contracts extracted into `src/gateway/governance/seams/{normative,attestation,actuation,graph_topology}.py` with **ZERO imports from the kernel**. | Eliminates circular dependencies between the kernel and vendor integration packages. | `ImportError` on importing seam contracts from old module locations (`normative_provider`, `attestation_provider`, `execution_actuator`). |
| **SC-2** | Hold | `DeferReason.FLOWSIGNAL_ESCALATION` renamed to `DeferReason.EXTERNAL_HOLD`. Vendor-specific branch in `enforce_fria_boundary()` removed. | Generalizes external hold mechanism across all providers; drives TTL dynamically from finding fields (`hold_ttl_seconds`). | `AttributeError` on `DeferReason.FLOWSIGNAL_ESCALATION`. |
| **SC-3** | Attestation | `provider_name` added as first-class field on `ExternalAttestation`. Error smuggling via `attestation_type="PROVIDER_ERROR:{name}"` eliminated (POAM-2026-072). | Prevents single-provider exceptions from aborting the entire fetch loop; ensures full non-repudiation (AU-10/AU-12). | Callers filtering by `PROVIDER_ERROR` prefix will miss errors; inspect `fetch_error` and `provider_name` instead. |
| **SC-4** | Evidence | Complete `RefusalReceipt` v3 objects (and, until P4-1, `PauseReceipt`) serialized into evidence stream via `dataclasses.asdict()`. | Preserves 5-part proof chain, `tier_failures`, and byte-identical `proof_hash` in audit trail. | Stale consumers expecting flat refusal summaries must parse v3 nested receipt structure. |
| **SC-5** | Tokens | Consequence token minting moved exclusively to kernel (`src/gateway/governance/consequence_token_service.py`). | Prevents external adapters from minting consequence authorizations outside kernel governance. | Direct calls to external adapter token generators fail or lack kernel signature validation. |
| **SC-6** | Provider 02 | Provider 02 adheres to `AttestationProvider` protocol; verifies Ed25519 CER signatures against key manifest. | Fails closed on unverified CER signatures to prevent forged causal evidence. | Unsigned or unverified CER payloads trigger immediate fail-closed rejection. |
| **SC-7** | Evidence KMS | Strict validation requiring KMS signing in `production` and `staging` postures. | Prevents running production evidence chains without cryptographic non-repudiation. | Fails fast with `ConfigurationError` on startup if KMS key is not configured in production. |

---

## v3.1.0 Clean Breaks — Zero-Trust Identity & Egress (2026-09-22)

Released in `v3.1.0`. See [`CHANGELOG.md`](../CHANGELOG.md) §[3.1.0] and the canonical
[`AGENT_IDENTITY_BINDING_SPEC.md`](architecture/AGENT_IDENTITY_BINDING_SPEC.md).

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **ZT-1** | Ingress identity | `X-Agent-ID` and `X-SPIFFE-ID` header parsing removed from [`inference_proxy.py`](../src/gateway/server/inference_proxy.py) and [`agent_gateway_adapter.py`](../src/gateway/server/agent_gateway_adapter.py). Under Linkerd mTLS, the Linkerd inbound proxy terminates TLS and sets `l5d-client-id` (`<sa>.<ns>.serviceaccount.identity.linkerd.<trust-domain>`); gateway ingress authentication and caller identity extraction live in [`src/gateway/server/workload_identity.py`](../src/gateway/server/workload_identity.py) (`WorkloadIdentityMiddleware` and `extract_client_identity(scope)`). | An HTTP header is client-controlled. Any caller able to craft a request could forge an agent identity, defeating every downstream tier that keys off `agent_id`. | **403** / **401** fail-closed rejection when no verified Linkerd workload identity is present. |
| **ZT-2** | Ingress identity | Body-derived identity (`body.get("agent_id")`) no longer honoured. | Same spoofing surface as ZT-1, one layer deeper. | Request is rejected before governance dispatch; the body field is ignored entirely. |
| **ZT-3** | Ingress identity | Anonymous fallback removed. There is no unauthenticated path. | Fail-closed boundary: an unidentifiable caller cannot be governed, so it must not be served. | 401 `authentication_required` rather than a degraded anonymous tier. |
| **ZT-4** | A2A authorization | Agent-to-agent trust is declared as SPIFFE **prefixes** (`authorized_parent_prefixes` in `config/agent_catalog.json`, matched by `startswith()` in [`agent_catalog.rego`](../config/opa/agent_catalog.rego)), not enumerated exact IDs. | Ephemeral pod suffixes in policy bodies caused spurious `POLICY_DRIFT_VIOLATION` on every restart. | Parent SPIFFE IDs outside a declared prefix are denied with `parent agent '%v' is not authorized to invoke subagent '%v'`. |
| **ZT-5** | Egress credentials | Adapters no longer hold outbound API credentials. The Layer 1 `CredentialBrokerAdapter` protocol ([`seams/credential_broker.py`](../src/gateway/governance/seams/credential_broker.py)) is invoked by the Layer 3 actuator as a pre-dispatch gate and the result is passed to `submit_envelope(extra_headers=...)`, keyed on agent SVID and tool name. | Credentials become a governed consequence rather than ambient adapter state; values are masked in logs and absent from the audit record. | `CredentialNotFound` / `CredentialAccessDenied` fail closed — no envelope is built, no signature produced, and no HTTP request issued. |
| **ZT-6** | Integrations | `src/integrations/provider_04/` removed. | Orphaned after the transition to `actuator_01`; zero residual references. | `ImportError` on `src.integrations.provider_04`. |

**Migration for ZT-1 – ZT-3:** present a mesh-issued mTLS client certificate with a
SPIFFE URI SAN. No compatibility shim is provided; the removed path was a spoofing
vector and a deprecation window would have preserved it.

---

## Unreleased — Single Committing Trade Run (Phase 0)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **TG-1** | Gateway API | `POST /governance/validate-action` runs the DRY_RUN profile in [`governor.py`](../src/gateway/governance/governor/governor.py): no seal, no scope reservation. `REQUIRE_APPROVAL` returns a `deferred_id` parked in the gateway [`DeferQueue`](../src/gateway/governance/defer_queue.py). The `APPROVED` verdict is no longer emitted. | A preview that commits budget or mints a seal turned every advisory check into a consequence; only the execution boundary may commit. | Callers expecting a `seal` field get none; [`GatewayClient.validate_action`](../src/governed_financial_advisor/infrastructure/gateway_client.py) raises `PermissionError` on `APPROVED` or on `REQUIRE_APPROVAL` without `deferred_id`. |
| **TG-2** | Gateway API | `POST /governance/revalidate-post-hitl` removed. Approved trades call `execute_trade_action(..., deferred_id=...)`; the gateway consumes the approval atomically and runs the POST_HITL profile in [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) (`enforce_approved_governance`). | Approval state held by the advisor was forgeable and replayable; custody now lives in the kernel and each approval authorises exactly one execution. | 404/405 on the removed route; a replayed, unapproved or mismatched `deferred_id` returns `BLOCKED`. |
| **TG-3** | Advisor graph | [`governed_trader_graph.py`](../src/governed_financial_advisor/graph/subgraphs/governed_trader_graph.py) enters at `executor`; HITL is reached only via a gateway `REQUIRE_APPROVAL`. `post_hitl_revalidate` is a slippage gate only. | The gateway, not the advisor, decides whether a human is needed. | Advisor-side approval thresholds have no effect. |

---

## Unreleased — Structural POST_HITL, FTRA Provenance, Conditional FTRA (Phase 1)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **P1-1** | Pipeline | `PROFILE_STAGES` and `PROFILE_RUNS_ALL_DOMAIN_TIERS` removed from [`pipeline.py`](../src/gateway/governance/governor/pipeline.py); selection is `stage_runs_under(profile, name=, mutating=)`. POST_HITL runs `opa` plus every claiming phase-2 tier. | A name list silently skipped plugin barriers (healthcare `dose_barrier`) after approval; selection now follows structure (`mutating`), not names. Proved in [`proof/model.py`](../proof/model.py) (`post_hitl_runs_every_phase2_tier`). | `ImportError` on `PROFILE_STAGES`. |
| **P1-2** | FTRA | `FTRA_IRREVERSIBLE` replaced by provenance codes (`FTRA_REGISTERED_IRREVERSIBLE`, `FTRA_REGISTERED_EXTERNALLY_REVERSIBLE`, `FTRA_UNREGISTERED_ACTION`, `FTRA_REGISTRY_ENTRY_INVALID`, `FTRA_REGISTRY_UNAVAILABLE`); `FtraBoundaryResult.from_classification` takes `registry_state=` instead of `in_registry=`. An unreadable registry is HARD (DENY). | One code hid whether the domain said "terminal" or the kernel defaulted to it; reviewers and auditors need the provenance, and an unreadable registry is not a reviewable state. | `TypeError` on `in_registry=`; consumers matching `FTRA_IRREVERSIBLE` see no match. Classification keys on `ViolationKind`, so verdicts are unchanged except UNAVAILABLE. |
| **P1-3** | FTRA registry | Optional signed `autonomous_envelope` in the terminal registry ([`classifier.py`](../src/gateway/governance/ftra/classifier.py), [`autonomy.py`](../src/gateway/governance/ftra/autonomy.py)). The digest covers `{autonomous_envelope, terminals}` when present; an unsigned envelope refuses to load. | Every in-range trade escalating to a human made HITL a rubber stamp; the ceiling is authority, so it is signed like the terminals. | A hand-edited envelope without `--rehash` fails the integrity check at load. |
| **P1-4** | Contracts | `PluginContribution.magnitude_extractor` added; `ConsensusContribution.magnitude_extractor` defaults to `None` and inherits the plugin's. | One magnitude reader per domain feeds consensus and conditional FTRA alike. | A domain without an extractor never clears FTRA autonomously and consensus sees magnitude 0.0. |
| **P1-5** | Finance tiers | [`CBFTierPlugin`](../src/cage_finance/tiers/cbf_tier.py) / [`FiscalTierPlugin`](../src/cage_finance/tiers/fiscal_tier.py) claim by `cost_resolver` cost > 0; `execute_trade_bounded` is now claimed. | A name list let a new cash-spending action bypass the barrier. | A malformed amount is a HARD `TIER_EXCEPTION`. |
| **P1-6** | Finance surface | `release_wire` removed from the finance registry, `REGISTERED_ACTIONS` and STPA UCA-11. | Tier 3 commercial-deployment-only interface (AGENTS.md); recorded as an OSCAL customer-responsibility statement. | `release_wire` is unregistered: `FTRA_UNREGISTERED_ACTION` (HITL), and no tier governs it post-approval. |

---

## Unreleased — Phase-2 Barrier Preview Before Human Approval (Phase 2)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **P2-1** | Pipeline | [`run_pipeline`](../src/gateway/governance/governor/pipeline.py) gates phase 2 with `phase2_mode(profile, phase1_kinds)`: `SKIP` on any HARD finding, `PREVIEW` (side-effect-free `preview()`) on only non-HARD findings or under `DRY_RUN`, `COMMIT` only over a clean phase 1. Previously phase 2 was skipped on *any* phase-1 finding. | A trade parked for a human was approved blind: a barrier that would refuse it (CBF, `dose_barrier`) was only consulted after the human had spent the review. Proved in [`proof/model.py`](../proof/model.py) (`no_commit_under_pending_findings`, `hard_preview_denies_before_hitl`). | A request with an OPA `MANUAL_REVIEW` and a HARD barrier breach is now `DENY` (`403`) instead of `REQUIRE_APPROVAL`; no DeferToken is parked. A `NARROWABLE` breach (`FISCAL_LIMIT_EXCEEDED`) still parks it, with the breach recorded. |
| **P2-2** | Pipeline | `_preview_mutating` stops at the first **HARD** preview finding and continues past non-HARD ones; the `DRY_RUN` loop previously stopped at the first violation of any kind. | The reviewer must see every breach the approved request would hit, and a later HARD barrier must still deny before a human is asked. | `validate_action()` may report more than one phase-2 violation. |
| **P2-3** | Verdict surface | `PipelineResult` gains `barrier_preview` (`BarrierPreview.PASS` / `FAIL` / `None`) and `preview_violations`. `validate_action()` meta and the DeferToken `opa_input_snapshot` carry `barrier_preview` and `barrier_preview_violations`. | Evidence for the reviewer, persisted with the token rather than recomputed. | Additive; strict schema consumers of the meta / snapshot must accept the new keys. |
| **P2-4** | Committing NARROW | [`SymbolicGovernor.govern()`](../src/gateway/governance/governor/governor.py) no longer denies a committing run that failed only on NARROWABLE findings when narrowing is enabled: `_sealed_narrow()` re-runs the sealed FULL pipeline on the clamped params and, inside the `ReservationScope`, writes `narrow:receipt:<seal>` via [`issue_narrow_receipt`](../src/gateway/governance/narrow_receipt.py) (`run_sealed(..., on_seal=)`). The domain tool consumes it via `narrow_receipt_key(seal)`. | The NARROW verdict had no committing path, so the execution boundary could never act on it. The receipt is written before the scope is marked sealed, so an undeliverable receipt rolls the commits back. | `govern()` may return a seal over narrowed params. A tool that ignores the receipt would execute the original params; [`tool_provider.py`](../src/cage_finance/tools/tool_provider.py) reads and burns it. |

---

## Unreleased — PAUSE Verdict and Pause Primitive Removed (Phase 4)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **P4-1** | Verdict lattice | `GovernanceDecision.PAUSE`, `PauseResponse`, `PauseReceipt`, `ViolationKind.TRANSIENT`, `PluginContribution.standing_projector`, `DecisionFlags.pause`, `is_cage_pause_enabled()` / `CAGE_PAUSE_ENABLED` and the whole `src/gateway/governance/pause_primitive.py` module are removed. The lattice is `ALLOW \| NARROW \| REQUIRE_APPROVAL \| DEFER \| DENY` ([`decisions.py`](../src/gateway/governance/decisions.py)). | No tier ever produced a `TRANSIENT` violation, so `PAUSE` was unreachable in every posture (the flag defaulted to **true**, not false as earlier docs said — reachability, not the flag, was the gate). A transient fault is a `HARD` violation: `DENY` with a refusal receipt, and the caller retries a fresh request. [`proof/model.py`](../proof/model.py) no longer models a `PAUSE` phase (`phases_closed` asserts the model names no verdict the runtime lacks; gated state count 52 → 42). | A client switching on `"PAUSE"` never sees it; [`gateway_client.py`](../src/governed_financial_advisor/infrastructure/gateway_client.py) drops it from `_ROUTABLE_VERDICTS`. `build_provenance_record(decision="PAUSE")` raises `ValueError` (`LEGACY_PAUSE` in [`provenance_chain.py`](../src/gateway/governance/provenance_chain.py)). |
| **P4-2** | HTTP surface | `GET /v1/pause/{token}` and `POST /v1/pause/{token}/resume` are removed from [`hybrid_server.py`](../src/gateway/server/hybrid_server.py); `_emit_pause_receipt` and the PAUSE branch are removed from [`governance_middleware.py`](../src/gateway/server/governance_middleware.py). | The endpoints served a verdict that could not occur. | `404` for stale callers. |
| **P4-3** | Workload identity | `OPEN_PATH_PREFIXES` is removed from [`workload_identity.py`](../src/gateway/server/workload_identity.py); `is_open_path()` is exact-match only over `OPEN_EXACT_PATHS`. The Linkerd `AuthorizationPolicy` / Helm `openGetPrefixes` lose the matching `PathPrefix` rules. [`tests/test_gateway_mesh_policy.py`](../tests/test_gateway_mesh_policy.py) now rejects any prefix match on the open route. | The only prefix was `/v1/pause/`; an open prefix is an authz footgun with no remaining user. | An unauthenticated GET under a former prefix is `401`. |
| **P4-4** | Evidence stream | `pause_token` stays in `EvidenceRecord` and the ClickHouse DDL as a **legacy, read-only, hash-covered** sparse header member ([`stream.py`](../src/gateway/governance/evidence/stream.py)); nothing writes it any more. | It is inside the `cage-audit/3.0` link hash; dropping it would make historical records unverifiable. | None — additive retention. |
| **P4-5** | Advisor state | `pause_resume_token` / `pause_reason` removed from [`graph/state.py`](../src/governed_financial_advisor/graph/state.py); `compliance/schemas/agent_state_schema.json` regenerated. | Dead fields. | Checkpoints carrying the keys are ignored by `TypedDict`; no migration. |

---

## Unreleased — Gateway Surface Cleanup (Phase 5)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **P5-1** | HTTP surface | `POST /governance/check` and `GovernanceCheckRequest` are removed from [`governance_middleware.py`](../src/gateway/server/governance_middleware.py). Use `POST /governance/validate-action` (body `{"action", "params", "policy_version_id"}`) or the MCP tool `simulate_governance_check`. | A second, non-committing decision route with its own `APPROVED`/`REJECTED` vocabulary duplicated `validate-action`. | `404` (or `403` first, from workload identity, for an unidentified caller). |
| **P5-2** | MCP tool | `simulate_governance_check` ([`mcp_tool_server.py`](../src/gateway/server/mcp_tool_server.py)) returns `verdict` (a `GovernanceDecision` value: `ALLOW` iff no violations, else `verify()`'s classified `decision`, fail-closed to `DENY`) instead of `status: APPROVED/REJECTED`. `SymbolicGovernor.verify()` now returns that `decision`. | One decision vocabulary across the gateway. | A caller reading `status` gets `None`; the advisor's [`evaluator_node.py`](../src/governed_financial_advisor/graph/nodes/evaluator_node.py) treats anything but `ALLOW` as unsafe. |
| **P5-3** | Governor | `SymbolicGovernor._run_checks()` is removed; tests and tools call `verify()` (DRY_RUN). | Legacy shim over `run_pipeline()`. | `AttributeError`. |
| **P5-4** | Pipeline stages | `OpaStage.decoded_verdict` and `FtraStage.result` are removed. `Stage.run()` may return a frozen `StageOutput(violations, opa_verdict, ftra)` ([`pipeline.py`](../src/gateway/governance/governor/pipeline.py)); `run_pipeline` threads it into later `StageContext`s and the `PipelineResult`, which also gains `barrier_outcome`. | Stage instances are shared across concurrent requests; per-request facts must not live on them. | Custom stages returning a list keep working (`as_stage_output`); code reading the removed attributes gets `AttributeError`. |
| **P5-5** | CBF | `ControlBarrierFunction.verify_action()` is a pure preview (`admits(balance, cost)`); the in-process `_local_debits` accumulator and `reset_local_debits()` are removed ([`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py)). Intra-window double-spend protection is the Redis `cbf:local_debits` list written by `atomic_verify_and_commit()` (superseded by the settlement-aware ledger, R2-1 below). | The accumulator was written only by previews and never reset, so repeated previews shrank later admissible cost. | Callers of `reset_local_debits()` get `AttributeError`; nothing replaces it. |
| **P5-6** | Approval binding | `revalidate_post_hitl(action, params, *, approved_barrier_preview, trace_id=None)` takes a required keyword. `DeferQueue.approve()` stamps `ApprovalRecord.approved_barrier_preview` from the token server-side; `consume_approval()` refuses an approval bound to another snapshot; the committing run refuses `PASS`→`FAIL` drift with `GovernanceError [APPROVAL_CONTEXT_DRIFT]` and mints no seal (`FAIL`→`PASS` is allowed) ([`governor.py`](../src/gateway/governance/governor/governor.py), [`defer_queue.py`](../src/gateway/governance/defer_queue.py)). | A human approved a specific barrier picture; executing against a different one is not what they approved (D-H). | `TypeError` without the keyword; an unparseable snapshot is refused before anything runs. |
| **P5-7** | Formal model / config | `"fria"` is removed from `TIERS` / `TIER_LABELS` in [`proof/model.py`](../proof/model.py) (8 tiers; gated / ungated / skipped-tier state counts 42/21/39 → 38/19/35). The AAIF `output_validation` stage no longer maps to a nonexistent Tier 7 ([`aaif_adapter.py`](../src/gateway/governance/ingress/aaif_adapter.py)); it is an unknown stage (`tier: -1`). | No pipeline stage named `fria` exists. | An AAIF spec relying on `output_validation` → Tier 7 gets the unknown-stage entry. |
| **P5-8** | Tooling | `scripts/check_stpa_freshness.py` compares the sha256 of each artifact with an in-memory regeneration (volatile stamps masked) and falls back to commit order only for artifacts it cannot regenerate. `patch2.py` / `patch3.py` are deleted. | Commit order is a proxy; content is the property (F-3, F-6). | A hand-edited artifact now fails the gate even when committed after its source. |

---

## Unreleased — FRIA Wired Only Under EU_ECB; Confidence Band Renamed (Phase 6)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **P6-1** | Thresholds / env vars | The `fria` block of [`config/governance_thresholds.json`](../config/governance_thresholds.json) is removed. The universal band is `confidence.agent_threshold` (0.95) and `confidence.defer_floor` (0.70, new, validated `<= agent_threshold`). Removed: `FriaThresholds`, `get_fria_zone_allow()`, `get_fria_zone_defer()` (use [`get_agent_confidence_threshold()` / `get_confidence_defer_floor()`](../src/gateway/governance/schemas/thresholds.py)), and `defer_queue.DEFER_CONFIDENCE_THRESHOLD`. Env-var mapping: `FRIA_ZONE_ALLOW` → `AGENT_CONFIDENCE_THRESHOLD`; `FRIA_ZONE_DEFER` → `CONFIDENCE_DEFER_FLOOR`. TLA+ constants in [`FtraBoundary.tla`](../proof/FtraBoundary.tla): `FRIA_ZONE_DEFER/ALLOW` → `CONFIDENCE_DEFER_FLOOR/ALLOW_FLOOR`. | The band runs in every region (`ConfidenceStage`, FTRA). Calling it "FRIA" implied an impact assessment that never ran. | `ImportError` / `AttributeError` on the removed names. A stale `FRIA_ZONE_*` env var is silently ignored, so set the new name. |
| **P6-2** | Normative provider | `enforce_fria_boundary()`, `FRIAEnforcementResult` and `_async_attestation()` are removed from [`normative_provider.py`](../src/gateway/governance/normative_provider.py). `is_stub_provider()` is added. | The primitive had no pipeline caller (POAM-2026-084), and it let an action through on confidence ≥ 0.95 without any assessment. | `ImportError`. Integrations get FRIA from the `fria` tier instead. |
| **P6-3** | Governor assembly | New [`jurisdiction/`](../src/gateway/governance/jurisdiction/) package (`JurisdictionContribution`, `JURISDICTIONS`, `resolve_jurisdiction`). `assemble_governor(..., jurisdiction=None)` resolves the active region's contribution, and `GovernorComponents.jurisdiction` carries it. `SymbolicGovernor.tiers` lists domain and jurisdiction tiers, while `domain_tiers` stays domain-only. Under `CAGE_DEPLOYMENT_REGION=EU_ECB` every governor gains the phase-1 `fria` tier after `causal`. It claims every action by default, so every EU_ECB action now runs the confidence stage too and needs a confidence ≥ the agent threshold. | FRIA is a jurisdiction obligation, not a kernel or domain concept (D-L). | An EU_ECB action without a current FRIA artefact in `CTRL_FRIA_006.assessments` is denied (`FRIA_ASSESSMENT_STALE`). An unknown region passed to `resolve_jurisdiction` raises `ValueError`. A domain tier named `fria` collides at construction. |
| **P6-4** | Startup posture | `assert_production_posture()` adds the `jurisdiction_requirements` check: an enforcing EU_ECB posture refuses to start on the stub `NormativeProvider`. | The stub admits every assessment (Completeness Principle). | `PostureViolation` at startup. Set `CAGE_NORMATIVE_PROVIDER` to a real provider. |
| **P6-5** | Control registry | `ControlRegistry.reconfigure(region)` keeps `active_region` equal to the loaded region; it used to reset it to the default. | `active_region` selects the jurisdiction, so the reset silently dropped the `fria` tier after a reconfigure. | Code that relied on `active_region` reading `US_FED` after `reconfigure("EU_ECB")` now sees `EU_ECB`. |
| **P6-6** | Citation | EU AI Act FRIA is cited as **Art. 27** (Regulation (EU) 2024/1689); "Art. 29a" was the draft numbering. The Lula control id `EU_AI_ACT_ART29A` → `EU_AI_ACT_ART27`. | Correct legal citation. | Historical `compliance/lula/assessment-results.yaml` entries keep the old id. |

---

## Unreleased — One Enforcement Point per Rule; Read-Only / Mutating Tier Split (Phase 7)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **P7-1** | FTRA | The FTRA semantic validator module (`ftra.semantic_validator`) is deleted: `validate_tool_input`, `ActionSchema`, `ParameterConstraint`, `register_action_schema`, `ACTION_SCHEMAS`, `SemanticValidationResult`, `ValidationFailureCode`, and `FtraBoundaryResult.from_semantic_breach`. The codes `FTRA_SEMANTIC_BREACH`, `FTRA_VALIDATION_ERROR` and `<CLASS>_SEMANTIC_BREACH` and the span attributes `cage.ftra.semantic_*` are gone. [`FtraStage`](../src/gateway/governance/governor/stages/ftra.py) does classification, the autonomy predicate and a magnitude-shape check only (new span attribute `cage.ftra.magnitude_known`). See [`FTRA_SCOPE.md`](governance/FTRA_SCOPE.md). | No `ActionSchema` was ever registered, so the validator never ran; value rules are enforced once, by the STPA UCA rules and domain OPA (analysis R9). | `ImportError`. Value rules belong in the domain's STPA source or Rego. |
| **P7-2** | Confidence / STPA | The Tier-2 structural-corroboration branch is deleted (`TIER2_STRUCTURAL_OVERRIDE`, span `cage.tier2_structural_corroboration`), with `StageContext.stpa_violation_count` and the `verify()` key `"stpa_violation_count"`. [`StpaStage`](../src/gateway/governance/governor/stages/stpa.py) promotes any non-HARD finding to HARD (span `governance.stpa.promoted_to_hard`). | The branch was unreachable: every STPA finding is HARD, and every `None`-verdict OPA path emits HARD first (analysis R5). | `TypeError` constructing `StageContext(stpa_violation_count=...)`; `KeyError` reading the `verify()` key. |
| **P7-3** | Bounding (B10) | `BoundingContractTierPlugin._classification_override` and `get_classification_override()` are deleted. A closed rollback window on `execute_trade_bounded` is a `Violation(kind=HITL, code="B10_ROLLBACK_WINDOW_CLOSED")`, so the trade parks for approval (`REQUIRE_APPROVAL` + `deferred_id`). A missing or invalid B10 threshold stays HARD. `BoundingContractRegistry.evaluate_all()` returns `list[ContractResult]`, and `ContractResult` gains `code`. | The override was written on a shared tier instance and never read, so a closed window was denied, not escalated (analysis G4). | `AttributeError`. A closed-window trade that used to return DENY now returns `REQUIRE_APPROVAL`. |
| **P7-4** | Tier contract | `GovernanceTierPlugin` is replaced by nominal ABCs in [`contracts.py`](../src/gateway/governance/contracts.py) ([ADR-009](adr/ADR-009-tier-protocol-split.md)): `ReadOnlyTier` (`evaluate`) and `MutatingTier` (`evaluate`, `commit`, `rollback`, `confirm`), siblings under `GovernanceTier`. `phase` is derived from the base class. `DomainTierStage` runs `check_tier_kind()`. `JurisdictionContribution` accepts only `ReadOnlyTier`s. `CAGE_PLUGIN_API_VERSION` is `"2.0"`. | Five phase-1 tiers carried no-op `commit()` / `rollback()`, and the phase was a free integer the kernel trusted (D-F). | `ImportError` on `GovernanceTierPlugin`. `TypeError` for a tier that subclasses neither kind, a `ReadOnlyTier` defining `commit` / `rollback` / `confirm`, or a non-`ReadOnlyTier` jurisdiction tier. `ValueError` for a `phase` override that contradicts the kind. A plugin declaring `api_version = "1.x"` is refused. |
| **P7-5** | Settlement | Phase-2 commits are settled after actuation. `run_sealed()` binds a sealed run's commits to its seal in a [`SettlementLedger`](../src/gateway/governance/governor/settlement.py). New `SymbolicGovernor.settle(seal, *, executed)` confirms (`True`) or releases (`False`) them and returns `CONFIRM_FAILED` / `ROLLBACK_FAILED` violations. `ReservationScope.seal_issued()` returns the held commits (`tuple[HeldCommit, ...]`). `execute_trade_action()` calls `settle()` after `actuate()` and loses its `safety_filter` parameter; `FinancialToolProvider()` takes no arguments. | A sealed reservation was final before the action ran, so a seal that never actuated consumed budget forever (analysis R11). | `TypeError` on `safety_filter=` or `FinancialToolProvider(safety_filter)`. A caller that actuates outside `execute_trade_action` must call `settle()`; otherwise its fiscal reservation is reclaimed after the TTL. |
| **P7-6** | Fiscal guard | [`FiscalLimitGuard`](../src/cage_finance/safety/fiscal_limit_guard.py) reserves with a Lua script into the `fiscal:pending` ZSET; `confirm()` makes the spend permanent; `release()` and the lazy `reclaim_expired()` return it, each exactly once. `FiscalTierPlugin.commit()` only reserves; `confirm()` runs at settlement. Removed: the `WATCH`/`MULTI` path, `_MAX_RETRIES`, the sentinel-key helpers and `rollback_state`. `reservation_ttl` must be > 0. `release()` raises on a Redis error. | Confirm-inside-commit deleted the TTL key crash recovery relied on. | `AttributeError` on `rollback_state`. `ValueError` for `reservation_ttl <= 0`. Reservations made by the old guard are not in `fiscal:pending`, so they are never reclaimed; they age out with the daily window. |
| **P7-7** | Causal gatekeeper | The cache holds only the params-independent `WorldModelVerdict(trusted, beta, reason)`, keyed `causal_wm:{spec_fp}:{action}:{context}`, and only for synthetic-factory telemetry; the risk boundary is evaluated on every request. `causal_safety_check(params, current_telemetry=None, *, action=None)`. The async `_causal_cache_get` / `_causal_cache_set` are deleted; `_causal_cache_get_sync` returns `WorldModelVerdict \| None`. `cache_ttl_seconds <= 0` skips Redis. | A cached ALLOW for a small trade was replayed for any amount (POAM-2026-085). | `AttributeError` on the removed helpers. Old `causal_cache:*` keys are never read and expire on their own. |
| **P7-8** | Compliance mapping | The FTRA OSCAL component is restated (`ftra0001-4e47-bbc8-irreversibility01`; control implementation `ftra0001-ctrl-impl-8000-classifier01`; SI-10 `si100001-ftra-8000-classifier00001`) and its AC-4 requirement is withdrawn. `get_control_meta("US_FED")` no longer contains `"AC-4"`. The `ftra_semantic_validation` and `ftra_flow_enforcement` events are no longer mapped by [`compliance_bridge/types.py`](../src/compliance_bridge/types.py) or [`iso_control.py`](../src/gateway/governance/iso_control.py). | No producer emitted either event; the AC-4 parameter-smuggling claim rested on the deleted validator. | Consumers keyed on the old OSCAL uuids or on `nist.AC-4.passed` find nothing. AC-4 is still claimed for NetworkPolicy flow enforcement (`deployment/k8s/`). |

---

## Unreleased — Settlement-Aware Debit Ledger and Discrepancy Floor (Review Round 2)

| Item | Area | Clean Break Description | Architectural Rationale | Failure Mode on Stale Caller |
|---|---|---|---|---|
| **R2-1** | CBF Redis keys | The `cbf:local_debits` LIST is replaced by an O(1) ledger owned by [`debit_ledger.py`](../src/gateway/governance/safety/debit_ledger.py): `cbf:debits` (HASH `debit_id → entry`), `cbf:debits:by_time` (ZSET by `submitted_at`), `cbf:debits:total` (running sum) and `cbf:debits:rolled_back` (tombstones). `_REDIS_KEY_LOCAL_DEBITS`, `LUA_TRIM_DEBITS_BY_SEQUENCE`, `trim_local_debits_through_sequence()` and `trim_local_debits_through_sequence_sync()` are deleted from [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) ([ADR-010](adr/ADR-010-settlement-aware-debit-ledger.md)). | Pruning by snapshot sequence was not causally linked to settlement (and pruned everything each poll in the default configuration); commit and rollback were O(L). | `ImportError` on the removed names. **Runbook:** on upgrade, `DEL cbf:local_debits` — entries there are never read again; nothing migrates them, so any debit outstanding at upgrade time is forgotten (reconcile first, upgrade in a quiet window). |
| **R2-2** | Barrier engine contract | `atomic_verify_and_commit(action, params, governance_signature="", *, debit_id=None)` and `rollback_state(magnitude, governance_signature=None, *, debit_id=None)`; `reconciliation_sequence` is gone. `commit_barrier()` mints the `debit_id` and returns it in `CommitReceipt.token`; `rollback_barrier()` passes `debit_id=receipt.token`. The `BarrierEngine` and `SafetyFilter` protocols ([`contracts.py`](../src/gateway/governance/contracts.py), [`barrier_tier.py`](../src/gateway/governance/safety/barrier_tier.py)) carry the keyword. | Rollback must retire exactly the debit it committed, idempotently, instead of the newest entry of equal amount. | A test double or custom engine without the keyword fails with `TypeError: ... unexpected keyword argument 'debit_id'`; `rollback_state(reconciliation_sequence=...)` likewise. |
| **R2-3** | Commit semantics | In reconciled mode `LUA_ATOMIC_CBF` nets `cbf:debits:total` from the **raw** verified scalar in-script and first checks that the published snapshot (`cage:ground_truth:{invariant}`) is byte-identical to the one Python verified; otherwise it denies with `SNAPSHOT_CHANGED` (no retry). Previews (`verify_action()`, `admissible_cost()`) read the same total, so they are tighter whenever debits are outstanding. | Netting must happen where it is enforced and against one snapshot generation; previews must not promise headroom the commit refuses. | A commit racing a reconciler publish is denied instead of netted against the wrong generation. NARROW bounds and HITL barrier previews shrink by the outstanding total. |
| **R2-4** | Snapshot contract | `GroundTruthSnapshot.settled_through: float \| None` and `ReconciliationResult.settled_through` are new; `snapshot_signing_payload()` includes `settled_through`, so snapshots signed before this change no longer verify. `ReconciliationResult.raw_payload` carries the exact bytes read from Redis. `FaultMode.SETTLEMENT_STALL` is added (fault census 10 → 11). | A tampered cutoff must fail signature verification; the reference custodian must be able to lag. | A stored pre-upgrade snapshot fails `verify_snapshot_signature()` until the reconciler publishes a new one (strict CBF refuses meanwhile). Fault-mode census tests expecting 10 fail. |
| **R2-5** | Reconciler guard | The discrepancy guard compares against `max(discrepancy_ratio × \|baseline\|, discrepancy_abs_floor)` and measures the distance outside `[baseline, baseline + unsettled]`; the baseline key for `finance.cash_balance` is `safety:current_cash` (was the stale `safety:cash_balance`). New `ReconciliationThresholds` block (`reconciliation.*`) in [`governance_thresholds.json`](../config/governance_thresholds.json); constructor kwargs `settlement_lag_seconds`, `settlement_clock_skew_seconds`. | Tiny balances tripped on legitimate moves, large ones hid double-spend, and a lagging custodian tripped on every large trade. | A deployment that relied on the guard never firing for balances below 200 now sees refusals above the 100.0 floor; one that relied on the stale key now compares against the live barrier state. |
| **R2-6** | Simulated custodian wiring | `SimulatedSource(journal=None, settlement_lag_s=0.0)`; `record_debit(magnitude, *, submitted_at=None, debit_id=None) -> str`. The journal is selected by `CAGE_SIM_LEDGER_BACKEND` (`memory` default, `redis` for the shared `sim:ledger:{invariant}` ZSET) and the lag by `CAGE_SIM_SETTLEMENT_LAG_SECONDS`; both are set in [`gateway.yaml`](../deployment/k8s/gateway.yaml) and [`reconciliation-worker.yaml`](../deployment/k8s/reconciliation-worker.yaml). `BrokerActuator(ledger=None)` journals each accepted fill; a journal failure returns `accepted=False, retryable=True, CUSTODIAN_JOURNAL_FAILED`. | The actuator and the reconciler are different pods; an in-process journal could never settle. | Without `CAGE_SIM_LEDGER_BACKEND=redis` on **both** pods the reconciler never sees fills: debits stay outstanding until the lag fallback and the guard band is never exercised. |
| **R2-7** | Causal tier codes and wiring | [`CausalTierPlugin`](../src/cage_finance/tiers/causal_tier.py)`(causal_gatekeeper=None, telemetry_provider=None)` fetches live telemetry on every evaluation; [`create_finance_tiers`](../src/cage_finance/__init__.py) supplies `get_telemetry_provider()` (new `telemetry_provider=` kwarg). In enforcing postures causal denies now carry `CAUSAL_TELEMETRY_UNAVAILABLE` (no live rows / provider error) or `CAUSAL_INSUFFICIENT_SAMPLES` (< `causal.min_samples`) instead of `CAUSAL_CHECK_FAILED`; all remain `HARD`. [`CausalGatekeeper.evaluate()`](../src/gateway/governance/causal/gatekeeper.py) returns `CausalDecision(safe, reason)`; an empty frame counts as "no live telemetry". The Langfuse provider returns its real rows (with `timestamp`) below `MIN_SAMPLES` instead of the fallback frame | The tier passed no telemetry, so enforcing postures denied every trade with a code indistinguishable from a refutation, and the refuter was unreachable (POAM-2026-088, decision D3) | Dashboards or tests matching `CAUSAL_CHECK_FAILED` for missing-telemetry denies stop matching; `CAGE_TELEMETRY_PROVIDER=remote` without credentials now fails at governor assembly instead of on the first trade |

---

**Last updated:** 2026-10-02 (Review round 2 clean breaks R2-1–R2-7)

