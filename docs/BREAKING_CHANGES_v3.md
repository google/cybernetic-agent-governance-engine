# CAGE v3.0.0 Breaking Changes

> **Status:** Released — v3.0.0 shipped 2026-08-15. See
> [`CHANGELOG.md`](../CHANGELOG.md) for the full release notes. This document
> describes the breaking changes included in this release. Item IDs (`SR-#`,
> `MR-#`, `CR-#`, `FF-#`, `EV-#`) match
> [`docs/MAJOR_VERSION_CLEANUP_PLAN.md`](MAJOR_VERSION_CLEANUP_PLAN.md) 1:1
> so the two documents can be cross-referenced.

## Overview

CAGE `v3.0.0` removes deprecated shims, backward-compatibility aliases, and
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
behavior change in `v3.0.0`.

---

## API Changes

### Removed Modules

| Module | Replacement | Migration |
|--------|-------------|-----------|
| [`src/gateway/governance/stpa_validator.py`](../src/gateway/governance/stpa_validator.py) (`STPAValidator` class) | [`src/gateway/governance/generated_stpa_validator.py`](../src/gateway/governance/generated_stpa_validator.py:38) (`GeneratedSTPAValidator`) | Replace `from src.gateway.governance.stpa_validator import STPAValidator` with `from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator`; replace `.validate(action_name, params)` calls with `.validate_generated(action_name, params)`. |
| [`src/gateway/governance/safety.py`](../src/gateway/governance/safety.py) (entire file) | [`src/gateway/governance/text_filter.py`](../src/gateway/governance/text_filter.py) (`ac_keyword_scan`); [`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py) (`ControlBarrierFunction`, `safety_filter`) | Replace `from src.gateway.governance.safety import ac_keyword_scan` with `from src.gateway.governance.text_filter import ac_keyword_scan`; replace `from src.gateway.governance.safety import ControlBarrierFunction, safety_filter` with `from src.gateway.governance.cbf import ControlBarrierFunction, safety_filter`. |

### Removed Classes/Functions

| Symbol | Module | Replacement | Migration |
|--------|--------|-------------|-----------|
| `GovernanceClient` (alias) | [`src/governed_financial_advisor/infrastructure/governance_client.py:323`](../src/governed_financial_advisor/infrastructure/governance_client.py:323) | `StructuredLLMClient` (same module) | Replace `GovernanceClient(...)` with `StructuredLLMClient(...)`; update any type hints from `GovernanceClient` to `StructuredLLMClient`. |
| `RedisClient` (alias) | [`src/governed_financial_advisor/infrastructure/redis_client.py:268`](../src/governed_financial_advisor/infrastructure/redis_client.py:268) | `AsyncRedisClient` (same module) | Replace `RedisClient()` with `AsyncRedisClient()`. **Note:** do not confuse with the unrelated `_AsyncRedisClient`/`_SyncRedisClient` pair in [`src/gateway/infrastructure/redis_client.py`](../src/gateway/infrastructure/redis_client.py) — that module is untouched by this removal. |
| `HybridClient` (alias) | [`src/governed_financial_advisor/infrastructure/llm_client.py:23`](../src/governed_financial_advisor/infrastructure/llm_client.py:23) | `GatewayClient` from [`src/gateway/core/llm.py`](../src/gateway/core/llm.py) | Replace `from src.governed_financial_advisor.infrastructure.llm_client import HybridClient` with `from src.gateway.core.llm import GatewayClient`. |
| `check_safety_constraints` (tool alias) | [`src/governed_financial_advisor/agents/evaluator/agent.py:193`](../src/governed_financial_advisor/agents/evaluator/agent.py:193); [`src/gateway/server/mcp_tool_server.py:483`](../src/gateway/server/mcp_tool_server.py:483); [`src/governed_financial_advisor/tools/api.py:87-88`](../src/governed_financial_advisor/tools/api.py:87); [`src/governed_financial_advisor/graph/nodes/evaluator_node.py:22,147`](../src/governed_financial_advisor/graph/nodes/evaluator_node.py:22) | `simulate_governance_check` | Rename every reference to the tool/function name `check_safety_constraints` to `simulate_governance_check` across all 4 call sites (they must land in one atomic PR). |
| `create_ftra_node(registry_path=..., plan_key=...)` deprecated params | [`src/gateway/governance/ftra/node_factory.py:145-149`](../src/gateway/governance/ftra/node_factory.py:145) | `config: FtraNodeConfig` parameter (same function) | Replace `create_ftra_node(registry_path="x", plan_key="y")` with `create_ftra_node(config=FtraNodeConfig(registry_path="x", plan_key="y"))`. See [Migration Guide](MIGRATION_GUIDE_v3.md#step-3-update-api-calls) for the full before/after. |
| `CONTROL_META` (module-level dict alias) | [`src/compliance_bridge/types.py:340`](../src/compliance_bridge/types.py:340) | `get_control_meta(region)` | Replace `from src.compliance_bridge.types import CONTROL_META` + direct iteration with `from src.compliance_bridge.types import get_control_meta` and call `get_control_meta(CAGE_DEPLOYMENT_REGION)`. **Behavior note:** `CONTROL_META` contained universal (ISO 42001) controls only — `get_control_meta(region)` returns universal + jurisdictional controls merged for the given region. Passing `"universal"` (or any unrecognized region string) reproduces the old universal-only subset. |
| `EVIDENCE_SLA_SECONDS` (module-level dict alias) | [`src/compliance_bridge/types.py:446`](../src/compliance_bridge/types.py:446) | `get_sla_seconds(region)` | Replace direct dict access with `get_sla_seconds(region)`. Same universal-only → region-merged behavior note as `CONTROL_META` applies. |
| `ISO_CONTROL_MAP` (module-level dict alias — **two distinct symbols**) | [`src/compliance_bridge/types.py:512`](../src/compliance_bridge/types.py:512) **and** [`src/gateway/governance/ontology.py:197-234`](../src/gateway/governance/ontology.py:197) (`TradingKnowledgeGraph.ISO_CONTROL_MAP` class attribute) | `get_iso_control_map(region)` (types.py); `get_control_map(region)` (ontology.py) | These are **two unrelated symbols with the same name in two different modules** — migrate each independently. `src/compliance_bridge/types.py` callers use `get_iso_control_map(region)`; `TradingKnowledgeGraph` callers use `get_control_map(region)`. |
| `update_state()` — no signature change, but internal-use-only in v3.0.0 | [`src/gateway/governance/cbf.py:907-998`](../src/gateway/governance/cbf.py:907) | `atomic_verify_and_commit()` (same module) | `update_state()` is **not deleted** in v3.0.0 (see [CR-3 rationale](../docs/MAJOR_VERSION_CLEANUP_PLAN.md) §2.3) — it is retained as an internal primitive. New code must call `atomic_verify_and_commit()`, which performs the CBF safety check and the state commit atomically, closing the TOCTOU window documented in `update_state()`'s own deprecation warning (MED-5). If the CR-3 rename decision (`update_state()` → `_update_state_unsafe()`) is adopted during implementation, direct external calls to `update_state()` will break — track this uncertainty in your upgrade testing. |

### Removed Endpoints

No CAGE HTTP endpoint is removed in v3.0.0. `POST /v1/nemo/apply-refinement`
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
environment variables in `v3.0.0` will have **no effect** once the
corresponding module is migrated; use the config file instead.

| Variable | Replacement | Migration |
|----------|-------------|-----------|
| `FRIA_ZONE_ALLOW`, `FRIA_ZONE_DEFER` | `config/thresholds/*.json` (per-region FTRA boundary thresholds) | Move the values you previously set via env var into the appropriate region file under [`config/thresholds/`](../config/thresholds/). This migration also fixes a latent drift bug where [`src/gateway/governance/ftra/graph_analyzer.py:73-74`](../src/gateway/governance/ftra/graph_analyzer.py:73) hardcoded `0.70` independent of the env var — after migration, both `symbolic_governor.py` and `graph_analyzer.py` read the same config value via `get_fria_zone_defer()`. |
| `AGENT_CONFIDENCE_THRESHOLD` | `config/thresholds/*.json` | Move the value into config; the two independent read sites in [`symbolic_governor.py:1088-1097,1366-1368`](../src/gateway/governance/symbolic_governor.py:1088) are consolidated into a single read via `get_agent_confidence_threshold()`. |
| `CAUSAL_LOCK_P_VALUE_THRESHOLD`, `CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE`, `CAUSAL_LOCK_RISK_BOUNDARY` | `config/thresholds/*.json` | Move MRM/ISO 42001 §A.9.4-governed threshold values from env vars ([`src/gateway/governance/causal_gatekeeper.py:80-110`](../src/gateway/governance/causal_gatekeeper.py:80)) into the versioned config file. This also gives an audit trail for threshold changes. |
| `NEMO_AUTO_APPLY_ENABLED` | *(deleted, not migrated)* | This variable is removed entirely as part of CR-2 (the legacy auto-apply code path is deleted). Setting it in v3.0.0 has no effect regardless of value. |
| `KMS_BATCH_MAX_SIZE`, `KMS_BATCH_ENABLED` | `config/thresholds/*.json` | **Resolved:** The default is standardized to `"false"` across `kms_batch_signer.py` and `main.py`. Batch configuration is loaded via schema thresholds. |
| `CAUSAL_MIN_SAMPLES`, `CAUSAL_CACHE_TTL_SECONDS`, `TELEMETRY_MAX_STALENESS_SECONDS` | `config/thresholds/*.json` | Consolidated to `config/thresholds/*.json` via accessor functions like `get_telemetry_max_staleness_seconds()`. |

### New Required Configuration

| Config | Purpose | Default |
|--------|---------|---------|
| `config/thresholds/<REGION>_BASELINE.json` — FTRA zone keys (`fria_zone_allow`, `fria_zone_defer`) | Replaces `FRIA_ZONE_ALLOW`/`FRIA_ZONE_DEFER` env vars | `0.95` / `0.70` (matches current env var defaults) |
| `config/thresholds/<REGION>_BASELINE.json` — `agent_confidence_threshold` key | Replaces `AGENT_CONFIDENCE_THRESHOLD` | Matches current env var default (confirm exact value in [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py:1088) before upgrading) |
| `config/thresholds/<REGION>_BASELINE.json` — `causal_lock_*` keys | Replaces the three `CAUSAL_LOCK_*` env vars | Matches current env var defaults; confirm with MRM/ISO 42001 owner before upgrading |
| `config/thresholds/<REGION>_BASELINE.json` — `kms_batch_*` keys | Replaces `KMS_BATCH_MAX_SIZE`/`KMS_BATCH_ENABLED` | `32` / `false` (standardized across modules) |
| `config/thresholds/<REGION>_BASELINE.json` — `causal_min_samples`, `causal_cache_ttl_seconds`, `telemetry_max_staleness_seconds` keys | Replaces the three misc causal/telemetry env vars | Matches current defaults (`30`, `300`, `300`) |

### Feature Flags Graduated

| Flag | New Behavior |
|------|--------------|
| `CAGE_DEFER_ENABLED` | **Not graduated in v3.0.0** (explicit recommendation in the cleanup plan §2.4). The flag remains, still defaulting to `"true"`. If your deployment currently sets this to `"false"` to force the DENY-fallback path, that behavior is **unchanged** in v3.0.0. This is a deliberate deviation from the "graduate stable flags" theme of this release — flagged here so consumers do not assume removal. |
| `KMS_BATCH_ENABLED` | **Status uncertain pending Wave 0 discrepancy resolution.** [`kms_batch_signer.py:75`](../src/compliance_bridge/kms_batch_signer.py:75) currently defaults this to `"true"`; [`main.py:211-212`](../src/compliance_bridge/main.py:211)'s comment claims the production default is `"false"`. **Do not assume this flag is graduated to any particular value until the CAGE release notes for your specific `v3.0.0` build confirm the resolved default.** If graduated, the flag is hardcoded and the `KMS_BATCH_ENABLED` env var (see above) is removed. |

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
- **`CBF.update_state()` may become internal-only** (pending the CR-3
  decision). If your integration calls `update_state()` directly instead of
  `atomic_verify_and_commit()`, it may need to migrate to the atomic wrapper
  to avoid a `TypeError`/`AttributeError` after the rename, or to close the
  MED-5 TOCTOU window regardless of whether the rename ships.
- **Threshold overrides via environment variable stop taking effect** for
  every variable listed under [Removed Environment Variables](#removed-environment-variables).
  Any CI/CD pipeline, Helm chart, or Terraform variable that injects these as
  env vars will silently have no effect post-migration — the values must be
  moved into the corresponding `config/thresholds/*.json` file instead. This
  is the single most likely "silent" breaking change in this release since
  no exception is raised; verify with the [Migration Guide's test
  verification step](MIGRATION_GUIDE_v3.md#step-4-test-verification).

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
  mechanism for the audit evidence trail. Per the cleanup plan, this item
  requires a **data-migration completeness gate** (100% of production
  evidence records migrated v1.0 → v1.1) and Compliance/OSCAL + Security
  sign-off *before* it can ship — it is not gated purely on code review.
  Historical v1.0 records remain verifiable via a retained archival/read-only
  path even after live-write v1.0 support is removed.
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
considering these items complete — see the [Migration Guide's test
verification step](MIGRATION_GUIDE_v3.md#step-4-test-verification).
