# CAGE v3.0.0 Breaking Changes

> **Status:** Corrected release. v3.0.0 was initially tagged 2026-08-15 with
> four breaking changes still outstanding (see below); those changes were
> completed on branch `fix/v3-breaking-changes-completion` and this document
> has been updated to reflect what was actually removed. See
> [`CHANGELOG.md`](../CHANGELOG.md) for the full release notes. This document
> describes the breaking changes included in this release. Item IDs (`SR-#`,
> `MR-#`, `CR-#`, `FF-#`, `EV-#`) match
> [`docs/MAJOR_VERSION_CLEANUP_PLAN.md`](MAJOR_VERSION_CLEANUP_PLAN.md) 1:1
> so the two documents can be cross-referenced.
>
> **Post-tag corrections (this update):** `AGWEnvelope`/`AGWEnvelopeBuilder`
> removal was missing from this document entirely; legacy provider signing method
> removal was missing from the Removed Classes/Functions table; the
> `KMS_BATCH_ENABLED` discrepancy flagged in the original release notes is
> now resolved (default confirmed as `"false"`, not `"true"` — see
> [Feature Flags Graduated](#feature-flags-graduated)).

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
behavior change in `v3.0.0`.

---

## API Changes

### Removed Modules

| Module | Replacement | Migration |
|--------|-------------|-----------|
| [`src/gateway/governance/stpa_validator.py`](../src/gateway/governance/stpa_validator.py) (`STPAValidator` class) | [`src/gateway/governance/generated_stpa_validator.py`](../src/gateway/governance/generated_stpa_validator.py:38) (`GeneratedSTPAValidator`) | Replace `from src.gateway.governance.stpa_validator import STPAValidator` with `from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator`; replace `.validate(action_name, params)` calls with `.validate_generated(action_name, params)`. |
| [`src/gateway/governance/safety.py`](../src/gateway/governance/safety.py) (entire file) | [`src/gateway/governance/text_filter.py`](../src/gateway/governance/text_filter.py) (`ac_keyword_scan`); [`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py) (`ControlBarrierFunction`, `safety_filter`) | Replace `from src.gateway.governance.safety import ac_keyword_scan` with `from src.gateway.governance.text_filter import ac_keyword_scan`; replace `from src.gateway.governance.safety import ControlBarrierFunction, safety_filter` with `from src.gateway.governance.cbf import ControlBarrierFunction, safety_filter`. |
| `src/gateway/governance/agw_envelope.py` (entire file — `AGWEnvelope`, `AGWEnvelopeBuilder` backward-compatibility aliases) | [`src/gateway/governance/governance_envelope.py`](../src/gateway/governance/governance_envelope.py) (`GovernanceEnvelope`, `GovernanceEnvelopeBuilder`) | Replace `from src.gateway.governance.agw_envelope import AGWEnvelope` with `from src.gateway.governance.governance_envelope import GovernanceEnvelope`; replace `AGWEnvelopeBuilder` with `GovernanceEnvelopeBuilder` (same module). `tests/test_agw_envelope.py` (the backward-compatibility test suite for these aliases) is also deleted — see [`tests/test_governance_envelope.py`](../tests/test_governance_envelope.py) for the canonical coverage. **(Completed post-tag, `fix/v3-breaking-changes-completion`.)** |

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
| `update_state()` (public API) | [`src/gateway/governance/cbf.py:907-998`](../src/gateway/governance/cbf.py:907) | `atomic_verify_and_commit()` (same module) | **Completed (CR-3)**: `update_state()` was renamed to `_update_state_unsafe()` (internal-only) to eliminate TOCTOU race conditions. External callers must call `atomic_verify_and_commit()`, which performs the CBF safety check and state commit atomically within a single Redis Lua execution. |
| `sign_provider_04_digest()` (legacy method) | [`src/gateway/governance/kms_signer.py`](../src/gateway/governance/kms_signer.py) (`KMSSigner` class) | `sign()` (same class) | Replace legacy digest signing with `kms_signer.sign(payload)`; `sign()` is the canonical signing entry point and covers the same code path. **(Completed post-tag, `fix/v3-breaking-changes-completion`.)** |

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
considering these items complete — see the [Migration Guide's test
verification step](MIGRATION_GUIDE_v3.md#step-4-test-verification).

---

## Evidence Hash Canonicalization (FlowSignal Phase 2)

**Breaking Change:** Evidence and attestation hash computation in [`normative_provider.py`](../src/gateway/governance/normative_provider.py) migrated from `json.dumps(sort_keys=True)` to RFC 8785 JCS canonicalization.

| Function/Method | Old Algorithm | New Algorithm | Impact |
|---|---|---|---|
| [`_async_attestation()`](../src/gateway/governance/normative_provider.py:410) | `hashlib.sha256(json.dumps(action_context, sort_keys=True).encode()).hexdigest()` | `hashlib.sha256(jcs_canonicalize_plan(action_context)).hexdigest()` | Evidence hash values will differ for payloads containing floats (e.g., `1.0` → `"1"` in JCS vs `"1.0"` in json.dumps) |
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
| [`src/compliance_bridge/evidence_stream.py`](../src/compliance_bridge/evidence_stream.py) | `cage-evidence-stream/1.1` | `cage-evidence-stream/2.0` |
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
| `_detect_schema_version()` | [`src/compliance_bridge/evidence_stream.py`](../src/compliance_bridge/evidence_stream.py) | *(none — all records are `/2.0`; there is nothing to detect)* |
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
| Reconciliation signed balance | [`src/compliance_bridge/reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py) | 300 s | A balance signed pre-cutover will not verify post-cutover. The CBF **fails closed** on an unverifiable or expired balance, so a deployment may see up to 5 minutes of conservative DENY behavior until the reconciliation worker writes a freshly-signed balance. |

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
`ALLOW`, `DENY`, `DEFER`, `NARROW`, `PAUSE`, `REQUIRE_APPROVAL`.

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
| `defer_id` | `defer_token` | [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py) |
| `missing_input_reason` | `classification_reason` | [`decisions.py`](../src/gateway/governance/decisions.py), [`agent_gateway_adapter.py`](../src/gateway/server/agent_gateway_adapter.py) |

**Migration:** clients parsing DEFER responses must read `decision`,
`defer_token`, and `classification_reason`. The removed keys are absent from the
JSON body entirely — a client using `body["verdict"]` will raise `KeyError`
rather than silently degrading, which is deliberate. This affects the
`/validate-action` DEFER path and the `/v1/defer/*` polling responses.

### `rollback()` requires an explicit window (BC-07)

**Breaking Change:** `rollback()` in
[`src/gateway/governance/fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py)
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

**Last updated:** 2026-08-27 (post-v3.0.0-tag corrections + FlowSignal Phase 2 ST-5
+ backward-compatibility remediation BC-01–BC-08 / POAM-2026-060, -062–-068)
