# Changelog

All notable changes to this project are documented in this file.

## [2.0.0] — 2026-05-24

### CSA AARM Native Integration — Consequence-Governance Primitives

This release transforms CAGE from a proactive exploration repository into the industry's
definitive reference implementation for the Cloud Security Alliance (CSA) Autonomous Agent
Risk Management (AARM) specification. Three engineering-hardened primitives are promoted
from playground utilities to production infrastructure, each directly satisfying an AARM
mandate before proprietary fragmentation occurs.

### Added

- **Cryptographic Hash-Chained Context Accumulator (`src/compliance_bridge/context_accumulator.py`):**
  Promotes the SHA-256 chain-of-custody pattern from `examples/telemetry.py` to the core
  compliance pipeline. Each `OscalFinding` appended to the `ContextAccumulator` is hash-linked
  to the preceding node using `SHA-256(prev_hash || content_json)`. Genesis seed is derived from
  `sha256(audit_id)` for deterministic chain identity. The accumulator is sealed with a
  `CHAIN_SEALED` sentinel after every audit run and persisted to GCS/S3 as
  `<audit_id>/context_chain.ndjson`. `chain_root`, `chain_length`, and `chain_integrity_valid`
  are returned in all audit API responses. Satisfies **AARM-V1 Memory Poisoning** neutralization
  and **ISO 42001 Annex A.5.3** chain-of-custody requirements.

- **DEFER State Machine Primitive (`src/gateway/governance/defer_queue.py`):**
  Extends CAGE's tri-state OPA decision (`ALLOW | DENY | MANUAL_REVIEW`) to four states
  by introducing `DEFER`. Activates at the "Confidence-Starvation Boundary" — when
  `confidence_score < 0.70` AND OPA would return `MANUAL_REVIEW`. Three-way split:
  - `≥ 0.95` → Autonomous Clearance (execute)
  - `0.70–0.95` → MANUAL_REVIEW (human sign-off)
  - `< 0.70` → DEFER (automated data-hydration loop)

  `DeferToken` is persisted in Redis `db=1` with `maxmemory-policy noeviction` (isolated from
  the LangGraph checkpointer at `db=0` to prevent eviction interference). UCA-7 formally
  documents this as "Agent proceeds with ambiguous context instead of parking for data injection."
  Satisfies **AARM-V7 Context Window Overflow** neutralization and **ISO 42001 Annex A.8.4**.

- **Native AARM Threat Vector Mapping — 11-Vector Threat Ledger
  (`src/compliance_bridge/aarm_mapper.py`, `aarm_report_generator.py`):**
  Machine-readable proof that specific CAGE control points neutralize each of the 11 CSA AARM
  attack vectors. `build_aarm_conformance_report()` joins the static threat ledger against live
  `OscalFinding` results to produce per-vector verdicts: `NEUTRALIZED | PARTIAL | EXPOSED`.
  Report card is auto-serialized to GCS/S3 as `<audit_id>/aarm_conformance.json` on every
  Lula-scheduled audit run. `GET /v1/aarm/conformance-report` provides on-demand access with
  optional vLLM narrative enrichment (11 concurrent calls, `asyncio.Semaphore(3)` rate cap).

- **New Lula Validation Manifest (`compliance/lula/lula-validation-aarm-vectors.yaml`):**
  OPA Rego asserts: (1) all 11 AARM vectors present, (2) zero `EXPOSED` vectors, and
  (3) all 7 `CRITICAL`-severity vectors (`V1`, `V2`, `V3`, `V4`, `V9`, `V10`, `V11`)
  are `NEUTRALIZED`.

- **OSCAL Component Definition — AARM Conformance Engine
  (`compliance/oscal/component-definition.yaml`):**
  New `AARM Conformance Engine` component documents all three primitives with
  `control-implementations` cross-referencing AARM v1.0 and ISO 42001 requirements.
  `context-accumulator-chain-root` and `aarm-spec-version` props embedded in every
  OSCAL Assessment Results document.

- **New API Endpoints (`src/compliance_bridge/main.py`):**
  - `GET /v1/aarm/conformance-report` — AARM Conformance Report Card (JSON/YAML, optional narrative)
  - `GET /v1/defer/pending` — list parked DEFER queue tokens
  - `POST /v1/defer/{id}/inject` — resolve via automated data injection
  - `POST /v1/defer/{id}/escalate` — escalate to MANUAL_REVIEW

- **New SSE Event Types (`src/compliance_bridge/sse_events.py`):**
  `CONTEXT_CHAIN_SEALED` (emitted on chain seal) and `DEFER_PARKING` / `DEFER_RESOLVED`
  (emitted on token park/resolution). KernelDashboard consumers see real-time chain status.

- **New Tests:**
  - `tests/test_context_accumulator.py` — 15 tests including critical tamper-detection
    invariant: mutating `node_index=0` payload causes `verify_integrity()` to return
    `(False, 0)` — structural failure caught at the mutated node.
  - `tests/test_defer_queue.py` — hermetic fakeredis tests for all DeferQueue operations,
    confirms `DEFER_CONFIDENCE_THRESHOLD == 0.70`.
  - `tests/test_aarm_mapper.py` — ledger completeness, NEUTRALIZED/PARTIAL/EXPOSED scoring,
    overall posture classification (SECURE/DEGRADED/CRITICAL).

### Modified

- **`src/compliance_bridge/audit_workflow.py`:** Upgraded from 5-step to 6-step pipeline.
  Step 2b injects the `ContextAccumulator` after OSCAL parse. Step 6 generates the AARM
  Conformance Report Card.
- **`src/compliance_bridge/types.py`:** `OscalFinding` gains `chain_index: int | None`.
  `CONTROL_META` enriched with `aarm` framework cross-references across all affected controls.
  `ISO_CONTROL_MAP` gains `context_accumulate` → `A.5.3` and `defer_parking` → `A.8.4`.
- **`src/compliance_bridge/oscal_exporter.py`:** Finding props include `aarm-vector`
  cross-references. Assessment Results props include `context-accumulator-chain-root`,
  `context-accumulator-sealed-utc`, and `aarm-spec-version`.
- **`src/gateway/governance/ontology.py`:** UCA-7 (DEFER) formally registered with
  Confidence-Starvation Boundary (0.70) documented in `detection_pattern`.
- **Compliance Bridge version:** `2.1.0` (service API version bump within CAGE v2.0.0).

## [2.0.0] — 2026-05-23

### Global Productization & Multi-Jurisdiction Compliance

This release expands CAGE into a multi-jurisdiction product, allowing seamless transition of compliance postures between United States, European Union, and Singapore regulatory environments without code changes.

### Added

- **Multi-Region Compliance Baseline System:** Dynamic loading of regional control profiles (`config/compliance/`) and thresholds (`config/thresholds/`) using `CAGE_DEPLOYMENT_REGION` env var (`US_FED`, `EU_ECB`, `APAC_MAS`).
- **Fundamental Rights Impact Assessment (FRIA) Attestation:** Added pre-market FRIA attestation control (`CTRL_FRIA_006` / EU AI Act Art. 29a) in `EU_ECB` region, stamping attestation metadata onto live OpenTelemetry span attributes.
- **Dynamic Threshold Calibration:** Regionalized CBF drawdown limits (5% default, 4% EU), confidence levels (0.95 default, 0.97 EU), and consensus debate thresholds ($10k default, $7.5k EU, $5k MAS).
- **Flexible Exporter Framework:** Added `--framework` CLI flag to the automated OSCAL SSP compiler (`oscal_ssp_exporter.py`) supporting `EU_AI_ACT`, `MAS_FEAT`, `ISO42001`, and `NIST` cross-walk compilation.
- **Crown Jewel Decoupling (`FrameworkRouter`):** Extracted all four hardcoded UCA-to-control mapping dicts from `oscal_ssp_exporter.py` into versioned JSON routing files under `config/oscal/framework_mappings/`. New `FrameworkRouter` class loads and caches them at runtime. Adding a new jurisdiction is a config-only operation.
- **Data-Driven SR 26-2 Telemetry Suppression:** The `causal_gatekeeper` now reads a `"no legal force"` sentinel from each regional profile's `legacy_citation` field. When present, it emits `primary_framework` (the jurisdiction-correct citation) on OTel spans instead of the US-specific SR 26-2 string. The hardcoded `_EU_LEGACY_CITATION_OVERRIDE` dict is eliminated entirely.
- **Thread-safe ControlRegistry Singleton:** Hardened `ControlRegistry` with safe mapping lookups (`get_mapping_safe()`) to gracefully handle region-specific controls without system-wide exceptions.

### Operational Lock-Down

- **Manifest Hardening:** `CAGE_DEPLOYMENT_REGION` added explicitly to all container manifests (`deployment/k8s/generated/gateway-deployment.yaml`, `docker-compose.yml`, `docker-compose.dev.yml`) with `${CAGE_DEPLOYMENT_REGION:-US_FED}` shell default. Silent fallback to US_FED in non-US production pods is no longer possible without explicit override.
- **`.env.example` Documentation:** Full boot contract documentation block added describing all three supported region values, fallback warning, and runtime `reconfigure()` procedure.
- **FrameworkRouter Test Matrix (`tests/test_framework_router.py`):** 41-test suite covering JSON schema integrity (4 frameworks × 7 required keys), cache identity, cache isolation, UCA-1–UCA-9 control coverage, description completeness, narrative template rendering, `build_summary()` UCA coverage, `all_controls()` deduplication, unknown-framework error handling, and sentinel-driven trace citation logic across all three regions.

## [1.0.0] — 2026-05-23

### Initial Production Release

This release establishes the baseline production-ready version of the Cybernetic Governance Engine (CAGE). It consolidates all core systems, safety features, compliance structures, and deployment topologies into a single, cohesive foundation.

### Added

- **Decoupled Governance Abstraction (Option 3 Framework):** Removed hardcoded regulatory citation strings from Python business logic. Introduced the `GovernanceControl` enum and a thread-safe `ControlRegistry` singleton backed by `config/control_mappings.json` as the authoritative mapping layer.
- **Unified Control Mapping:** Wired `CTRL_MRM_004` directly to the Control Barrier Function (CBF), replacing legacy citations, and ensured all violation payloads dynamically resolve through `ControlRegistry`.
- **DoWhy Causal Gatekeeper:** Placebo refutation causal inference validation of the world-model before high-stakes operations. Evaluates in two phases: statistical kernel (MRM control) and placebo refutation (ISO 42001 compliance).
- **STPA-Driven LangGraph Saga Pattern:** Auto-generates Saga sub-graphs (WAL ledger entries, forward nodes, LIFO rollback, idempotent compensating nodes, and ghost-state recovery) from `config/stpa_control_structure.yaml` using the STPA-to-Policy compiler target.
- **Saga Telemetry Interceptor:** Added `SagaCallbackHandler` class to emit OTel decision spans tagged with `iso42001.control_id=A.8.4` immediately when any Saga node completes or rolls back.
- **FiscalLimitGuard:** Redis-backed atomic pre-reservation guard preventing concurrent TOCTOU (Time-of-Check-Time-of-Use) limits race conditions. Supports exponential backoff and fail-closed security.
- **STPA-to-Policy Compiler:** CLI tool (`stpa_compiler.py`) compiling `stpa_control_structure.yaml` into OPA Rego rules, NeMo Colang rails, Python validator classes, and LangGraph Saga nodes.
- **Zero-Trust Network (Z3N) Hardening:** Configured Linkerd mTLS for cluster-internal secure communications and Cilium network policies for strict FQDN egress lockdown on sovereign agent pods.
- **OSCAL SSP Exporter:** CLI tool (`oscal_ssp_exporter.py`) to programmatically patch implementation evidence narratives for all security controls in-place into `compliance/oscal/system-security-plan.yaml` on CI runs.
- **Cryptographic Evidence Chain:** Playground telemetry writing a tamper-evident, SHA-256 hash-chained audit trail log (`cage-intent/1.0` schema) alongside read-access tracking (GDPR/MiFID II compliance).
- **HITL Mandatory Rationale:** Enforced mandatory human justification on high-risk trade interrupts, hashing rationale into the audit evidence chain before resumes.
- **Mandatory NeMo Guardrails:** Non-bypassable input/output Colang rails with Presidio PII data scanning.
- **OPA Policy Engine:** Modular, REST-based OPA execution path supporting dynamic checks with a deny-on-failure circuit breaker.
- **Chaos Agent Playground:** Walkthrough utility to test prompt injection, PII exfiltration, gas front-running, Saga rollback, and ghost-state recovery against the full governance stack.
- **Kubernetes-Native Secrets:** Secure secrets storage via K8s Secret resources, eliminating third-party remote providers.
