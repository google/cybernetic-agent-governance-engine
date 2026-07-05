# Extensibility Architecture: Domain-Agnostic Core & Declarative Schema Ingestion

| Field              | Value                     |
| ------------------ | ------------------------- |
| **Classification** | PUBLIC                    |
| **Date**           | 2026-06-03                |
| **Version**        | v0.1.0                    |
| **Status**         | Current State + Roadmap (v0.1.0-rc.2; GKE deployment verified 2026-06-03) |

---

## Executive Summary

The CAGE runtime execution engine is a **domain-agnostic, invariant state-space controller**. The underlying kernel does not maintain programmatic awareness of specific statutory codes, clinical trial phases, or industrial automation rules. Instead, it models all governance criteria as mathematical boundaries mapped to an immutable state-space constraint:

$$h(x) \geq 0$$

Where $h(x)$ represents the Control Barrier Function (CBF) defining the boundary of the admissible operational space.

By separating the deterministic execution engine from the compliance payload it enforces, the architecture enables domain extensibility without kernel modification. New regulatory domains (pharmaceutical GxP, industrial NIST 800-82, defense ITAR) can be onboarded by authoring a declarative JSON compliance profile — the runtime invariants remain unchanged.

This document describes both the **current implementation** (grounded in source code) and the **architecture roadmap** for multi-domain extensibility.

---

## Part 1 — Current Implementation (Verified)

The following capabilities are implemented, tested, and operational in the CAGE v0.1.0 codebase.

### 1.1 The Domain-Agnostic Kernel

The CBF engine ([`safety.py`](../../../src/gateway/governance/safety.py)) implements a pure mathematical invariant with no domain-specific logic:

```python
# src/gateway/governance/safety.py — ControlBarrierFunction.get_h()
def get_h(self, cash_balance: float) -> float:
    """Safety function h(x). Safe when h(x) >= 0."""
    return cash_balance - self.min_cash_balance
```

The enforcement boundary:

$$h(x_{t+1}) \geq (1 - \gamma) \cdot h(x_t) \quad \text{and} \quad h(x_{t+1}) \geq 0$$

Where:
- $x$ = continuous state variable (currently: `cash_balance`)
- $\gamma$ = decay coefficient (sourced from `THRESHOLDS.cbf.gamma`)
- $h(x) = 0$ defines the critical safety boundary

The function `get_h()` accepts any continuous scalar. The financial semantics (`cash_balance`, `min_cash_balance`) are injected via the threshold configuration singleton ([`governance_thresholds.json`](../../../config/governance_thresholds.json)), not hardcoded in the kernel. This is the structural property that enables domain generalization.

### 1.2 The ControlRegistry: Decoupled Compliance Metadata

The [`ControlRegistry`](../../../src/gateway/governance/constants.py) singleton is a thread-safe, region-switchable resolver that translates stable internal control IDs (`CTRL_*` enum members) to external regulatory metadata at runtime.

**Key design principle:** Python source code references *only* stable `GovernanceControl` enum members. All framework citation strings (`SR 26-2 §IV.B`, `ISO 42001 §A.5.2`, `MAS FEAT Principle 4.2`) live exclusively in declarative JSON profiles loaded at container initialization.

```
src/gateway/governance/constants.py
├── GovernanceControl(Enum)        # Stable internal IDs — never change
│   ├── CTRL_AGT_001               # Agentic confidence threshold
│   ├── CTRL_WAL_002               # Write-Ahead Log atomicity
│   ├── CTRL_TEL_003               # Telemetry live validation
│   ├── CTRL_MRM_004               # Traditional MRM validation
│   ├── CTRL_OPA_005               # OPA policy enforcement
│   └── CTRL_FRIA_006              # EU AI Act FRIA (EU_ECB only)
│
└── ControlRegistry (singleton)    # Resolves CTRL_* → regulatory metadata
    ├── _load_registry()           # Reads JSON from config/compliance/
    ├── get_mapping(control)       # Returns {primary_framework, co_frameworks, ...}
    ├── get_mapping_safe(control)  # Returns None for region-absent controls
    └── reconfigure(region)        # Hot-swap regional profile at runtime
```

### 1.3 Active Regional Compliance Profiles

Three production profiles are implemented and loadable via `CAGE_DEPLOYMENT_REGION`:

| Region     | Profile File                        | Primary Framework            | Controls Defined |
| ---------- | ----------------------------------- | ---------------------------- | ---------------- |
| `US_FED`   | [`US_FED_BASELINE.json`](../../../config/compliance/US_FED_BASELINE.json)     | SR 26-2 / ISO 42001          | 5                |
| `EU_ECB`   | [`EU_ECB_BASELINE.json`](../../../config/compliance/EU_ECB_BASELINE.json)     | EU AI Act / DORA / GDPR      | 6 (+FRIA)        |
| `APAC_MAS` | [`APAC_MAS_BASELINE.json`](../../../config/compliance/APAC_MAS_BASELINE.json) | MAS FEAT / MAS TRM / ISO 42001 | 5              |

**Runtime behavior:** Setting `CAGE_DEPLOYMENT_REGION=EU_ECB` causes the ControlRegistry to load the EU profile at container startup. All `GovernanceError` payloads, OTel span attributes, SIEM emissions, and OSCAL findings automatically reference EU AI Act citations instead of SR 26-2 — with zero code changes.

### 1.4 The SymbolicGovernor Pipeline

The [`SymbolicGovernor`](../../../src/gateway/governance/symbolic_governor.py) orchestrates an ordered interceptor chain. Each tier is domain-agnostic — it evaluates a mathematical or logical predicate, not a domain-specific business rule:

| Tier | Interceptor                | Invariant                                              | Domain Coupling |
| ---- | -------------------------- | ------------------------------------------------------ | --------------- |
| 0    | STPA/UCA Validator         | Hazard analysis predicates from YAML control structure  | None            |
| 1    | Agentic Confidence Check   | `confidence_score ≥ threshold`                          | None            |
| 2    | Control Barrier Function   | `h(x) ≥ 0` (state-space boundary)                      | None            |
| 3    | SLM Sidecar                | ~~Semantic similarity `≥ threshold`~~ **Deprecated** — bypassed via `slm_available=false` sentinel; Tier 3 is a no-op in v0.1.0 | None |
| 4    | OPA Rego Policy            | Declarative policy rules (externalized)                 | None            |
| 5    | Multi-Model Consensus      | Heterogeneous critic agreement                          | None            |
| 6    | DoWhy Causal Gatekeeper    | Placebo refutation `p-value ≥ 0.05`                     | None            |
| 6b   | Adaptive FRIA Gate         | Confidence-mapped external validation (§2.5)            | None            |

Every tier's decision boundary is parameterized through [`governance_thresholds.json`](../../../config/governance_thresholds.json) and the regional compliance profile — not through imperative code branches.

### 1.5 Fail-Closed Posture

The CBF engine defaults to `BLOCKED` when its state source (Redis) is unreachable. This is the `CBF_FAIL_OPEN=false` enforcement verified in the v0.1.0 integration test suite (136/136 passing against live GKE `cage-dev` cluster).

The system will not permit an action it cannot independently verify as safe. This property is invariant across all domains.

### 1.6 Compliance Assessment State Semantics

The compliance output model of the domain-agnostic kernel uses a **four-state OSCAL result vocabulary** aligned with NIST SP 800-53A §3.2 assessment attribute semantics. Every [`OscalFinding`](../../src/compliance_bridge/types.py) produced by the compliance bridge carries exactly one of these states:

| `OscalResult` | OSCAL Wire Value | Meaning | Auditor Visibility |
|---|---|---|---|
| `PASS` | `satisfied` | Control evaluated; evidence meets threshold | ✅ Satisfied |
| `FAIL` | `not-satisfied` | Control evaluated; evidence below threshold | ❌ Not Satisfied |
| `NOT_APPLICABLE` | `not-applicable` | Control does not apply to this component type (deliberate scoping decision) | ℹ️ Scoped Out |
| `ERROR` | `error` | Control applies but scanner/collector failed to gather evidence | 🚨 Blind Spot |

#### Why ERROR ≠ NOT_APPLICABLE

`NOT_APPLICABLE` is a **deliberate architectural scoping decision** — the control is out of scope for this component by design (e.g., a network isolation control applied to a stateless function). It is set intentionally by a human or policy author.

`ERROR` is a **runtime evidence-collection failure** — the control is in scope, the scanner attempted to gather evidence, and the attempt failed (e.g., `"fetch failed"`, timeout, missing credentials). Masking an `ERROR` as `NOT_APPLICABLE` hides a security blind spot from auditors and violates the completeness requirement of most compliance frameworks.

> **Invariant:** A data-collection failure MUST be reported as `ERROR`. It MUST NOT be silently dropped or coerced to `NOT_APPLICABLE`.

#### Kernel Touch Points

| Component | Role |
|---|---|
| [`src/compliance_bridge/types.py`](../../src/compliance_bridge/types.py) | Defines `OscalResult = Literal["PASS", "FAIL", "NOT_APPLICABLE", "ERROR"]` |
| [`src/compliance_bridge/oscal_parser.py`](../../src/compliance_bridge/oscal_parser.py) | `_map_state()` — unrecognised OSCAL `status.state` → `ERROR` (not `NOT_APPLICABLE`) |
| [`src/compliance_bridge/oscal_exporter.py`](../../src/compliance_bridge/oscal_exporter.py) | `_finding_to_state()` — `ERROR` → `"error"` wire value; `findings_from_metrics_dict()` — fetch errors emit `ERROR` findings |
| [`src/compliance_bridge/audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py) | `_step4_alert_on_critical_fail()` — critical-control alert filter matches `result in ("FAIL", "ERROR")` |

#### Critical-Control Alert Behaviour

Controls in `CRITICAL_CONTROLS = {"A.9.2", "SC-4", "A.8.4"}` trigger Slack/PagerDuty alerts on **both** `FAIL` and `ERROR`. An `ERROR` on a critical control is treated with the same urgency as a `FAIL` because the system cannot assert the control is satisfied — the absence of evidence is itself a risk signal.

This property is invariant across all domains that extend the compliance bridge.

---

## Part 2 — Architecture Roadmap (Partial Implementation)

> **Note:** The following sections describe the target extensibility architecture. §2.5 (External Normative Provider Interface) is **implemented** as of v2.1.0. All other sections remain architecture designs illustrating the generalization path enabled by the domain-agnostic kernel described in Part 1.

### 2.1 Domain Profile Schema

The existing `ControlRegistry` JSON profile format generalizes naturally to non-financial domains. The proposed schema extends the current `{REGION}_BASELINE.json` pattern to support arbitrary domain verticals:

```jsonc
// PROPOSED: config/compliance/PHARMA_GxP_21CFR11.json
{
  "_schema_version": "0.1.0",
  "_region": "US_FDA",
  "_domain": "pharmaceutical",
  "_primary_prudential_authority": "FDA / CDER / CBER",

  "CTRL_AGT_001": {
    "internal_id": "THR-CONF-001",
    "primary_framework": "21 CFR Part 11 §11.10(a)",
    "co_frameworks": ["EU GMP Annex 11 §4.8"],
    "legacy_citation": "ICH Q10 §3.2.1",
    "scope": "agentic",
    "description": "Minimum model confidence for autonomous dosage adjustment recommendation."
  },

  "CTRL_MRM_004": {
    "internal_id": "THR-MRM-004",
    "primary_framework": "ICH Q8(R2) — Design Space Validation",
    "co_frameworks": ["FDA Process Validation Guidance Stage 3"],
    "legacy_citation": "GxP Model Lifecycle",
    "scope": "traditional_ml",
    "description": "CBF state variable reinterpreted: h(x) = active_ingredient_concentration - min_therapeutic_threshold."
  }
}
```

**Key insight:** The `GovernanceControl` enum members (`CTRL_AGT_001`, `CTRL_MRM_004`, etc.) remain unchanged. Only the metadata payload changes. The SymbolicGovernor pipeline executes identically — it checks `h(x) ≥ 0` regardless of whether `x` represents cash balance, API concentration, or actuator torque.

### 2.2 Proposed Domain Profiles

| Profile                     | Domain              | CBF State Variable `x`                     | Primary Framework          |
| --------------------------- | ------------------- | ------------------------------------------- | -------------------------- |
| `FINANCE_SR26_2_DORA`       | Financial Services  | `cash_balance` (USD)                        | SR 26-2 / DORA             |
| `PHARMA_GxP_21CFR11`        | Pharmaceutical      | `active_ingredient_concentration` (mg/mL)   | 21 CFR Part 11 / ICH Q8   |
| `OT_NIST_800_82_REV3`       | Industrial OT/ICS   | `actuator_position` (engineering units)      | NIST 800-82 Rev 3         |
| `DEFENSE_ITAR_CMMC`         | Defense / Aerospace | `decision_authority_level` (clearance tier)  | ITAR / CMMC Level 3       |

### 2.3 CBF Generalization Pattern

The CBF kernel requires no modification to support new domains. The generalization is purely configurational:

```
Current (Finance):     h(x) = cash_balance - min_cash_balance
Pharma (Proposed):     h(x) = API_concentration - min_therapeutic_threshold
Industrial (Proposed): h(x) = actuator_position - min_safe_position
```

In all cases, the runtime enforcement is identical:
- If `h(x_next) < (1 - γ) · h(x_t)` → **BLOCK**
- If `h(x_next) < 0` → **BLOCK** (critical boundary violation)

The decay coefficient `γ`, the state variable source, and the minimum threshold are all configurable through the threshold JSON and a pluggable state provider interface.

#### Formal Mathematical Invariant & TOCTOU Resolution

To guarantee that the continuous state trajectory of the environment cannot outpace the discrete guard conditions during HITL suspension, CAGE defines a mathematically bounded Safe Set. The post-HITL re-validation node resolves the TOCTOU gap by executing a deterministic acceptance function evaluated strictly over a fresh price snapshot:

$$\text{SAFE} \iff \left( \frac{|P_{\text{fresh}} - P_{\text{stale}}|}{P_{\text{stale}}} \le \text{max\_slippage\_pct} \right) \land \left( \text{CBF}(P_{\text{fresh}}, \text{amount}) \ge 0 \right) \land \left( \text{OPA}(P_{\text{fresh}}, \text{params}) = \text{ALLOW} \right)$$

This formal boundary definition ensures that trade execution is locked to a deterministic evaluation of both physical thresholds (CBF) and logical policies (OPA) on the same, fresh pricing sample. It mathematically prevents "ghost-state" execution where the environment drifts past policy limits while the system remains paused for human review.

### 2.4 Implementation Requirements

To fully realize the multi-domain architecture, the following engineering work is required:

| Requirement                          | Current State                                        | Target State                                                  |
| ------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------------- |
| **Profile Loading**                  | JSON read from `config/compliance/` at startup        | Same mechanism, extended schema with `_domain` field          |
| **CBF State Provider Interface**     | Hardcoded to Redis `safety:current_cash` key          | Pluggable `StateProvider` interface with domain-specific impls |
| **Domain-Specific Validators**       | Not implemented                                       | Optional pre-tier validators (e.g., `MedDRACodingValidator`)  |
| **Threshold Profile Generalization** | `governance_thresholds.json` uses financial terms      | Domain-neutral threshold schema with per-profile overrides    |
| **Telemetry Isolation**              | Dual Langfuse project (main / compliance)             | Configurable telemetry isolation modes per domain requirement |
| **Network Isolation**                | Kubernetes NetworkPolicy + namespace segregation       | Same mechanism, domain-specific policy templates              |

### 2.5 External Normative Provider Interface ✅ IMPLEMENTED

> **Status:** Implemented in v2.1.0. See [`normative_provider.py`](../../../src/gateway/governance/normative_provider.py).

The CAGE kernel enforces mathematical invariants locally (`h(x) ≥ 0`). But the *normative data* that parameterizes those invariants — which legal baselines apply, which attestations are required, which evidence seals must be appended — can originate from external sources. This section defines the integration architecture for external normative providers.

#### 2.5.1 Integration Taxonomy

All external provider interactions fall into three categories, each with a distinct hot-path impact profile:

| Category                  | Hot-Path Impact                           | Data Flow Direction       | Latency Contract                                    |
| ------------------------- | ----------------------------------------- | ------------------------- | --------------------------------------------------- |
| **Normative Data Supply** | None (boot-time + periodic)               | Provider → CAGE cache     | Boot-time only; no inline calls                     |
| **Attestation Logging**   | None (async fire-and-forget)              | CAGE → Provider           | Background; no acknowledgment wait                  |
| **External Validation**   | **Adaptive** (confidence-dependent)       | CAGE ↔ Provider           | Async at ≥0.95; sync gate at [0.70, 0.95); deny <0.70 |

**Critical constraint:** No external provider call may appear on the synchronous hot path between a user request entering the SymbolicGovernor pipeline and the governed response being returned. The CBF check ([`safety.py`](../../../src/gateway/governance/safety.py) L192-199) executes in sub-microseconds. The full 7-tier SymbolicGovernor pipeline includes the SLM sidecar (1.5s timeout) and OPA query (~10-50ms). Introducing a synchronous external HTTP call would trade model non-determinism for network non-determinism — violating the architectural guarantee that local enforcement is deterministic and bounded.

#### 2.5.2 Reference Handshake: 3-Endpoint External Provider

The following 3-endpoint HTTP contract defines the standard integration surface for external normative providers. It is designed to be provider-agnostic — any compliance SaaS, internal policy engine, or regulatory data feed that implements these three endpoints can integrate with CAGE without kernel modification.

```
┌──────────────────────────────────────────────────────────────────┐
│                     CAGE GKE Cluster                             │
│                                                                  │
│  ┌────────────────────┐     ┌──────────────────────────────────┐ │
│  │ Boot-Time Fetcher  │────►│ ControlRegistry (in-memory)      │ │
│  │ (container init)   │     │ + config/compliance/*.json cache │ │
│  └────────┬───────────┘     └──────────────┬───────────────────┘ │
│           │                                │                     │
│           │                    ┌───────────▼───────────┐         │
│           │                    │ SymbolicGovernor      │         │
│           │                    │ 7-Tier Pipeline       │         │
│           │                    │ (HOT PATH: no network)│         │
│           │                    └───────────┬───────────┘         │
│           │                                │                     │
│  ┌────────▼───────────┐     ┌──────────────▼───────────────────┐ │
│  │ Background Cron    │     │ Async Validation Sidecar         │ │
│  │ (6h poll interval) │     │ POST /validate → out-of-band     │ │
│  └────────┬───────────┘     │ GET /evidence  → async append    │ │
│           │                 └──────────────┬───────────────────┘ │
└───────────┼────────────────────────────────┼─────────────────────┘
            │                                │
            ▼                                ▼
┌──────────────────────────────────────────────────────────────────┐
│              External Normative Provider (Cloud)                 │
│                                                                  │
│  GET /legal-baseline/{region}     ← Normative Data Supply        │
│  POST /validate/fria              ← External Validation          │
│  GET /evidence-chain/{thread_id}  ← Attestation Logging          │
└──────────────────────────────────────────────────────────────────┘
```

##### Endpoint 1: `GET /legal-baseline/{region}` — Normative Data Supply

**Purpose:** Fetch the active legal/regulatory baseline for a deployment region.

**Integration pattern:** Boot-time initialization + periodic background refresh.

- **At container startup**, the FastAPI lifespan hook ([`hybrid_server.py`](../../../src/gateway/server/hybrid_server.py) L57-62) fetches the baseline via HTTP and writes it to `config/compliance/{REGION}_BASELINE.json`.
- `ControlRegistry._load_registry()` then loads the profile identically to the current static-file path — no changes to the singleton.
- A background `asyncio.Task` polls the endpoint at a configurable interval (default: 6 hours) and calls `ControlRegistry.reconfigure()` if the baseline has changed.
- **The hot path never touches the network.** All lookups resolve against the in-memory singleton.

**Fallback chain** (in order):

| Level | Source                                          | Condition                           |
| ----- | ----------------------------------------------- | ----------------------------------- |
| 1     | External provider HTTP API                      | Provider reachable at boot          |
| 2     | Local cached copy (`config/compliance/*.json`)  | Provider unreachable; cache exists  |
| 3     | Static bundled profile (committed to repo)      | No cache; first cold-start          |
| 4     | `RuntimeError` → container fails to start       | No profile found at any level       |

This four-level fallback extends the existing `ControlRegistry` two-level chain (regional JSON → legacy JSON) without modifying the registry's loading logic.

##### Endpoint 2: `POST /validate/fria` — External Validation

**Purpose:** Submit a Fundamental Rights Impact Assessment (or equivalent domain-specific attestation) for external validation against the provider's normative database.

**Integration pattern:** Async out-of-band validation with revocation on failure.

```
Transaction enters SymbolicGovernor
        │
        ├──► CBF enforces h(x) ≥ 0 locally (sub-μs)        ← HOT PATH
        │
        ├──► OPA evaluates ALLOW/DENY locally (~10-50ms)    ← HOT PATH
        │
        └──► Response returned to caller                    ← HOT PATH ENDS
                 │
                 └──► [async] POST /validate/fria payload
                             │
                             ├── ✅ Provider confirms → no action
                             │
                             └── ❌ Provider flags legal gap
                                      │
                                      └──► Revoke agent session token
                                           Emit SIEM alert
                                           Log to compliance Langfuse project
```

**Design decision: RESOLVED — Adaptive Gating Primitive (v2.1.0)**

The binary async-vs-sync choice has been rejected. Instead, [`enforce_fria_boundary()`](../../../src/gateway/governance/normative_provider.py) implements an **Asymmetric, Adaptive Runtime Policy** that maps the blocking semantic directly to the model's confidence boundary:

| Confidence Zone | Score Range | Execution Path | Hot-Path Impact |
| --- | --- | --- | --- |
| **HIGH** | ≥ 0.95 (`THRESHOLDS.confidence.min_trade_confidence`) | `ASYNC_ATTESTATION` — fire-and-forget | 0ms |
| **AMBIGUOUS** | [0.70, 0.95) (`DEFER_CONFIDENCE_THRESHOLD`) | `SYNC_GATE` — transaction frozen in DEFER queue until provider responds | Up to 5s (configurable) |
| **LOW** | < 0.70 | `LOCAL_HARD_DENY` — no external call | 0ms |

This anchors to the existing `DEFER` state machine ([`defer_queue.py`](../../../src/gateway/governance/defer_queue.py)) via the new `DeferReason.EXTERNAL_VALIDATION` enum member. The adaptive gate is positioned after all 7 local tiers — if local governance already DENY'd, the external provider is never contacted.

The gate runs as tier 6b in [`symbolic_governor.py`](../../../src/gateway/governance/symbolic_governor.py), activated only when `CAGE_NORMATIVE_PROVIDER != "static"`.

##### Endpoint 3: `GET /evidence-chain/{thread_id}` — Attestation Logging

**Purpose:** Submit the local governance evidence hash and retrieve an externally sealed attestation for the audit trail.

**Integration pattern:** Async background append.

- After the SymbolicGovernor pipeline completes, the governance evidence (KMS-signed, hash-chained) is emitted to the compliance Langfuse project.
- Simultaneously, an async task submits the evidence hash to the external provider.
- When the provider returns the external seal, it is appended to the audit record.
- **Zero blocking on the transaction path.** If the provider is unreachable, the local evidence chain remains intact and the external seal is retried on a backoff schedule.

#### 2.5.3 Architectural Precedent: `reconciliation_worker.py`

This async-fetch-sign-cache-and-fail-closed pattern is not a design proposal — it is already implemented in the CAGE codebase.

The [`reconciliation_worker.py`](../../../config/compliance/reconciliation_worker.py) (697 lines) implements exactly this architecture for the CBF external balance reconciliation:

| Reconciliation Worker Pattern                | External Normative Provider Equivalent         |
| -------------------------------------------- | ---------------------------------------------- |
| `LedgerProvider.fetch_balance()` → HTTP/gRPC  | `GET /legal-baseline/{region}` → HTTP          |
| KMS-sign payload before Redis write            | KMS-sign baseline before ControlRegistry load  |
| `ExternalLedgerReconciler.run_loop()` polling  | Background cron polling `/legal-baseline`      |
| `read_verified_balance()` → returns `None` if stale | `ControlRegistry` → fails if no profile loaded |
| CBF fails closed on stale/absent balance       | ControlRegistry raises `RuntimeError` on missing profile |
| `StubLedgerProvider` for dev/CI               | Static JSON profiles for dev/CI                |

The reconciliation worker proves the pattern is operationally sound: async external fetch, cryptographic signing, local cache with TTL, fail-closed on stale data.

#### 2.5.4 Provider Registration

External normative providers are configured via environment variables, following the same pattern as `RECONCILIATION_PROVIDER`:

```bash
# External normative provider configuration
CAGE_NORMATIVE_PROVIDER=trustlayers          # Provider name (default: "static")
CAGE_NORMATIVE_ENDPOINT=https://api.trustlayers.example.com
CAGE_NORMATIVE_POLL_INTERVAL_HOURS=6         # Background refresh interval
CAGE_NORMATIVE_BOOT_TIMEOUT_SECONDS=10       # Max wait at container init
CAGE_NORMATIVE_API_KEY_SECRET=projects/cage-prod/secrets/trustlayers-api-key
```

When `CAGE_NORMATIVE_PROVIDER=static` (default), the ControlRegistry loads from `config/compliance/` as it does today. No external dependency is introduced unless explicitly configured.

### 2.6 Vendor-Isolated Integration Architecture ✅ IMPLEMENTED

> **Status:** Implemented in v2.1.0. See `src/integrations/`.

All third-party compliance and attestation provider adapters are consolidated under `src/integrations/{vendor}/`, each with its own `__init__.py`, provider module, and test directory. This boundary prevents vendor SDK code from leaking into the governance kernel or gateway packages.

```
src/integrations/
├── __init__.py                # Provider factory (lazy-loading)
├── nexart/
│   ├── __init__.py
│   ├── adapter.py             # NexArtAttestationCallback (LangGraph callback handler) + NexArtClient
│   ├── provider.py            # NexArtProvider (NormativeProvider interface, JWK-verifiable CERs)
│   └── tests/
│       ├── __init__.py
│       ├── test_adapter.py
│       └── test_provider.py
└── trustlayers/
    ├── __init__.py
    └── provider.py            # TrustLayersProvider (3-endpoint normative provider adapter)
```

**Key architectural rules:**
- Cloud KMS (`kms_signer.py`) and Redis (`evidence_stream.py`) are **NOT** vendor adapters — they are substrate infrastructure invariants and remain in `src/gateway/governance/`.
- Each vendor directory is an optional dependency group in `pyproject.toml` (roadmap: PEP 508 extras).
- The provider factory in `src/integrations/__init__.py` uses lazy imports — vendor SDKs are not loaded unless explicitly configured via environment variables.

### 2.7 What Does NOT Change

The following components are domain-invariant by design and require **zero modification** for new domain onboarding:

- `ControlBarrierFunction.get_h()` — pure mathematical predicate
- `ControlRegistry` singleton — already reads arbitrary JSON profiles
- `SymbolicGovernor` 7-tier pipeline — evaluates mathematical/logical predicates only
- `GovernanceControl` enum — stable internal IDs, independent of external frameworks
- OPA Rego policy structure — declarative rules parameterized by profile metadata
- Cloud KMS HSM signing — domain-agnostic cryptographic attestation
- STPA-to-Policy Compiler — ingests YAML hazard definitions, not domain logic
- LangGraph Saga engine — atomic transaction guarantees independent of payload semantics

---

## Part 3 — The Reference Implementation: Financial Services

The `FINANCE_SR26_2_DORA` profile (current `US_FED_BASELINE.json`) serves as the active reference implementation demonstrating the full architecture:

### Implemented & Verified

| Capability                         | Source                                                                                   | Status       |
| ---------------------------------- | ---------------------------------------------------------------------------------------- | ------------ |
| CBF with `h(x) = cash - floor`    | [`safety.py`](../../../src/gateway/governance/safety.py) L151-153                        | ✅ Production |
| ControlRegistry (3 regions)        | [`constants.py`](../../../src/gateway/governance/constants.py) L121-308                  | ✅ Production |
| 7-Tier SymbolicGovernor            | [`symbolic_governor.py`](../../../src/gateway/governance/symbolic_governor.py)            | ✅ Production |
| Cloud KMS HSM signing              | [`kms_signer.py`](../../../src/gateway/governance/kms_signer.py)                         | ✅ Production |
| Heterogeneous multi-model consensus | [`consensus.py`](../../../src/gateway/governance/consensus.py)                           | ✅ Production |
| Fail-closed CBF enforcement        | `CBF_FAIL_OPEN=false` in `.env`                                                          | ✅ Verified   |
| DoWhy causal gatekeeper            | [`causal_gatekeeper.py`](../../../src/gateway/governance/causal_gatekeeper.py)            | ✅ Production |
| STPA-to-Policy Compiler            | [`stpa_compiler.py`](../../../src/gateway/governance/stpa_compiler.py)                    | ✅ Production |
| External CBF reconciliation        | [`reconciliation_worker.py`](../../../config/compliance/reconciliation_worker.py)         | ✅ Production |
| External Normative Provider (§2.5)| [`normative_provider.py`](../../../src/gateway/governance/normative_provider.py)          | ✅ Production |
| TrustLayers normative provider     | [`src/integrations/trustlayers/provider.py`](../../../src/integrations/trustlayers/provider.py) | ✅ Production |
| NexArt attestation provider        | [`src/integrations/nexart/provider.py`](../../../src/integrations/nexart/provider.py)    | ✅ Production |
| OPA policy enforcement             | [`config/opa/`](../../../config/opa/)                                                     | ✅ Production |
| NeMo input/output rails            | [`config/rails/`](../../../config/rails/)                                                 | ✅ Production |
| LangGraph Saga engine              | `src/governed_financial_advisor/agents/`                                                   | ✅ Production |
| Automated test suite (844 passing, 0 failed, 24 skipped) | [`tests/`](../../../tests/)                                                   | ✅ Passing    |

### Architecture Insight: Why Financial Services First

Financial services is the highest-constraint domain for AI governance:
- **SR 26-2** mandates dual-track model risk management (traditional MRM + agentic oversight)
- **DORA Art. 10-12** requires ICT operational resilience with fail-closed defaults
- **ISO 42001** provides the international agentic AI management system baseline
- **MAS FEAT / EU AI Act** add jurisdictional overlay requirements

By solving the hardest regulatory domain first, the CAGE kernel naturally generalizes downward. Any domain with simpler governance requirements (fewer tiers, fewer controls, lower frequency validation) is a strict subset of the financial services enforcement surface.

---

## Conclusion

The CAGE runtime is not a financial services application with governance features. It is a **domain-agnostic governance kernel** whose first production deployment happens to be financial services. The mathematical invariant `h(x) ≥ 0` does not know what `x` means — it only knows the boundary must not be crossed.

The path to multi-domain extensibility is a configuration exercise, not a rewrite. The kernel is ready. The profiles are the product.

---

## Platform Portability

CAGE's driver-based extensibility model ensures the governance kernel is not tied to any specific cloud provider or Kubernetes distribution. The three key extension points are:

| Extension Point | GCP Driver | AWS Driver | Azure Driver | On-Prem / Agnostic |
|---|---|---|---|---|
| **KMS / Audit Signing** | `GCPKMSProvider` (Cloud KMS) | `AWSKMSProvider` (AWS KMS) | `AzureKMSProvider` (Azure Key Vault) | HashiCorp Vault |
| **Evidence Storage** | `GCSStorageBackend` (Cloud Storage) | `S3StorageBackend` (S3-compatible) | `S3StorageBackend` (Azure Blob via S3 interop) | `LocalStorageBackend` (filesystem / MinIO) |
| **Ingress / TLS** | GCE L7 + ManagedCertificate (`deployment/k8s/gcp/`) | AWS ALB Ingress Controller | Azure Application Gateway | nginx ingress (`deployment/k8s/ingress.yaml`) |

All three extension points are selected at runtime via environment variables (`KMS_PROVIDER`, `STORAGE_BACKEND`, `ingressClassName`) — no code changes are required to switch between providers.

> **For PA Lead reviewers:** This architecture is consistent with the Kubernetes extension NonProduct classification: CAGE works with any Kubernetes 1.24+ cluster. GCP integrations are optional drivers, not core dependencies. See [`infra/targets/agnostic/`](../../infra/targets/agnostic/) for the cloud-agnostic Terraform deployment target.

---

## Related Documentation

| Document                                                              | Relationship                                            |
| --------------------------------------------------------------------- | ------------------------------------------------------- |
| [CAUSAL_AND_CBF_GOVERNANCE.md](../governance/CAUSAL_AND_CBF_GOVERNANCE.md)       | Detailed CBF mathematical formulation and DoWhy design  |
| [GATEWAY_ARCHITECTURE.md](GATEWAY_ARCHITECTURE.md)                 | Full inference gateway architecture                     |
| [NEURO_SYMBOLIC_GOVERNANCE.md](../governance/NEURO_SYMBOLIC_GOVERNANCE.md)       | SymbolicGovernor pipeline deep-dive                     |
| [Technical Report Series](../technical-report/README.md)              | Complete 10-document engineering record                 |
| [config/compliance/README.md](../../../config/compliance/README.md)   | Regional profile specification and authoring guide      |
| [DUAL_PROJECT_ARCHITECTURE.md](DUAL_PROJECT_ARCHITECTURE.md)         | Dual-project telemetry isolation design and threat model |
