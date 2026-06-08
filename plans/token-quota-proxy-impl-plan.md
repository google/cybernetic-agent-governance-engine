# CAGE 2.0.0 Stable Release — Unified Implementation Plan

**Document version:** 4.1.0 (policy update — enforces ISO 42001-only global baseline + additive regional layers as canonical release standard)
**ISO 42001 Change Category:** Cat-N (Normal) — 5 business day CAB review required
**Cross-region impact:** US_FED · EU_ECB · APAC_MAS (shared module: `src/gateway/governance/`)
**Gap Analysis source:** `plans/release-readiness-gap-analysis.md` v1.0.0 (2026-06-08)
**Authority:** `.clinerules` §1–14, `docs/GIT_WORKFLOW_STANDARDS.md`, `docs/DEPLOYMENT_RULES.md`
**Architecture policy:** ISO 42001-only global baseline; regional frameworks are additive layers only (`.clinerules` §5.1–5.4, `config/compliance/README.md` §Layered Compliance Architecture)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Boundaries](#2-scope-and-boundaries)
3. [Architecture Overview](#3-architecture-overview)
4. [Detailed Component Specifications](#4-detailed-component-specifications)
5. [Data Flow Diagrams](#5-data-flow-diagrams)
6. [Redis Schema](#6-redis-schema)
7. [Rego Policy Additions](#7-rego-policy-additions)
8. [UCA Record Generation Logic](#8-uca-record-generation-logic)
9. [PII Sanitization Pipeline](#9-pii-sanitization-pipeline)
10. [Release Gate Evaluation — Universal](#10-release-gate-evaluation--universal)
11. [Release Gate Evaluation — Region-Specific](#11-release-gate-evaluation--region-specific)
12. [Critical Gaps and P0/P1 Blockers](#12-critical-gaps-and-p0p1-blockers)
13. [Implementation Phases — Track A: Token Quota Proxy](#13-implementation-phases--track-a-token-quota-proxy)
14. [Implementation Phases — Track B: P0/P1 Blocker Remediation](#14-implementation-phases--track-b-p0p1-blocker-remediation)
15. [Implementation Phases — Track C: Seal Enforcement Verification](#15-implementation-phases--track-c-seal-enforcement-verification)
16. [Implementation Phases — Track D: Compliance Validation](#16-implementation-phases--track-d-compliance-validation)
17. [Implementation Phases — Track E: Tagging and Release](#17-implementation-phases--track-e-tagging-and-release)
18. [Testing Strategy](#18-testing-strategy)
19. [Compliance Traceability Matrix](#19-compliance-traceability-matrix)
20. [Branch and PR Strategy](#20-branch-and-pr-strategy)
21. [Risk Register and Rollback Procedures](#21-risk-register-and-rollback-procedures)
22. [Monitoring and Alerting](#22-monitoring-and-alerting)
23. [Non-Critical Gaps — Deferred Items](#23-non-critical-gaps--deferred-items)
24. [Success Metrics and Acceptance Criteria](#24-success-metrics-and-acceptance-criteria)
25. [Release Decision Criteria](#25-release-decision-criteria)

---

## 1. Executive Summary

### 1.1 Purpose of This Document

This document is the **single authoritative roadmap** for delivering CAGE 2.0.0 as a production-ready stable release. It is written from scratch and fully integrates:

- The Token Quota Proxy feature implementation plan (original `plans/token-quota-proxy-impl-plan.md`)
- All findings, deficiencies, and recommendations from the gap analysis (`plans/release-readiness-gap-analysis.md` v1.0.0, 2026-06-08)

No other document defines the scope of work required for the v2.0.0 stable tag. Development, QA, and release management teams must follow this document exclusively.

### 1.2 What Is Being Built

Three tightly coupled governance capabilities inside the CAGE DGE (Dynamic Governance Engine) Plane:

**1. Token Quota Proxy** — A stateful, inline circuit breaker that intercepts every call to external foundational models and enforces hard per-session token and step-count quotas. Backed by Redis atomic counters via Lua script, it blocks execution and forces safe rollback when `sequence_step_count > 12` OR `accumulated_tokens > quota_max`. Fail-CLOSED: Redis unavailable → request blocked.

**2. UCA Compliance Record Logger** — Every blocked execution produces a cryptographically signed Unsafe Control Action (UCA) record persisted to the WORM ledger via [`storage.py`](../src/compliance_bridge/storage.py). Records are signed using the existing [`KMSGovernanceSigner`](../src/gateway/governance/kms_signer.py) and conform to the ISO 42001 Clause 6.1 JSON schema.

**3. 3-Step Audit Verification Suite** — A pytest-based compliance verification harness that exercises prompt injection blocking (Annex A.2/A.6), infinite-loop quota exhaustion (Annex A.4), and PII sanitization (Clause 9) in a reproducible, CI-gated sequence.

### 1.3 Gap Analysis Verdict

The gap analysis (`plans/release-readiness-gap-analysis.md`) assessed the Token Quota Proxy plan against v2.0.0 release gates and returned **CONDITIONALLY READY**:

- The Token Quota Proxy PR **may be merged to `main` independently** of the P0 blockers (Track A).
- The **v2.0.0 stable tag cannot be applied** until five pre-existing P0/P1 blockers (D-01, D-02, D-04, D-06, D-07) are resolved via a separate `fix/v2-p0-blockers` branch (Track B).
- Two commit message violations (Phase 2c and squash PR title exceed 72 chars) **must be corrected** before the PR is opened — both are corrected in this document.
- Eight additional universal release gates (U-01 through U-08) require post-merge validation actions.

### 1.4 Why This Is Being Built

CAGE is pursuing ISO 42001:2023 certification. The certification evidence package requires demonstrable, machine-verifiable controls for:

- **Annex A.4 (Resource Management):** Compute and token resource protection with hard caps
- **Clause 6.1 (STPA Risk Logging):** Every unsafe control action must produce a signed, immutable audit record
- **Annex A.6 (Data Lineage and PII Leak Mitigation):** Pre-ledger sanitization before any WORM write
- **Annex A.2 (Operational Boundaries):** Signed JWT in every inter-agent gRPC call; OPA `tool_approved` rule

The Token Quota Proxy is the primary evidence mechanism for Annex A.4. Without it, the certification body has no machine-verifiable proof that the system enforces resource limits on agentic loops.

### 1.5 Parallel Work Tracks

```
Track A — Token Quota Proxy PR (feat/TQP-001-token-quota-proxy → main)
Track B — P0/P1 Blocker Remediation (fix/v2-p0-blockers → rc-v2.0.0)
Track C — Seal Enforcement Verification (depends on B)
Track D — Compliance Validation (depends on A + B + C)
Track E — Tagging and Release (depends on all prior tracks)
```

Tracks A and B are **independent** and may proceed in parallel. Tracks C, D, and E are sequential and depend on prior tracks completing.

### 1.6 Gap Analysis Integration Summary

Every gap, risk, and deficiency identified in `plans/release-readiness-gap-analysis.md` is addressed in this document as follows:

| Gap Analysis Finding | Section in This Document |
|---|---|
| D-01: Committed secrets (P0) | §12.1, §14.1–14.5 |
| D-02: Pod MinimumReplicasUnavailable (P0) | §12.2, §14.6–14.7 |
| D-04: HMAC seal enforcement disabled (P0) | §12.3, §14.8–14.9, §15 |
| D-06: security-scanner-cronjob missing (P1) | §12.4, §14.10 |
| D-07: PSA labels not applied (P1) | §12.5, §14.11 |
| U-01–U-04: Lula re-validation deferred | §10, §16.1–16.4 |
| U-05: SBOM not regenerated | §10, §16.5 |
| U-08: New tests must pass CI | §13.5, §18 |
| U-09: STPA freshness | §13.4, §18.4 |
| Commit message violations (Phase 2c, PR title) | §20.2 |
| OPA dead-code risk | §4.6, §7 |
| OSCAL component update for CTRL_TQP_007 | §19, §23.6 |
| Region-specific gates (F, E, A series) | §11, §23 |

### 1.7 Architecture Policy Changes (v4.1.0 — Finalized Baseline)

The following architectural policy decisions have been confirmed and applied across all governing documents. They are **finalized baseline state** — not open action items.

#### ISO 42001-Only Global Baseline

The global stable tag `v2.0.0` is gated exclusively on ISO 42001 universal gates (`.clinerules` §5.1). No regional framework gate (NIST SP 800-53, EU AI Act, GDPR, DORA, MAS FEAT, MAS Notice 655) is a prerequisite for the global stable tag. This is enforced in:

- **`.clinerules` §5.1:** Added `ARCHITECTURE:` comment block confirming ISO 42001-only universal gates
- **`.clinerules` §5.2–5.4:** Added `SCOPE:` comment blocks to each regional section confirming they block regional deployment only, not the global stable tag
- **`docs/V2_RELEASE_PLAN.md` §2 Dependency Graph:** Phase 6 prerequisite corrected — NIST ≥45% and ATO are US_FED deployment gates, not global tag prerequisites
- **`docs/V2_RELEASE_PLAN.md` §8.5:** Added US_FED-ONLY blockquote; closing note updated to reference US_FED production promotion rather than tagging
- **`docs/V2_RELEASE_PLAN.md` §8.8 tag message:** Replaced `NIST coverage ≥45%. ATO process initiated.` with `US_FED deployment requires separate NIST ≥45% and ATO gates (.clinerules §5.2).`

#### Compliance Traceability Corrections

- **§12.4 D-06 description:** Corrected to distinguish U-17 (universal gate — `security-scanner-cronjob` exists in `governance-stack` namespace, `.clinerules` §5.1) from `lula-validation-ra5.yaml` (US_FED-only Lula assertion, not a universal gate)
- **§19 Compliance Traceability Matrix:** U-17 row updated to `Universal (Trivy)` with Lula assertion `N/A — verified by Trivy scan; lula-validation-ra5.yaml is US_FED-only`; U-18 row Lula assertion updated to `N/A — verified by kubectl; lula-validation-cm6.yaml is US_FED-only`

#### Regional Baseline Metadata (Machine-Readable)

All three regional baseline JSON files now carry `"_baseline_type": "additive_regional_layer"` as their first key, making the layered architecture relationship machine-readable and self-documenting:

| File | `_baseline_type` | `_global_baseline` | `_activation` |
|---|---|---|---|
| `config/compliance/US_FED_BASELINE.json` | `additive_regional_layer` | `ISO_42001` | `CAGE_DEPLOYMENT_REGION=US_FED` |
| `config/compliance/EU_ECB_BASELINE.json` | `additive_regional_layer` | `ISO_42001` | `CAGE_DEPLOYMENT_REGION=EU_ECB` |
| `config/compliance/APAC_MAS_BASELINE.json` | `additive_regional_layer` | `ISO_42001` | `CAGE_DEPLOYMENT_REGION=APAC_MAS` |

All three files validated as structurally sound JSON (parse verification passed).

#### Layered Compliance Architecture Documentation

`config/compliance/README.md` now contains a **"Layered Compliance Architecture"** section that documents:
- The ISO 42001-only global baseline and its gate reference (`.clinerules` §5.1)
- The three regional additive layers with activation table
- Five non-negotiable rules governing the relationship between global and regional postures

---

## 2. Scope and Boundaries

### 2.1 In Scope

The following work items are required for the v2.0.0 stable tag and are covered by this plan:

**New source files:**
- `src/gateway/governance/token_quota_proxy.py` — stateful circuit breaker with Redis Lua atomicity
- `src/gateway/governance/uca_logger.py` — KMS-signed UCA record builder and WORM persister
- `src/gateway/governance/pii_sanitizer.py` — pre-ledger regex sanitization pipeline

**Modified source files:**
- [`src/gateway/server/inference_proxy.py`](../src/gateway/server/inference_proxy.py) — quota check inserted as step 2
- [`src/gateway/server/hybrid_server.py`](../src/gateway/server/hybrid_server.py) — pre-warming in `_gateway_lifespan()`
- [`deployment/system_authz.rego`](../deployment/system_authz.rego) — new quota and tool-approval Rego rules
- [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py) — `CTRL_TQP_007` enum entry

**New configuration files:**
- `config/thresholds/token_quota.yaml` — per-session quota defaults and model overrides

**New test files:**
- `tests/test_token_quota_proxy.py`
- `tests/test_uca_logger.py`
- `tests/test_pii_sanitizer.py`

**Compliance artifacts:**
- `CHANGELOG.md` — `[CR-2026-TQP-001]` Cat-N entry
- `config/compliance/US_FED_BASELINE.json` — `CTRL_TQP_007` entry
- `config/compliance/EU_ECB_BASELINE.json` — `CTRL_TQP_007` entry
- `config/compliance/APAC_MAS_BASELINE.json` — `CTRL_TQP_007` entry

**P0/P1 blocker remediation (Track B):**
- D-01: Committed secrets — working tree fix, credential rotation, git history rewrite
- D-02: `governed-financial-advisor` pod availability — Cloud Build trigger
- D-04: HMAC seal enforcement — Terraform wiring for `CAGE_ROUTING_SEAL_SECRET` and `GOVERNANCE_SALT`
- D-06: `security-scanner-cronjob` — manifest apply
- D-07: PSA labels — namespace label apply and Terraform apply

**Post-merge validation (Tracks C and D):**
- All four universal Lula assertions re-validated against live cluster
- SBOM regenerated and Trivy scan passed
- Full test suite: 0 failures
- Seal enforcement verified: unsigned → 403, signed → 200

**Release execution (Track E):**
- Annotated tag `v2.0.0` pushed to origin
- GitHub Release published as Latest

### 2.2 Out of Scope

The following items are explicitly excluded from this plan and do not affect the global v2.0.0 stable tag:

- Changes to gRPC proto definitions
- Changes to NeMo guardrails configuration files
- Changes to the Langfuse evaluation pipeline
- US_FED-specific NIST SP 800-53 gates (F-01 through F-04) — block US_FED deployment only
- EU_ECB-specific gates (E-01 through E-04) — block EU_ECB deployment only
- APAC_MAS-specific gates (A-01 through A-04) — block APAC_MAS deployment only
- UCA-4 addition to `config/stpa_control_structure.yaml` (deferred to follow-on PR)
- OSCAL component definition update for `CTRL_TQP_007` in `compliance/oscal/` (2-business-day follow-on)
- OPA runtime injection of Redis session state into `governance_middleware.py` (deferred; Python enforcer is primary)

### 2.3 Cross-Region Guard Requirement

All new storage paths and telemetry sinks in `src/gateway/governance/` must be gated on `CAGE_DEPLOYMENT_REGION` per `.clinerules` §12. This is enforced by the `_get_worm_bucket()` method in `uca_logger.py`:

- `US_FED` → `OSCAL_S3_BUCKET_US_FED` (us-central1 or approved US region)
- `EU_ECB` → `OSCAL_S3_BUCKET_EU_ECB` (europe-west1 only — GDPR Art. 44)
- `APAC_MAS` → `OSCAL_S3_BUCKET_APAC_MAS` (asia-southeast1 only — MAS TRM §4.2)

Any PR touching `src/gateway/governance/`, `src/compliance_bridge/`, `config/compliance/`, `config/thresholds/`, or `config/oscal/` must declare cross-region impact for all three regions per `.clinerules` §3.7.

---

## 3. Architecture Overview

### 3.1 Existing DGE Plane Components (Relevant)

| Component | File | Role |
|---|---|---|
| Inference Proxy | [`inference_proxy.py`](../src/gateway/server/inference_proxy.py) | Routes `/v1/chat/completions` through governance pipeline to vLLM |
| Hybrid Server | [`hybrid_server.py`](../src/gateway/server/hybrid_server.py) | Composition root; mounts sub-apps; runs lifespan hooks |
| ISO Control Stamper | [`iso_control.py`](../src/gateway/governance/iso_control.py) | Stamps OTel spans with ISO 42001 evidence attributes |
| Fiscal Limit Guard | [`fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py) | Atomic Redis WATCH/MULTI/EXEC pre-reservation for fiscal limits |
| Redis Client | [`redis_client.py`](../src/gateway/infrastructure/redis_client.py) | Shared async/sync Redis wrapper with `watched_transaction()` |
| Routing Seal | [`routing_seal.py`](../src/gateway/governance/routing_seal.py) | HMAC-SHA256 short-lived governance seals |
| KMS Signer | [`kms_signer.py`](../src/gateway/governance/kms_signer.py) | Cloud KMS asymmetric signing for governance plans |
| WORM Storage | [`storage.py`](../src/compliance_bridge/storage.py) | GCS/S3 OSCAL artifact persistence |
| STPA Validator | [`generated_stpa_validator.py`](../src/gateway/governance/generated_stpa_validator.py) | Auto-generated UCA constraint checks |
| OPA Policy | [`system_authz.rego`](../deployment/system_authz.rego) | System authorization policy |
| Constants/Registry | [`constants.py`](../src/gateway/governance/constants.py) | `GovernanceControl` enum and `ControlRegistry` singleton |
| Governance Middleware | [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) | Injects session state into OPA input document |

### 3.2 New Components Being Added

| Component | File | Role |
|---|---|---|
| Token Quota Proxy | `src/gateway/governance/token_quota_proxy.py` | Stateful circuit breaker; Redis Lua counters; 429 enforcement |
| UCA Logger | `src/gateway/governance/uca_logger.py` | Builds, signs, and persists UCA compliance records |
| PII Sanitizer | `src/gateway/governance/pii_sanitizer.py` | Pre-ledger regex sanitization pipeline |
| Quota Config | `config/thresholds/token_quota.yaml` | Per-session quota defaults and model overrides |

### 3.3 Component Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DGE Plane (Gateway)                          │
│                                                                     │
│  ┌──────────────┐    ┌──────────────────────────────────────────┐  │
│  │  Cognitive   │    │           Inference Proxy                │  │
│  │    Core      │───►│  /v1/chat/completions                    │  │
│  │  (Agent)     │    │                                          │  │
│  └──────────────┘    │  1. Tier-1 keyword scan                  │  │
│                      │  2. [NEW] Token Quota Check ◄────────┐   │  │
│                      │  3. NeMo input verification           │   │  │
│                      │  4. ISO 42001 evidence stamp          │   │  │
│                      │  5. Forward to vLLM                   │   │  │
│                      └──────────────────────────────────────┘   │  │
│                                          │                       │  │
│                              429 BLOCK   │                       │  │
│                                          ▼                       │  │
│                      ┌──────────────────────────────────────┐   │  │
│                      │        Token Quota Proxy             │   │  │
│                      │  token_quota_proxy.py                │   │  │
│                      │                                      │   │  │
│                      │  ┌─────────────┐  ┌──────────────┐  │   │  │
│                      │  │   Redis     │  │  UCA Logger  │  │   │  │
│                      │  │  Counters   │  │ uca_logger.py│  │   │  │
│                      │  │             │  │              │  │   │  │
│                      │  │ step_count  │  │ PII Sanitize │  │   │  │
│                      │  │ token_accum │  │ KMS Sign     │  │   │  │
│                      │  └─────────────┘  │ WORM Write   │  │   │  │
│                      │                   └──────────────┘  │   │  │
│                      └──────────────────────────────────────┘   │  │
│                                                                  │  │
│  ┌──────────────────────────────────────────────────────────┐   │  │
│  │                    Redis (Stateful Store)                 │   │  │
│  │  quota:session:{agent_uuid}:steps    (INCR, TTL=3600)    │   │  │
│  │  quota:session:{agent_uuid}:tokens   (INCRBY, TTL=3600)  │   │  │
│  │  quota:session:{agent_uuid}:meta     (HSET, TTL=3600)    │   │  │
│  └──────────────────────────────────────────────────────────┘   │  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │              WORM Ledger (GCS/S3)                        │      │
│  │  uca-records/{date}/{compliance_event_id}.yaml           │      │
│  └──────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 Integration Point: Where the Proxy Sits

The Token Quota Proxy is inserted as **step 2** in the existing [`chat_completions()`](../src/gateway/server/inference_proxy.py) handler, between the Tier-1 keyword scan and the NeMo input verification. This placement ensures:

1. Quota enforcement happens before any expensive NeMo or vLLM calls
2. The existing governance pipeline (steps 3–5) is only reached for requests that pass quota
3. A blocked request still gets an ISO 42001 evidence stamp (via `stamp_iso_control`) before returning 429

### 3.5 Fail-CLOSED Security Posture

The Token Quota Proxy mirrors the security posture of [`FiscalLimitGuard`](../src/gateway/governance/fiscal_limit_guard.py):

- Redis unavailable → request **BLOCKED** (not allowed through)
- KMS signing unavailable → UCA record written with HMAC-SHA256 stub in test mode; in production, signing failure raises and the request is blocked
- WORM write failure → UCA record is logged to structured stderr and the block is still enforced (the block is not contingent on successful WORM write)

---

## 4. Detailed Component Specifications

### 4.1 `src/gateway/governance/token_quota_proxy.py` — New File

**Purpose:** Stateful inline circuit breaker enforcing per-session token and step-count quotas. Mirrors the atomic reservation pattern from [`fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py) but operates on token counts rather than USD amounts.

**License header:** Apache 2.0 required by `.clinerules` §10.2 for all new `.py` files under `src/`.

#### Exception: `QuotaExceededError`

```python
class QuotaExceededError(Exception):
    """Raised when a session exceeds its token or step-count quota.

    Attributes:
        agent_id:      The agent UUID session that was blocked.
        reason:        Human-readable reason: "step_count" or "token_count".
        current_value: The counter value that triggered the block.
        quota_max:     The configured hard limit.
        session_key:   The Redis key prefix for this session.
    """
    def __init__(
        self,
        agent_id: str,
        reason: str,
        current_value: int,
        quota_max: int,
        session_key: str,
    ) -> None: ...
```

#### Dataclass: `QuotaCheckResult`

```python
@dataclass
class QuotaCheckResult:
    allowed: bool
    agent_id: str
    step_count: int
    accumulated_tokens: int
    step_quota_max: int
    token_quota_max: int
    block_reason: Optional[str]
    session_ttl: int
```

#### Class: `TokenQuotaProxy`

Key design decisions validated by the gap analysis:

- **Lua script atomicity:** All counter mutations use a single Redis Lua script via `EVALSHA`. Eliminates the parallel-branch over-allocation race that bare `INCRBY` + Python check would create.
- **Two-phase commit:** Phase 1 (`check_and_increment`) reserves `max_tokens`. Phase 2 (`reconcile_actual_tokens`) corrects over-allocation after vLLM responds.
- **Fail-CLOSED:** Redis unavailable → request BLOCKED. Matches security posture of `FiscalLimitGuard`.
- **Rollback on downstream failure:** `rollback_step()` decrements counters when NeMo/OPA/vLLM fails after quota was reserved.

```python
class TokenQuotaProxy:
    def __init__(
        self,
        redis_client: object,
        step_quota_max: int = 12,
        token_quota_max: int = 100_000,
        session_ttl: int = 3600,
    ) -> None: ...

    @classmethod
    def from_env(cls) -> "TokenQuotaProxy": ...

    async def check_and_increment(
        self, agent_id: str, token_delta: int = 0,
    ) -> QuotaCheckResult: ...

    async def reconcile_actual_tokens(
        self, agent_id: str, reserved_tokens: int, actual_tokens_used: int,
    ) -> None: ...

    async def rollback_step(
        self, agent_id: str, reserved_tokens: int,
    ) -> None: ...

    async def reset_session(self, agent_id: str) -> None: ...

    async def get_session_state(self, agent_id: str) -> dict: ...

    def _session_key(self, agent_id: str, suffix: str) -> str:
        return f"quota:session:{agent_id}:{suffix}"
```

#### Singleton accessor (module-level, lazy init)

```python
_token_quota_proxy: Optional[TokenQuotaProxy] = None

def _get_token_quota_proxy() -> TokenQuotaProxy:
    global _token_quota_proxy
    if _token_quota_proxy is None:
        _token_quota_proxy = TokenQuotaProxy.from_env()
    return _token_quota_proxy
```

### 4.2 `src/gateway/governance/uca_logger.py` — New File

**Purpose:** Builds, cryptographically signs, and persists UCA compliance records to the WORM ledger. Implements ISO 42001 Clause 6.1.

**License header:** Apache 2.0 required.

#### Class: `UCALogger`

```python
class UCALogger:
    def __init__(
        self,
        signer: Optional[object],
        redis_client: object,
        bucket: str,
        pii_sanitizer: object,
        test_mode: bool = False,
    ) -> None: ...

    @classmethod
    def from_env(cls) -> "UCALogger": ...

    async def log_quota_exceeded(
        self, quota_result: "QuotaCheckResult", request_body: dict,
    ) -> str: ...

    async def log_prompt_injection(
        self, agent_id: str, injected_content: str, block_reason: str,
    ) -> str: ...

    async def log_pii_sanitization(
        self, agent_id: str, tool_name: str, original_args: str, sanitized_args: str,
    ) -> str: ...

    async def _build_uca_record(self, ...) -> dict: ...
    async def _persist_uca_record(self, record: dict) -> str: ...
    async def _generate_event_id(self) -> str: ...
```

#### WORM bucket region guard

```python
def _get_worm_bucket(self) -> str:
    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    bucket_map = {
        "US_FED":   os.environ.get("OSCAL_S3_BUCKET_US_FED",
                        os.environ.get("OSCAL_S3_BUCKET", "")),
        "EU_ECB":   os.environ.get("OSCAL_S3_BUCKET_EU_ECB",
                        os.environ.get("OSCAL_S3_BUCKET", "")),
        "APAC_MAS": os.environ.get("OSCAL_S3_BUCKET_APAC_MAS",
                        os.environ.get("OSCAL_S3_BUCKET", "")),
    }
    return bucket_map.get(region, os.environ.get("OSCAL_S3_BUCKET", ""))
```

This ensures EU_ECB UCA records stay within `europe-west1` and APAC_MAS records stay within `asia-southeast1`, satisfying gap analysis gates E-02 and A-02.

#### Test mode signing

In `CAGE_ENV=test`, `UCALogger` uses HMAC-SHA256 stub when `test_mode=True`:

```python
if self.test_mode:
    import hmac, hashlib
    stub_sig = hmac.new(
        b"test-key",
        json.dumps(record, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()
    record["cryptographic_signature"] = f"0xSTUB_{stub_sig[:16]}"
```

### 4.3 `src/gateway/governance/pii_sanitizer.py` — New File

**Purpose:** Pre-ledger regex sanitization pipeline. Implements ISO 42001 Annex A.6.

**License header:** Apache 2.0 required.

#### Regex pattern specifications

```python
_PII_PATTERNS: list[tuple[str, str]] = [
    (r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
     "[REDACTED_SSN]"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
     r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}"
     r"|(?:2131|1800|35\d{3})\d{11})(?:[-\s]?\d{4}){0,3}\b",
     "[REDACTED_CC]"),
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
     "[REDACTED_EMAIL]"),
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
     "[REDACTED_PHONE]"),
    (r"\b(?:pk-lf-|sk-lf-|hf_|Bearer\s+)[A-Za-z0-9_\-]{8,}\b",
     "[REDACTED_API_KEY]"),
]
```

### 4.4 Modifications to [`src/gateway/server/inference_proxy.py`](../src/gateway/server/inference_proxy.py)

Insert quota check as **step 2** in `chat_completions()`, after Tier-1 keyword scan, before NeMo. Function signature must be updated to accept `background_tasks: BackgroundTasks`.

```python
# ── Step 2 (NEW): Token Quota Enforcement (ISO 42001 Annex A.4) ────────
agent_id = (body.get("agent_id")
            or request.headers.get("X-Agent-ID", "")
            or "anonymous")
token_delta = int(body.get("max_tokens", 0))
quota_result = await _get_token_quota_proxy().check_and_increment(
    agent_id=agent_id, token_delta=token_delta,
)
if not quota_result.allowed:
    stamp_iso_control(span, tier=2, control="A.4", outcome="BLOCK")
    # IMPORTANT: awaited inline — NOT background_tasks.add_task.
    # Quota blocks are rare circuit-breaker events. The WORM ledger write
    # must complete before the 429 is returned to guarantee ISO 42001
    # Clause 6.1 audit lineage survives spot-instance eviction or
    # container scale-down immediately after the response is sent.
    await _get_uca_logger().log_quota_exceeded(quota_result, body)
    return JSONResponse(content={
        "error": "quota_exceeded",
        "reason": quota_result.block_reason,
        "step_count": quota_result.step_count,
        "accumulated_tokens": quota_result.accumulated_tokens,
        "quota_max_steps": quota_result.step_quota_max,
        "quota_max_tokens": quota_result.token_quota_max,
        "agent_id": agent_id,
        "iso42001_control": "A.4",
        "dge_action": "TERMINATED_WITH_ROLLBACK",
    }, status_code=429)
stamp_iso_control(span, tier=2, control="A.4", outcome="PASS")
```

Steps 3–5 must be wrapped in `try/except` to call `rollback_step()` on downstream failure.

### 4.5 Modifications to [`src/gateway/server/hybrid_server.py`](../src/gateway/server/hybrid_server.py)

Add pre-warming in `_gateway_lifespan()` after the OPA pre-warm block:

```python
try:
    from src.gateway.governance.token_quota_proxy import TokenQuotaProxy
    from src.gateway.governance.uca_logger import UCALogger
    app.state.token_quota_proxy = TokenQuotaProxy.from_env()
    app.state.uca_logger = UCALogger.from_env()
    logger.info("Token Quota Proxy and UCA Logger pre-warmed")
except Exception as e:
    logger.warning("Token Quota Proxy pre-warm failed (non-blocking): %s", e)
```

### 4.6 New OPA Rego Rules — [`deployment/system_authz.rego`](../deployment/system_authz.rego)

> **CRITICAL — Runtime Integration vs. Dead-Code Risk (gap analysis finding):**
> The Rego rules are only meaningful if [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) injects Redis session state into the OPA `input` document. Without this injection, the rules are dead code. If runtime OPA integration is deferred to a follow-on PR, document `CTRL_TQP_007` explicitly as "Python DGE enforcer — OPA rules are secondary evidence layer" in the OSCAL component definition. This deferral is acceptable per §23.7.

See §7 for the full Rego rule text.

### 4.7 New Threshold Config — `config/thresholds/token_quota.yaml`

```yaml
defaults:
  step_quota_max: 12
  token_quota_max: 100000
  session_ttl_seconds: 3600

model_overrides:
  "deepseek-r1":
    token_quota_max: 50000
  "deepseek-reasoning":
    token_quota_max: 50000

iso42001_control: "A.4"
evidence_mechanism: "stateful-redis-counter"
enforcement_tier: 2
```

### 4.8 Modifications to [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py)

Add the new control to the `GovernanceControl` enum:

```python
TOKEN_QUOTA_ENFORCEMENT = "CTRL_TQP_007"
```

Register it in `ControlRegistry` with metadata:

```python
ControlRegistry.register(
    GovernanceControl.TOKEN_QUOTA_ENFORCEMENT,
    iso_clause="A.4",
    description="Per-session token and step-count quota enforcement via Redis atomic counters",
    enforcement_tier=2,
)
```

---

## 5. Data Flow Diagrams

### 5.1 Happy Path — Request Allowed

```
Agent → POST /v1/chat/completions
  │
  ├─ Step 1: Tier-1 keyword scan → PASS
  │
  ├─ Step 2: TokenQuotaProxy.check_and_increment(agent_id, token_delta)
  │     └─ Redis Lua: INCR steps_key; INCRBY tokens_key token_delta
  │           └─ steps ≤ 12 AND tokens ≤ quota_max → allowed=True
  │
  ├─ Step 3: NeMo input verification → PASS
  ├─ Step 4: stamp_iso_control(A.4, PASS)
  ├─ Step 5: Forward to vLLM → response
  │
  └─ Post-response: reconcile_actual_tokens(reserved, actual_used)
        └─ Redis Lua: adjust tokens_key by (actual - reserved)
```

### 5.2 Quota Exceeded Path — Request Blocked

```
Agent → POST /v1/chat/completions
  │
  ├─ Step 1: Tier-1 keyword scan → PASS
  │
  ├─ Step 2: TokenQuotaProxy.check_and_increment(agent_id, token_delta)
  │     └─ Redis Lua: INCR steps_key → 13 > 12 → allowed=False
  │           └─ QuotaCheckResult(allowed=False, block_reason="step_count")
  │
  ├─ stamp_iso_control(A.4, BLOCK)
  ├─ BackgroundTask: UCALogger.log_quota_exceeded(quota_result, body)
  │     ├─ PII sanitize request body
  │     ├─ Build UCA record (ISO 42001 Clause 6.1 schema)
  │     ├─ KMS sign record
  │     └─ WORM write to GCS/{region}/uca-records/{date}/{event_id}.yaml
  │
  └─ Return JSONResponse(status=429, body={error: "quota_exceeded", ...})
```

### 5.3 Downstream Failure Path — Rollback

```
Agent → POST /v1/chat/completions
  │
  ├─ Step 2: check_and_increment → allowed=True (quota reserved)
  │
  ├─ Step 3: NeMo verification → EXCEPTION raised
  │
  └─ except block: rollback_step(agent_id, reserved_tokens)
        └─ Redis Lua: DECR steps_key; DECRBY tokens_key reserved_tokens
```

---

## 6. Redis Schema

### 6.1 Key Naming Convention

All quota keys follow the pattern `quota:session:{agent_uuid}:{suffix}` with a 1-hour TTL (configurable via `session_ttl_seconds`).

| Key | Type | Operation | TTL | Purpose |
|---|---|---|---|---|
| `quota:session:{id}:steps` | String (integer) | `INCR` / `DECR` | 3600s | Step counter for the session |
| `quota:session:{id}:tokens` | String (integer) | `INCRBY` / `DECRBY` | 3600s | Accumulated token counter |
| `quota:session:{id}:meta` | Hash | `HSET` | 3600s | Session metadata (model, start time, agent class) |

### 6.2 Lua Script — Atomic Check-and-Increment

The following Lua script is loaded via `SCRIPT LOAD` at proxy initialization and called via `EVALSHA`:

```lua
-- KEYS[1] = steps_key, KEYS[2] = tokens_key
-- ARGV[1] = step_quota_max, ARGV[2] = token_quota_max
-- ARGV[3] = token_delta, ARGV[4] = ttl_seconds
local steps  = redis.call('INCR', KEYS[1])
local tokens = redis.call('INCRBY', KEYS[2], ARGV[3])
-- Fixed-window TTL: only set expiry on the first increment (TTL == -1 means
-- key exists but has no expiry; TTL == -2 means key does not exist, which
-- cannot happen here since INCR just created it). This prevents a slow
-- malfunctioning agent from perpetually extending the session window by
-- resetting the TTL on every call, which would permanently lock the session.
if redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[4])
end
if redis.call('TTL', KEYS[2]) < 0 then
    redis.call('EXPIRE', KEYS[2], ARGV[4])
end
if steps > tonumber(ARGV[1]) then
    redis.call('DECR', KEYS[1])
    redis.call('DECRBY', KEYS[2], ARGV[3])
    return {0, steps - 1, tokens - tonumber(ARGV[3]), "step_count"}
end
if tokens > tonumber(ARGV[2]) then
    redis.call('DECR', KEYS[1])
    redis.call('DECRBY', KEYS[2], ARGV[3])
    return {0, steps - 1, tokens - tonumber(ARGV[3]), "token_count"}
end
return {1, steps, tokens, ""}
```

### 6.3 Rollback Lua Script

```lua
-- KEYS[1] = steps_key, KEYS[2] = tokens_key
-- ARGV[1] = reserved_tokens
redis.call('DECR', KEYS[1])
redis.call('DECRBY', KEYS[2], ARGV[1])
return 1
```

### 6.4 Reconciliation Lua Script

```lua
-- KEYS[1] = tokens_key
-- ARGV[1] = reserved_tokens, ARGV[2] = actual_tokens_used
local delta = tonumber(ARGV[2]) - tonumber(ARGV[1])
if delta ~= 0 then
    redis.call('INCRBY', KEYS[1], delta)
end
return 1
```

---

## 7. Rego Policy Additions

### 7.1 Rules to Append to [`deployment/system_authz.rego`](../deployment/system_authz.rego)

> **Dead-code risk acknowledged (gap analysis finding):** These rules are secondary evidence. The Python `TokenQuotaProxy` is the primary enforcer. The rules become active only when [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) injects `sequence_step_count`, `accumulated_tokens`, and `token_quota_max` into the OPA `input` document. That injection is deferred to a follow-on PR (see §23.7). Until then, `quota_within_limits` and `token_quota_within_limits` default to `true` via the second clause of each rule.

```rego
# ── Token Quota Enforcement (ISO 42001 Annex A.4) ──────────────────────
# CTRL_TQP_007 — secondary declarative evidence layer.
# Primary enforcement: TokenQuotaProxy (Python, Redis Lua).
# These rules activate when governance_middleware.py injects session state.

_max_sequence_steps := 12

quota_within_limits if {
    step_count := object.get(input, "sequence_step_count", 0)
    step_count <= _max_sequence_steps
}
quota_within_limits if { not input.sequence_step_count }

token_quota_within_limits if {
    accumulated := object.get(input, "accumulated_tokens", 0)
    quota_max   := object.get(input, "token_quota_max", 100000)
    accumulated <= quota_max
}
token_quota_within_limits if { not input.accumulated_tokens }

# ── Tool Allowlist (ISO 42001 Annex A.2) ───────────────────────────────
_approved_tools := {
    "send_alert", "get_market_data", "execute_trade", "get_portfolio",
    "calculate_risk", "get_account_balance", "submit_order",
    "cancel_order", "get_order_status",
}
tool_approved if { input.tool_name; input.tool_name in _approved_tools }
tool_approved if { not input.tool_name }

# ── Combined governance allow rule ─────────────────────────────────────
cage_systemic_governance_allow if {
    confidence_sufficient
    quota_within_limits
    token_quota_within_limits
    tool_approved
}
```

### 7.2 Corrected Commit Message for Rego Changes

Per gap analysis finding (Phase 2c commit exceeded 72 chars), the corrected commit message is:

```
feat(governance): add quota rego rules to system-authz
```

(53 characters — within the 72-char limit enforced by the `commit-msg` hook.)

---

## 8. UCA Record Generation Logic

### 8.1 ISO 42001 Clause 6.1 Schema

Every UCA record written to the WORM ledger must conform to this schema:

```yaml
compliance_event_id: "UCA-{uuid4}"
timestamp: "2026-06-08T01:57:37Z"
iso42001_clause: "6.1"
iso42001_control: "A.4"
governance_control_id: "CTRL_TQP_007"
uca_type: "quota_exceeded"
agent_id: "{agent_uuid}"
session_key: "quota:session:{agent_uuid}"
block_reason: "step_count"
current_value: 13
quota_max: 12
request_summary: "{sanitized_body_excerpt}"
cryptographic_signature: "{kms_signature_hex}"
signing_key_id: "{kms_key_resource_name}"
deployment_region: "US_FED"
worm_path: "uca-records/2026-06-08/UCA-{uuid4}.yaml"
```

Valid `uca_type` values: `quota_exceeded`, `prompt_injection`, `pii_sanitization`.

### 8.2 Event ID Generation

Event IDs are generated as `UCA-{uuid4}` using `uuid.uuid4()`. The WORM path is `uca-records/{YYYY-MM-DD}/{event_id}.yaml` where the date is UTC.

### 8.3 Signing Procedure

1. Serialize the record to JSON with `sort_keys=True` (deterministic)
2. Call `KMSGovernanceSigner.sign(payload_bytes)` → returns hex signature
3. Set `record["cryptographic_signature"]` to the hex string
4. Set `record["signing_key_id"]` to the KMS key resource name
5. In test mode (`CAGE_ENV=test`), use HMAC-SHA256 stub (see §4.2)

### 8.4 WORM Write Procedure

1. Serialize the signed record to YAML
2. Call `WORMStorage.write(path, content, region)` with the region-gated bucket from `_get_worm_bucket()`
3. On write failure: log to structured stderr with `level=ERROR`; the block is still enforced
4. Return the `worm_path` string to the caller for audit trail

---

## 9. PII Sanitization Pipeline

### 9.1 Pipeline Stages

The sanitizer runs all patterns sequentially against the input string. Each pattern is applied via `re.sub()`.

```
Input string
  │
  ├─ Pattern 1: SSN → [REDACTED_SSN]
  ├─ Pattern 2: Credit card → [REDACTED_CC]
  ├─ Pattern 3: Email → [REDACTED_EMAIL]
  ├─ Pattern 4: Phone → [REDACTED_PHONE]
  └─ Pattern 5: API key / Bearer token → [REDACTED_API_KEY]
  │
  └─ Output: sanitized string
```

### 9.2 Integration Points

The PII sanitizer is called in two places:

1. **Before UCA record construction** in `UCALogger._build_uca_record()` — sanitizes the `request_summary` field
2. **Before WORM write** in `UCALogger._persist_uca_record()` — final sanitization pass on the full serialized record

### 9.3 Acceptance Criteria for PII Sanitization

| Input | Expected Output |
|---|---|
| `123-45-6789` | `[REDACTED_SSN]` |
| `4111-1111-1111-1111` | `[REDACTED_CC]` |
| `user@example.com` | `[REDACTED_EMAIL]` |
| `+1 (555) 867-5309` | `[REDACTED_PHONE]` |
| `pk-lf-abc123xyz` | `[REDACTED_API_KEY]` |
| `Bearer eyJhbGc...` | `[REDACTED_API_KEY]` |
| `clean text with no PII` | `clean text with no PII` |

### 9.4 Lula Gate Dependency

The `lula-validation-a92.yaml` assertion (gate U-03) verifies PII leak rate = 0.0% by querying `compliance-bridge /v1/metrics/A.9.2`. The PII sanitizer is the primary mechanism that drives this metric to zero. The Lula assertion must be re-run post-merge against a live cluster (see §16.3).

---

## 10. Release Gate Evaluation — Universal

> Source: `.clinerules` §5.1. All gates must pass before `git tag -a v2.0.0` is executed.

| # | Gate | Status | Track | Action Required | Acceptance Criterion |
|---|------|--------|-------|-----------------|----------------------|
| U-01 | ISO 42001 Lula: `lula-validation-a52.yaml` (NeMo toxicity/injection ≥99%) | Deferred post-merge | D | `lula validate -f compliance/lula/lula-validation-a52.yaml` on live cluster | Returns PASS |
| U-02 | ISO 42001 Lula: `lula-validation-a53.yaml` (logging/monitoring safety ≥98%) | Deferred post-merge | D | `lula validate -f compliance/lula/lula-validation-a53.yaml` on live cluster | Returns PASS |
| U-03 | ISO 42001 Lula: `lula-validation-a92.yaml` (PII leak rate = 0.0%) | Deferred post-merge | D | `lula validate -f compliance/lula/lula-validation-a92.yaml` on live cluster | Returns PASS |
| U-04 | CSA AARM Lula: `lula-validation-aarm-vectors.yaml` (all 11 vectors; 7 critical = NEUTRALIZED) | Deferred post-merge | D | `lula validate -f compliance/lula/lula-validation-aarm-vectors.yaml` on live cluster | Returns PASS |
| U-05 | SBOM generated and validated | Pre-existing gap | D | `python scripts/generate_sbom.py`; validate output; no new CRITICAL CVEs | SBOM generated; Trivy scan passes |
| U-06 | Container image vulnerability scan passes (Trivy — no CRITICAL unmitigated) | Blocked on D-06 | B then D | D-06 resolved first; trigger `kubectl create job --from=cronjob/security-scanner-cronjob` | No CRITICAL unmitigated CVEs |
| U-07 | Secret detection scan passes (zero secrets in codebase) | P0 blocker D-01 | B | Complete D-01 Phase 1–3; `git log --all -S "CYBERNETIC_GOVERNANCE_2025"` | Zero matches |
| U-08 | All unit and integration tests pass (`uv run pytest tests/ -m local -v`) | Deferred post-merge | A then D | New test files marked `@pytest.mark.local`; CI `pytest-logic` job green | 0 failures |
| U-09 | STPA freshness check passes (`scripts/check_stpa_freshness.py`) | Conditional | A | Do NOT modify `config/stpa_control_structure.yaml` in this PR | CI `stpa-freshness-check` green |
| U-10 | Langfuse posture verified (`scripts/verify_langfuse_posture.py --dry-run`) | Deferred | A | CI must pass on PR; run against live cluster before tagging | Script exits 0 |
| U-11 | `git log --all -S "<any-credential>"` returns zero matches | P0 blocker D-01 | B | Complete Phase 3 history rewrite via `git filter-repo` | Zero output |
| U-12 | `governed-financial-advisor` READY 1/1, AVAILABLE 1 | P0 blocker D-02 | B | Complete Phase 4b Cloud Build trigger | `kubectl get deployment` → READY 1/1 |
| U-13 | `CAGE_ROUTING_SEAL_SECRET` in `advisor-secrets` (≥64 chars) | P0 blocker D-04 | B | Complete Phase 4a Terraform apply | Secret length ≥64 confirmed |
| U-14 | `GOVERNANCE_SALT` in `advisor-secrets` (≥64 chars) | P0 blocker D-04 | B | Same Terraform apply as U-13 | Secret length ≥64 confirmed |
| U-15 | Unsigned gateway request returns 403 | P0 blocker D-04 | C | Complete Phase 5 seal enforcement verification | `curl` unsigned → HTTP 403 |
| U-16 | Valid signed gateway request returns 200 | P0 blocker D-04 | C | Generate valid seal token; send signed request | `curl` signed → HTTP 200 |
| U-17 | `security-scanner-cronjob` exists in `governance-stack` namespace | P1 blocker D-06 | B | `kubectl apply -f deployment/k8s/security-scan-cronjob.yaml` | CronJob exists in namespace |
| U-18 | PSA labels applied: `governance-stack=restricted`, `langfuse=baseline`, `vllm=baseline` | P1 blocker D-07 | B | Apply `deployment/k8s/pod-security-admission.yaml` | Namespace labels confirmed |
| U-19 | `git tag v2.0.0` pushed to origin (annotated, `chore(release)` format) | Final gate | E | Execute only after all other universal gates pass | Tag exists on origin |
| U-20 | GitHub Release published as Latest | Final gate | E | `gh release create v2.0.0 --notes-file CHANGELOG.md --target rc-v2.0.0` | Release visible as Latest |
| U-21 | `terraform.auto.tfvars` confirmed gitignored | Already satisfied | A | Verify `git status` shows it as untracked | Untracked in `git status` |
| U-22 | License headers on all new `.py` files in `src/` | Addressed by plan | A | Implement files with Apache 2.0 headers per §4.1–4.3 | CI `license-check` job green |

### 10.1 Gate Dependency Chain

```
U-07, U-11 (D-01 secrets)           ─┐
U-12 (D-02 pod availability)         ├─► Track B complete
U-13, U-14, U-15, U-16 (D-04 seal)  │
U-17 (D-06 security scanner)         │
U-18 (D-07 PSA labels)              ─┘
                                      │
U-22 (license headers)              ─┐ │
U-08 (tests pass)                    ├─► Track A complete
U-09 (STPA freshness)               ─┘ │
                                      │
                                      ▼
U-15, U-16 (seal verification)      ──► Track C complete
                                      │
                                      ▼
U-01–U-04 (Lula re-validation)      ─┐
U-05, U-06 (SBOM + Trivy)           ├─► Track D complete
U-10 (Langfuse posture)             ─┘
                                      │
                                      ▼
U-19, U-20 (tag + GitHub Release)   ──► Track E = v2.0.0 STABLE
```

---

## 11. Release Gate Evaluation — Region-Specific

> These gates apply exclusively to their named deployment region. They do NOT block the global v2.0.0 stable tag. They block region-specific deployment only. Source: `.clinerules` §5.2–5.4.

### 11.1 US_FED Gates

| # | Gate | Gap? | Action Required | Acceptance Criterion |
|---|------|------|-----------------|----------------------|
| F-01 | All 10 NIST SP 800-53 Lula assertions pass | Yes — US_FED only | Run all 10 NIST Lula validations; activate stub manifests per `compliance/lula/README.md` | All 10 return PASS |
| F-02 | NIST SP 800-53 coverage ≥45% (via `oscal_ssp_exporter.py`) | Yes — currently 24% | Document additional implemented controls in OSCAL SSP; re-run exporter | Coverage ≥45% |
| F-03 | ATO process initiated (OSCAL SSP submitted to AO) | Yes — AO role TBD | Compile ATO package; submit to designated AO | AO acknowledgement received |
| F-04 | POAM items documented for all open findings | Yes | Verify `docs/POAM.md` current; add CTRL_TQP_007 if open findings arise | POAM-011, POAM-012, R-21 documented |

**Note:** The Token Quota Proxy's OPA `tool_approved` rule may affect `lula-validation-ac3.yaml` (access control). Verify F-01 includes re-running `lula-validation-ac3.yaml` after Track A merge.

### 11.2 EU_ECB Gates

| # | Gate | Gap? | Action Required | Acceptance Criterion |
|---|------|------|-----------------|----------------------|
| E-01 | EU AI Act compliance posture verified | Yes — EU_ECB only | Verify no new High-Risk AI behaviour introduced | Posture confirmed unchanged |
| E-02 | GDPR data residency: all paths within `europe-west1` | Addressed by plan | Verify `OSCAL_S3_BUCKET_EU_ECB` points to `europe-west1` bucket | Bucket region confirmed |
| E-03 | DORA Art. 10 audit logging enabled in [`eu-dev.tfvars`](../infra/targets/gcp-gke/eu-dev.tfvars) | Yes — EU_ECB only | Verify `enable_audit_logging = true` | Value confirmed true |
| E-04 | SR 26-2 telemetry suppression active (`"no legal force"` sentinel intact) | Yes — EU_ECB only | Verify sentinel not removed from EU baseline | Sentinel present |

### 11.3 APAC_MAS Gates

| # | Gate | Gap? | Action Required | Acceptance Criterion |
|---|------|------|-----------------|----------------------|
| A-01 | MAS FEAT compliance posture verified | Yes — APAC_MAS only | Verify MAS FEAT posture unaffected by quota enforcement addition | Posture confirmed unchanged |
| A-02 | MAS TRM §4.2 data residency: all paths within `asia-southeast1` | Addressed by plan | Verify `OSCAL_S3_BUCKET_APAC_MAS` points to `asia-southeast1` bucket | Bucket region confirmed |
| A-03 | MAS Notice 655 audit logging enabled in [`apac-dev.tfvars`](../infra/targets/gcp-gke/apac-dev.tfvars) | Yes — APAC_MAS only | Verify `enable_audit_logging = true` | Value confirmed true |
| A-04 | SR 26-2 telemetry suppression active (`"no legal force"` sentinel intact) | Yes — APAC_MAS only | Verify sentinel not removed from APAC baseline | Sentinel present |

### 11.4 Region Gate Entry Criteria

Before executing any region-specific deployment, all universal gates (U-01 through U-22) must be green. Region gates are evaluated in addition to, not instead of, universal gates.

---

## 12. Critical Gaps and P0/P1 Blockers

The following gaps **must be closed** before `git tag -a v2.0.0` is executed. They are ordered by the dependency chain. All are sourced from `plans/release-readiness-gap-analysis.md` §Critical Gaps.

### 12.1 D-01 / U-07 / U-11 — Committed Secrets (P0)

**Description:** Secrets present in working tree and git history:
- `CYBERNETIC_GOVERNANCE_2025` in `deployment/k8s/live_deployment.yaml`
- `REDACTED_REDIS_PASSWORD` sentinel in `tests/test_redis_eviction_envelope.py`
- Langfuse keys, Redis/PostgreSQL passwords, GCS HMAC key, HuggingFace token in commits `200da00`, `72f8f3d`, `6b14314`, `18c5bac`, `bf4e84c`

**Required remediation (three phases):**
1. **Phase 1 — Working tree fix:** Remove all secret values from tracked files; replace with `secretKeyRef` references or environment variable placeholders
2. **Phase 2 — Credential rotation:** Rotate all exposed credentials before history rewrite (history rewrite does not revoke live credentials)
3. **Phase 3 — Git history rewrite:** Suspend branch protection; run `git filter-repo --replace-text secrets.txt`; force-push; re-enable protection

**Verification gates:**
- `git log --all -S "CYBERNETIC_GOVERNANCE_2025" --oneline` → zero output
- Secret detection scan passes (zero secrets in codebase)
- Gates U-07 and U-11 both green

**Rollback:** If history rewrite corrupts the repository, restore from the pre-rewrite backup tag created before `git filter-repo` is run.

**Responsible:** Security owner + release manager
**Entry criterion:** All credentials identified and listed in `secrets.txt` replacement file
**Exit criterion:** U-07 and U-11 both green; all credentials rotated

### 12.2 D-02 / U-12 — `governed-financial-advisor` Pod MinimumReplicasUnavailable (P0)

**Description:** The `governed-financial-advisor` deployment in the `governance-stack` namespace has `MinimumReplicasUnavailable` — the pod is not READY 1/1, AVAILABLE 1.

**Required remediation:**
- Complete Cloud Build trigger for `deployment/k8s/financial-advisor.yaml`
- Verify image pull succeeds (check `imagePullPolicy` and GCR credentials)
- Verify resource requests/limits are within node capacity

**Verification gate:**
```
kubectl get deployment governed-financial-advisor -n governance-stack
```
→ `READY 1/1`, `AVAILABLE 1`

**Responsible:** Infrastructure team
**Entry criterion:** Cloud Build pipeline available; GCR credentials valid
**Exit criterion:** U-12 green; pod READY 1/1 for ≥5 minutes

### 12.3 D-04 / U-13 / U-14 / U-15 / U-16 — HMAC Seal Enforcement Disabled (P0)

**Description:** HMAC seal enforcement is disabled due to broken Terraform wiring. `CAGE_ROUTING_SEAL_SECRET` and `GOVERNANCE_SALT` are not wired through the module chain to the `advisor-secrets` Kubernetes Secret.

**Required remediation (two tracks):**

**Track 1 — Terraform apply:**
1. Update `infra/modules/governed_advisor/variables.tf` to expose `cage_routing_seal_secret` and `governance_salt` variables
2. Wire values through `infra/targets/gcp-gke/main.tf` → module → Kubernetes Secret
3. Run `terraform plan` → review → `terraform apply`
4. Verify secrets in cluster: `kubectl get secret advisor-secrets -n governance-stack -o jsonpath='{.data.CAGE_ROUTING_SEAL_SECRET}' | base64 -d | wc -c` → ≥64

**Track 2 — Gateway enforcement mode:**
1. Confirm `CAGE_SEAL_ENFORCEMENT=enforce` (not `log`) in gateway pod environment
2. Restart gateway pod to pick up new secrets

**Verification gates:**
- U-13: `CAGE_ROUTING_SEAL_SECRET` ≥64 chars in `advisor-secrets`
- U-14: `GOVERNANCE_SALT` ≥64 chars in `advisor-secrets`
- U-15: Unsigned request → 403
- U-16: Valid signed request → 200

**Responsible:** Infrastructure team + gateway team
**Entry criterion:** `terraform.auto.tfvars` contains valid secret values (≥64 chars each); file is gitignored
**Exit criterion:** All four gates U-13, U-14, U-15, U-16 green

### 12.4 D-06 / U-17 — `security-scanner-cronjob` Missing (P1)

**Description:** The `security-scanner-cronjob` CronJob does not exist in the `governance-stack` namespace. This is required by universal gate U-17 (`security-scanner-cronjob` exists in `governance-stack` namespace — `.clinerules` §5.1). The CronJob is also a prerequisite for the US_FED-only Lula assertion `lula-validation-ra5.yaml` (RA-5), but that assertion is not a universal gate.

**Required remediation:**
```
kubectl apply -f deployment/k8s/security-scan-cronjob.yaml
```

**Verification gate:**
```
kubectl get cronjob security-scanner-cronjob -n governance-stack
```
→ CronJob exists

**Responsible:** Infrastructure team
**Entry criterion:** `deployment/k8s/security-scan-cronjob.yaml` manifest exists with correct Trivy image (`aquasec/trivy:0.51.4`)
**Exit criterion:** U-17 green; CronJob exists and schedule is valid

### 12.5 D-07 / U-18 — PSA Labels Not Applied (P1)

**Description:** Pod Security Admission (PSA) labels are not applied to the required namespaces. Required labels:
- `governance-stack`: `pod-security.kubernetes.io/enforce=restricted`
- `langfuse`: `pod-security.kubernetes.io/enforce=baseline`
- `vllm`: `pod-security.kubernetes.io/enforce=baseline`

**Required remediation (two tracks):**

**Track 1 — kubectl apply:**
```
kubectl apply -f deployment/k8s/pod-security-admission.yaml
```

**Track 2 — Terraform apply:**
- Add PSA version labels to namespace resources in `infra/targets/gcp-gke/`
- Run `terraform plan` → review → `terraform apply`

**Verification gate:**
```
kubectl get namespace governance-stack langfuse vllm \
  -L pod-security.kubernetes.io/enforce
```
→ Shows `restricted`, `baseline`, `baseline` respectively

**Responsible:** Infrastructure team
**Entry criterion:** `deployment/k8s/pod-security-admission.yaml` manifest exists
**Exit criterion:** U-18 green; all three namespaces have correct PSA labels

### 12.6 U-01 through U-04 — Lula Assertions Not Yet Re-Validated Post-Merge

**Description:** The Token Quota Proxy PR modifies `src/gateway/governance/` (shared module). Per `.clinerules` §14.8, Lula validation must be re-run after merge against a live cluster.

**Required remediation:**
```
lula validate -f compliance/lula/lula-validation-a52.yaml
lula validate -f compliance/lula/lula-validation-a53.yaml
lula validate -f compliance/lula/lula-validation-a92.yaml
lula validate -f compliance/lula/lula-validation-aarm-vectors.yaml
```

**Verification gate:** All four return PASS

**Responsible:** QA / compliance team
**Entry criterion:** Track A (Token Quota Proxy PR) merged to `main`; live cluster available
**Exit criterion:** All four Lula assertions return PASS; results recorded in CHANGELOG.md

### 12.7 U-05 — SBOM Not Regenerated for New Components

**Description:** The three new Python files introduce new dependencies (e.g., `fakeredis` in tests, `pyyaml` for YAML serialization). SBOM must be regenerated.

**Required remediation:**
```
python scripts/generate_sbom.py
```
Validate output includes new files; no new unresolved CRITICAL CVEs.

**Verification gate:** SBOM generated and validated; Trivy scan passes (no CRITICAL unmitigated)

**Responsible:** QA team
**Entry criterion:** Track A merged; new files present in `src/gateway/governance/`
**Exit criterion:** U-05 and U-06 both green

### 12.8 Commit Message Violations (Gap Analysis Finding)

**Description:** Two commit messages in the original plan exceeded the 72-character limit enforced by the `commit-msg` hook:
- Phase 2c: `feat(governance): add quota and approved-tools rego rules to system-authz` (74 chars) — **FAIL**
- Squash PR title: `feat(governance): add token quota proxy with UCA logging and PII sanitization` (79 chars) — **FAIL**

**Corrected values (used in this plan):**
- Phase 2c commit: `feat(governance): add quota rego rules to system-authz` (53 chars) ✓
- Squash PR title: `feat(governance): add token quota proxy with UCA logging` (56 chars) ✓

**Verification gate:** `commit-msg` hook passes; CI `commit-lint` check green on PR

---

## 13. Implementation Phases — Track A: Token Quota Proxy

**Branch:** `feat/TQP-001-token-quota-proxy`
**Target:** `main`
**Merge strategy:** Squash merge
**Squash PR title:** `feat(governance): add token quota proxy with UCA logging` (56 chars)
**Change category:** Cat-N — 5 business day CAB review required
**Entry criterion:** `git checkout main && git pull origin main` completed; branch created from latest `main`
**Exit criterion:** PR squash-merged to `main`; CI all green; branch deleted from remote

### Phase 1 — New Source Files

#### Phase 1a — PII Sanitizer

**Commit:** `feat(governance): add pii sanitizer with regex redaction pipeline` (63 chars)

**Actions:**
1. Create `src/gateway/governance/pii_sanitizer.py` with Apache 2.0 license header
2. Implement `_PII_PATTERNS` list with all five pattern tuples (see §9)
3. Implement `PIISanitizer` class with `sanitize(text: str) -> str` method
4. Implement module-level `_get_pii_sanitizer()` singleton accessor

**Acceptance criteria:**
- File has Apache 2.0 header (CI `license-check` will enforce)
- All five patterns compile without error
- `sanitize("user@example.com")` → `"[REDACTED_EMAIL]"`
- `sanitize("clean text")` → `"clean text"` (no false positives)

#### Phase 1b — Token Quota Proxy

**Commit:** `feat(governance): add token quota proxy with redis atomic counters` (66 chars)

**Actions:**
1. Create `src/gateway/governance/token_quota_proxy.py` with Apache 2.0 license header
2. Implement `QuotaExceededError` exception class
3. Implement `QuotaCheckResult` dataclass
4. Implement `TokenQuotaProxy` class with Lua script atomicity (see §4.1, §6.2–6.4)
5. Implement `from_env()` classmethod reading `STEP_QUOTA_MAX`, `TOKEN_QUOTA_MAX`, `SESSION_TTL_SECONDS` from environment
6. Implement `_get_token_quota_proxy()` singleton accessor

**Acceptance criteria:**
- File has Apache 2.0 header
- Lua scripts load via `SCRIPT LOAD` at init time
- `check_and_increment` is atomic (single `EVALSHA` call)
- Fail-CLOSED: Redis connection error raises `QuotaExceededError`
- `rollback_step` decrements both counters atomically

#### Phase 1c — UCA Logger

**Commit:** `feat(governance): add uca logger with kms signing and worm persistence` (71 chars)

**Actions:**
1. Create `src/gateway/governance/uca_logger.py` with Apache 2.0 license header
2. Implement `UCALogger` class with all methods (see §4.2, §8)
3. Implement `_get_worm_bucket()` with `CAGE_DEPLOYMENT_REGION` guard (see §4.2)
4. Implement test mode HMAC-SHA256 stub signing
5. Implement `_get_uca_logger()` singleton accessor

**Acceptance criteria:**
- File has Apache 2.0 header
- `_get_worm_bucket()` returns correct bucket for each of the three regions
- UCA record conforms to ISO 42001 Clause 6.1 schema (see §8.1)
- WORM write failure does not suppress the block (block is enforced regardless)

#### Phase 1d — Quota Config

**Commit:** `chore(governance): add token quota threshold config yaml` (57 chars)

**Actions:**
1. Create `config/thresholds/token_quota.yaml` with content from §4.7
2. Verify `config/thresholds/` directory exists; create if not

**Acceptance criteria:**
- YAML parses without error
- `defaults.step_quota_max: 12` and `defaults.token_quota_max: 100000` present
- `model_overrides` for `deepseek-r1` and `deepseek-reasoning` present

### Phase 2 — Integration

#### Phase 2a — Inference Proxy Integration

**Commit:** `feat(governance): integrate token quota proxy into inference pipeline` (70 chars)

**Actions:**
1. Modify [`src/gateway/server/inference_proxy.py`](../src/gateway/server/inference_proxy.py)
2. Update `chat_completions()` signature to accept `background_tasks: BackgroundTasks`
3. Insert quota check as step 2 (see §4.4 for exact code)
4. Wrap steps 3–5 in `try/except` to call `rollback_step()` on downstream failure
5. Import `_get_token_quota_proxy`, `_get_uca_logger` from new modules

**Acceptance criteria:**
- Step 2 executes before NeMo (step 3)
- Quota exceeded → 429 response with correct JSON body
- Downstream failure → `rollback_step()` called; counters decremented
- `stamp_iso_control(A.4, BLOCK)` called on quota exceeded
- `stamp_iso_control(A.4, PASS)` called on quota allowed

#### Phase 2b — Hybrid Server Pre-Warming

**Commit:** `feat(governance): pre-warm quota proxy in hybrid server lifespan` (65 chars)

**Actions:**
1. Modify [`src/gateway/server/hybrid_server.py`](../src/gateway/server/hybrid_server.py)
2. Add pre-warming block in `_gateway_lifespan()` after OPA pre-warm (see §4.5)
3. Pre-warm failure must be non-blocking (logged as WARNING, not raised)

**Acceptance criteria:**
- `app.state.token_quota_proxy` set on startup
- `app.state.uca_logger` set on startup
- Pre-warm failure does not prevent gateway from starting

#### Phase 2c — Rego Rules

**Commit:** `feat(governance): add quota rego rules to system-authz` (53 chars — corrected per gap analysis)

**Actions:**
1. Append Rego rules to [`deployment/system_authz.rego`](../deployment/system_authz.rego) (see §7.1)
2. Add comment block documenting dead-code risk and deferral of OPA runtime injection

**Acceptance criteria:**
- `opa check deployment/system_authz.rego` passes (no syntax errors)
- `quota_within_limits` defaults to `true` when `input.sequence_step_count` is absent
- `tool_approved` defaults to `true` when `input.tool_name` is absent
- `cage_systemic_governance_allow` includes all four conditions

#### Phase 2d — Constants Update

**Commit:** `chore(governance): add ctrl-tqp-007 to governance control registry` (66 chars)

**Actions:**
1. Add `TOKEN_QUOTA_ENFORCEMENT = "CTRL_TQP_007"` to `GovernanceControl` enum in [`constants.py`](../src/gateway/governance/constants.py)
2. Register in `ControlRegistry` with metadata (see §4.8)

**Acceptance criteria:**
- `GovernanceControl.TOKEN_QUOTA_ENFORCEMENT.value == "CTRL_TQP_007"`
- `ControlRegistry` contains entry for `CTRL_TQP_007`

### Phase 3 — Tests

#### Phase 3a — PII Sanitizer Tests

**Commit:** `test(governance): add unit tests for pii sanitizer redaction pipeline` (70 chars)

**Actions:**
1. Create `tests/test_pii_sanitizer.py`
2. Test all five pattern types (see §9.3 acceptance criteria table)
3. Test false-positive resistance (clean text passes through unchanged)
4. Mark all tests with `@pytest.mark.local`

**Acceptance criteria:**
- `uv run pytest tests/test_pii_sanitizer.py -m local -v` → 0 failures
- All seven acceptance criteria from §9.3 covered

#### Phase 3b — Token Quota Proxy Tests

**Commit:** `test(governance): add unit tests for token quota proxy circuit breaker` (71 chars)

**Actions:**
1. Create `tests/test_token_quota_proxy.py`
2. Use `fakeredis` for Redis mocking
3. Test: step count enforcement (step 13 blocked)
4. Test: token count enforcement (accumulated > quota_max blocked)
5. Test: rollback decrements counters
6. Test: reconcile adjusts token counter
7. Test: fail-CLOSED (Redis unavailable → blocked)
8. Test: session TTL set correctly
9. Mark all tests with `@pytest.mark.local`

**Acceptance criteria:**
- `uv run pytest tests/test_token_quota_proxy.py -m local -v` → 0 failures
- Lua script atomicity verified via `fakeredis`

#### Phase 3c — UCA Logger Tests

**Commit:** `test(governance): add unit tests for uca logger compliance records` (67 chars)

**Actions:**
1. Create `tests/test_uca_logger.py`
2. Test: UCA record schema conforms to ISO 42001 Clause 6.1 (see §8.1)
3. Test: HMAC-SHA256 stub signing in test mode
4. Test: `_get_worm_bucket()` returns correct bucket for each region
5. Test: WORM write failure does not suppress block
6. Test: PII sanitization applied before record construction
7. Mark all tests with `@pytest.mark.local`

**Acceptance criteria:**
- `uv run pytest tests/test_uca_logger.py -m local -v` → 0 failures
- All three region bucket mappings verified

### Phase 4 — Compliance Artifacts

#### Phase 4a — CHANGELOG Update

**Commit:** `docs(compliance): update changelog for token quota proxy cat-n change` (70 chars)

**Actions:**
1. Add entry to `CHANGELOG.md`:

```
## [CR-2026-TQP-001] Token Quota Proxy — Cat-N Change
- **Description:** Add stateful per-session token and step-count quota enforcement
  (ISO 42001 Annex A.4) with UCA logging (Clause 6.1) and PII sanitization (Annex A.6)
- **Reviewed-by:** [CAB reviewer name]
- **Approved date:** [CAB approval date]
- **Implemented date:** [merge date]
- **Lula validation result:** Pending (run after merge against live cluster)
- **Cross-region impact:** US_FED, EU_ECB, APAC_MAS
- **OSCAL component:** CTRL_TQP_007 (follow-on PR within 2 business days)
```

**Acceptance criteria:**
- CHANGELOG entry present with all required fields
- `[CR-2026-TQP-001]` format matches `docs/CHANGE_MANAGEMENT_PROCESS.md` §9.4

#### Phase 4b — Regional Baseline Updates

**Commit:** `chore(governance): add ctrl-tqp-007 to regional compliance baselines` (70 chars)

**Actions:**
1. Add `CTRL_TQP_007` entry to `config/compliance/US_FED_BASELINE.json`
2. Add `CTRL_TQP_007` entry to `config/compliance/EU_ECB_BASELINE.json`
3. Add `CTRL_TQP_007` entry to `config/compliance/APAC_MAS_BASELINE.json`

Each entry must include: `control_id`, `iso_clause`, `description`, `enforcement_tier`, `worm_bucket_env_var`.

**Acceptance criteria:**
- All three baseline JSON files parse without error
- `CTRL_TQP_007` present in all three files

### Phase 5 — PR and CI

**Actions:**
1. Verify `config/stpa_control_structure.yaml` is NOT modified (preserves `stpa-freshness-check` CI pass)
2. Run `uv run pytest tests/ -m local -v` locally → 0 failures
3. Run `python3 scripts/verify_langfuse_posture.py --dry-run` → exits 0
4. Open PR `feat/TQP-001-token-quota-proxy` → `main`
5. Complete all sections of `.github/pull_request_template.md` (see §20.3)
6. Confirm CI passes: `license-check`, `pytest-logic`, `stpa-freshness-check`, `langfuse-posture-check` all green
7. Obtain maintainer review approval
8. Squash merge with title: `feat(governance): add token quota proxy with UCA logging`
9. Delete `feat/TQP-001-token-quota-proxy` branch from remote

**Exit criterion:** PR squash-merged; all CI green; branch deleted; U-08, U-09, U-10, U-22 green

---

## 14. Implementation Phases — Track B: P0/P1 Blocker Remediation

**Branch:** `fix/v2-p0-blockers`
**Target:** `rc-v2.0.0`
**Merge strategy:** Squash merge
**Change category:** Cat-N (D-06, D-07) and Cat-E (D-01, D-02, D-04 — emergency credential/availability fixes)
**Entry criterion:** `git checkout rc-v2.0.0 && git pull origin rc-v2.0.0` completed; branch created from latest `rc-v2.0.0`
**Exit criterion:** All five blockers resolved; U-07, U-11, U-12, U-13, U-14, U-17, U-18 green

> **Note:** Tracks A and B are independent and may proceed in parallel. Track B targets `rc-v2.0.0`, not `main`.

### Phase B1 — Working Tree Secret Removal (D-01, Phase 1)

**Commit:** `fix(infra): remove committed secrets from working tree` (52 chars)

**Actions:**
1. Remove `CYBERNETIC_GOVERNANCE_2025` from `deployment/k8s/live_deployment.yaml`; replace with `secretKeyRef` reference
2. Remove `REDACTED_REDIS_PASSWORD` sentinel from `tests/test_redis_eviction_envelope.py`; replace with `os.environ.get("REDIS_PASSWORD", "")` or mock
3. Audit all other tracked files for credential patterns matching `.clinerules` §9.1
4. Stage and commit only the working tree fixes (no history rewrite yet)

**Acceptance criteria:**
- `git diff HEAD` shows no credential strings
- `git grep -i "CYBERNETIC_GOVERNANCE_2025"` → zero matches in working tree

### Phase B2 — Credential Rotation (D-01, Phase 2)

**Actions (performed out-of-band, not committed):**
1. Rotate Redis password
2. Rotate PostgreSQL password
3. Rotate Langfuse API keys (`pk-lf-*`, `sk-lf-*`)
4. Rotate GCS HMAC key
5. Rotate HuggingFace token (`hf_*`)
6. Update all rotated credentials in `terraform.auto.tfvars` (gitignored)
7. Apply new credentials to cluster via `terraform apply` or `kubectl create secret`

**Acceptance criteria:**
- All five credential types rotated
- New credentials applied to cluster
- Old credentials revoked at source

### Phase B3 — Git History Rewrite (D-01, Phase 3)

**Actions:**
1. Create backup tag: `git tag backup/pre-filter-repo-$(date +%Y%m%d)`
2. Suspend GitHub branch protection on `rc-v2.0.0` and `main`
3. Build `secrets.txt` replacement file listing all credential strings to redact
4. Run: `git filter-repo --replace-text secrets.txt --force`
5. Force-push: `git push origin --force --all && git push origin --force --tags`
6. Re-enable GitHub branch protection
7. Notify all team members to re-clone (local clones are now stale)

**Verification:**
```
git log --all -S "CYBERNETIC_GOVERNANCE_2025" --oneline
```
→ zero output

**Acceptance criteria:**
- U-07 and U-11 both green
- Backup tag exists for recovery

### Phase B4a — Terraform Apply for Seal Secrets (D-04)

**Commit:** `fix(infra): wire cage routing seal secret through terraform module` (65 chars)

**Actions:**
1. Add `cage_routing_seal_secret` and `governance_salt` variables to [`infra/modules/governed_advisor/variables.tf`](../infra/modules/governed_advisor/variables.tf)
2. Wire variables through `infra/targets/gcp-gke/main.tf` → module → Kubernetes Secret resource
3. Set values in `terraform.auto.tfvars` (gitignored; ≥64 chars each)
4. Run `terraform plan` → review output → `terraform apply`
5. Verify secrets in cluster:
   ```
   kubectl get secret advisor-secrets -n governance-stack \
     -o jsonpath='{.data.CAGE_ROUTING_SEAL_SECRET}' | base64 -d | wc -c
   ```
   → ≥64

**Acceptance criteria:**
- U-13 and U-14 both green
- No secret values in committed `.tf` files

### Phase B4b — Cloud Build for Financial Advisor Pod (D-02)

**Commit:** `fix(infra): trigger cloud build for governed financial advisor image` (67 chars)

**Actions:**
1. Trigger Cloud Build: `gcloud builds submit --config deployment/docker/cloudbuild.advisor.yaml`
2. Verify image pushed to GCR
3. Apply updated deployment: `kubectl apply -f deployment/k8s/financial-advisor.yaml`
4. Wait for rollout: `kubectl rollout status deployment/governed-financial-advisor -n governance-stack`

**Acceptance criteria:**
- U-12 green: `kubectl get deployment governed-financial-advisor -n governance-stack` → READY 1/1, AVAILABLE 1
- Pod READY for ≥5 minutes without restart

### Phase B4c — PSA Labels (D-07)

**Commit:** `fix(infra): apply pod security admission labels to namespaces` (61 chars)

**Actions:**
1. Apply manifest: `kubectl apply -f deployment/k8s/pod-security-admission.yaml`
2. Add PSA version labels to namespace Terraform resources in `infra/targets/gcp-gke/`
3. Run `terraform plan` → review → `terraform apply`
4. Verify:
   ```
   kubectl get namespace governance-stack langfuse vllm \
     -L pod-security.kubernetes.io/enforce
   ```

**Acceptance criteria:**
- U-18 green: `governance-stack=restricted`, `langfuse=baseline`, `vllm=baseline`

### Phase B4d — Security Scanner CronJob (D-06)

**Commit:** `fix(infra): apply security scanner cronjob to governance-stack` (62 chars)

**Actions:**
1. Verify `deployment/k8s/security-scan-cronjob.yaml` exists with Trivy image `aquasec/trivy:0.51.4`
2. Apply: `kubectl apply -f deployment/k8s/security-scan-cronjob.yaml`
3. Verify: `kubectl get cronjob security-scanner-cronjob -n governance-stack`

**Acceptance criteria:**
- U-17 green: CronJob exists in `governance-stack` namespace

### Phase B5 — PR and Merge

**Actions:**
1. Open PR `fix/v2-p0-blockers` → `rc-v2.0.0`
2. Complete all sections of `.github/pull_request_template.md`
3. Confirm CI passes on PR
4. Obtain maintainer review approval
5. Squash merge with title: `fix(infra): resolve p0 p1 blockers for v2.0.0 stable release` (61 chars)
6. Delete `fix/v2-p0-blockers` branch from remote

**Exit criterion:** All five blockers resolved; U-07, U-11, U-12, U-13, U-14, U-17, U-18 green

---

## 15. Implementation Phases — Track C: Seal Enforcement Verification

**Depends on:** Track B phases B4a and B4b complete (secrets wired, pod available)
**Responsible:** Gateway team + infrastructure team
**Entry criterion:** U-13 and U-14 green (secrets in `advisor-secrets`); gateway pod restarted with new secrets
**Exit criterion:** U-15 and U-16 both green

### Phase C1 — Confirm Enforcement Mode

**Actions:**
1. Verify `CAGE_SEAL_ENFORCEMENT=enforce` (not `log`) in gateway pod environment:
   ```
   kubectl get deployment gateway -n governance-stack \
     -o jsonpath='{.spec.template.spec.containers[0].env}' | jq '.[] | select(.name=="CAGE_SEAL_ENFORCEMENT")'
   ```
2. If set to `log`, update the deployment manifest and apply

**Acceptance criterion:** `CAGE_SEAL_ENFORCEMENT=enforce` confirmed in gateway pod

### Phase C2 — Unsigned Request Test (U-15)

**Actions:**
1. Send unsigned request to gateway:
   ```
   curl -s -o /dev/null -w "%{http_code}" \
     -X POST https://{gateway-host}/v1/chat/completions \
     -H "Content-Type: application/json" \
     -d '{"model":"test","messages":[]}'
   ```
2. Confirm response is HTTP 403

**Acceptance criterion:** U-15 green — unsigned request returns 403

### Phase C3 — Signed Request Test (U-16)

**Actions:**
1. Generate valid HMAC-SHA256 seal token using `CAGE_ROUTING_SEAL_SECRET`
2. Send signed request:
   ```
   curl -s -o /dev/null -w "%{http_code}" \
     -X POST https://{gateway-host}/v1/chat/completions \
     -H "Content-Type: application/json" \
     -H "X-Governance-Seal: {seal_token}" \
     -d '{"model":"test","messages":[]}'
   ```
3. Confirm response is HTTP 200

**Acceptance criterion:** U-16 green — valid signed request returns 200

### Phase C4 — Remote Verification Script

**Actions:**
1. Run `python3 scripts/verify_remote.py` → all checks pass
2. Run `python3 scripts/verify_langfuse_posture.py` → Langfuse connectivity confirmed

**Acceptance criterion:** Both scripts exit 0

---

## 16. Implementation Phases — Track D: Compliance Validation

**Depends on:** Track A (Token Quota Proxy merged to `main`) + Track B (P0/P1 blockers resolved) + Track C (seal enforcement verified)
**Responsible:** QA / compliance team
**Entry criterion:** Tracks A, B, C all complete; live cluster available
**Exit criterion:** All universal gates U-01 through U-22 green

### Phase D1 — Lula Re-Validation (U-01 through U-04)

**Actions:**
```
lula validate -f compliance/lula/lula-validation-a52.yaml
lula validate -f compliance/lula/lula-validation-a53.yaml
lula validate -f compliance/lula/lula-validation-a92.yaml
lula validate -f compliance/lula/lula-validation-aarm-vectors.yaml
```

**Acceptance criteria:**
- All four return PASS
- Results recorded in CHANGELOG.md `[CR-2026-TQP-001]` entry (update "Lula validation result" field)

**Rollback:** If any assertion fails, identify the failing metric endpoint, diagnose the compliance gap, and open a targeted fix PR before re-running.

### Phase D2 — SBOM Generation and Trivy Scan (U-05, U-06)

**Actions:**
1. Run `python scripts/generate_sbom.py`
2. Validate SBOM output includes new files (`token_quota_proxy.py`, `uca_logger.py`, `pii_sanitizer.py`)
3. Trigger Trivy scan: `kubectl create job --from=cronjob/security-scanner-cronjob trivy-manual-$(date +%s) -n governance-stack`
4. Wait for job completion: `kubectl wait --for=condition=complete job/trivy-manual-* -n governance-stack --timeout=300s`
5. Review scan results: `kubectl logs job/trivy-manual-* -n governance-stack`

**Acceptance criteria:**
- SBOM generated without error
- Trivy scan: no CRITICAL unmitigated CVEs
- U-05 and U-06 both green

### Phase D3 — Full Test Suite (U-08)

**Actions:**
```
uv run pytest tests/ --run-integration -v --timeout=120
```

**Acceptance criteria:**
- 0 failures
- U-08 green

### Phase D4 — STPA Freshness Check (U-09)

**Actions:**
```
python scripts/check_stpa_freshness.py --verbose
```

**Acceptance criteria:**
- Script exits 0
- U-09 green
- Confirm `config/stpa_control_structure.yaml` was NOT modified by Track A PR

### Phase D5 — Langfuse Posture Verification (U-10)

**Actions:**
```
python3 scripts/verify_langfuse_posture.py
```

**Acceptance criteria:**
- Script exits 0
- U-10 green

### Phase D6 — Terraform State Verification (U-21)

**Actions:**
```
git status
```
Confirm `terraform.auto.tfvars` appears as untracked (not staged, not committed).

**Acceptance criterion:** U-21 green

---

## 17. Implementation Phases — Track E: Tagging and Release

**Depends on:** All prior tracks (A, B, C, D) complete; all universal gates U-01 through U-22 green; `main` synced into `rc-v2.0.0` via Phase E2 merge (critical — see git topology note below)

> **Git topology note:** Track A merges the Token Quota Proxy into `main`. Track B merges P0/P1 fixes into `rc-v2.0.0`. These are divergent branches. Without Phase E2 explicitly merging `main` into `rc-v2.0.0`, the `v2.0.0` tag will be applied to a commit that contains only the infrastructure fixes — the Token Quota Proxy, UCA Logger, and PII Sanitizer will be absent from the release package. Phase E2 is therefore a mandatory prerequisite for Phase E3 (tagging).
**Responsible:** Release manager
**Entry criterion:** All 22 universal gates green; release manager sign-off obtained
**Exit criterion:** `v2.0.0` annotated tag pushed to origin; GitHub Release published as Latest

### Phase E1 — Final Gate Verification

**Actions:**
1. Run through the complete universal gate checklist (§10) — confirm every gate is green
2. Confirm `git log --all -S "CYBERNETIC_GOVERNANCE_2025" --oneline` → zero output
3. Confirm `terraform.auto.tfvars` is gitignored

**Acceptance criterion:** All 22 universal gates confirmed green

### Phase E2 — Sync `main` into `rc-v2.0.0` Before Tagging

> **Critical git topology fix:** Track A merges the Token Quota Proxy into `main`. Track B merges P0/P1 fixes into `rc-v2.0.0`. Without an explicit merge of `main` into `rc-v2.0.0` before tagging, the stable `v2.0.0` tag will be applied to a commit that contains only the infrastructure fixes — the Token Quota Proxy, UCA Logger, and PII Sanitizer will be entirely absent from the release package.

**Actions:**
```
git checkout rc-v2.0.0
git pull origin rc-v2.0.0
git merge origin/main --no-ff \
  -m "chore(release): sync main feature additions into rc-v2.0.0"
git push origin rc-v2.0.0
```

**Acceptance criteria:**
- `git log rc-v2.0.0 --oneline | grep "token quota proxy"` → commit present
- `git log rc-v2.0.0 --oneline | grep "p0 p1 blockers"` → commit present
- Both Track A and Track B commits visible in `rc-v2.0.0` history

**Dependency:** Track A (Token Quota Proxy PR) must be merged to `main` before this step. Track B (`fix/v2-p0-blockers`) must be merged to `rc-v2.0.0` before this step.

### Phase E3 — Create Annotated Tag (U-19)

**Actions:**
```
git tag -a v2.0.0 -m "chore(release): stable v2.0.0

Promotion from v2.0.0-rc.2 after closure of D-01, D-02, D-04, D-06, D-07.
All P0 blockers resolved. HMAC seal enforcement active.
Token Quota Proxy merged. Full test suite: 0 failed.
All four universal Lula assertions: PASS.
Trivy scan: no CRITICAL unmitigated CVEs."
```

**Acceptance criteria:**
- Tag is annotated (not lightweight)
- Tag message follows Conventional Commits with `chore(release)` type per `.clinerules` §4.4

### Phase E4 — Push Tag

**Actions:**
```
git push origin v2.0.0
```

**Acceptance criterion:** Tag visible on remote: `git ls-remote --tags origin v2.0.0`

### Phase E5 — Create GitHub Release (U-20)

**Actions:**
```
gh release create v2.0.0 \
  --title "v2.0.0 — Stable Release" \
  --notes-file CHANGELOG.md \
  --target rc-v2.0.0 \
  --verify-tag
```

**Acceptance criteria:**
- GitHub Release published
- Marked as **Latest release**
- U-20 green

### Phase E6 — Post-Release Cleanup

**Actions:**
1. Merge `rc-v2.0.0` into `main` via merge commit (not squash — per `.clinerules` §3.5)
2. Delete `fix/v2-p0-blockers` branch from remote if not already deleted
3. Notify team of stable release
4. Open follow-on PR for OSCAL component update (`CTRL_TQP_007`) within 2 business days

---

## 18. Testing Strategy

### 18.1 Test Pyramid

```
                    ┌─────────────────────────────┐
                    │   Live Cluster Validation    │  ← Lula assertions (post-merge)
                    │   (Track D — manual)         │    Trivy scan, seal verification
                    └─────────────────────────────┘
                  ┌───────────────────────────────────┐
                  │   Integration Tests               │  ← pytest --run-integration
                  │   (CI + Track D)                  │    Redis, WORM, KMS (mocked)
                  └───────────────────────────────────┘
              ┌─────────────────────────────────────────────┐
              │   Unit Tests                                │  ← pytest -m local
              │   (CI — pytest-logic job)                   │    fakeredis, HMAC stub
              └─────────────────────────────────────────────┘
```

### 18.2 Unit Test Suite (CI-gated, `@pytest.mark.local`)

| Test File | Component Under Test | Key Scenarios |
|---|---|---|
| `tests/test_pii_sanitizer.py` | `PIISanitizer` | All 5 pattern types; false-positive resistance; empty string; multi-pattern in single string |
| `tests/test_token_quota_proxy.py` | `TokenQuotaProxy` | Step limit enforcement; token limit enforcement; rollback; reconcile; fail-CLOSED; TTL; concurrent increment atomicity |
| `tests/test_uca_logger.py` | `UCALogger` | Schema conformance; HMAC stub signing; region bucket mapping; WORM failure non-blocking; PII sanitization applied |

**CI job:** `pytest-logic` in `.github/workflows/ci.yml`
**Command:** `uv run pytest tests/ -m local -v`
**Required result:** 0 failures, 0 errors

### 18.3 3-Step Audit Verification Suite

The 3-step audit suite is a compliance-specific test sequence that exercises the three ISO 42001 evidence mechanisms in order:

**Step 1 — Prompt Injection Blocking (Annex A.2/A.6)**
- Send a request containing a known injection pattern to the gateway
- Verify: NeMo blocks the request; UCA record of type `prompt_injection` written to WORM ledger
- Verify: PII sanitizer applied before WORM write

**Step 2 — Infinite-Loop Quota Exhaustion (Annex A.4)**
- Send 13 sequential requests from the same `agent_id`
- Verify: Requests 1–12 return 200; request 13 returns 429
- Verify: UCA record of type `quota_exceeded` written to WORM ledger with `block_reason=step_count`
- Verify: Redis step counter = 12 after rollback

**Step 3 — PII Sanitization (Clause 9)**
- Send a request body containing SSN, email, and credit card number
- Verify: UCA record written to WORM ledger contains `[REDACTED_SSN]`, `[REDACTED_EMAIL]`, `[REDACTED_CC]`
- Verify: Original PII values do not appear in the WORM record

**Execution:** `uv run pytest tests/test_audit_verification_suite.py -v --run-integration`

### 18.4 STPA Freshness Check

**Requirement:** `config/stpa_control_structure.yaml` must NOT be modified by the Track A PR.

**Rationale:** The Token Quota Proxy handles UCA-4 directly via Python enforcement. The STPA model is supplementary evidence. Adding UCA-4 to the STPA model is deferred to a follow-on PR (see §23.1).

**Verification:** `python scripts/check_stpa_freshness.py --verbose` → exits 0

**Risk if violated:** If `stpa_control_structure.yaml` is accidentally modified, regenerate `generated_stpa_validator.py` using `python src/gateway/governance/stpa_compiler.py` before committing.

### 18.5 Langfuse Posture Check

**CI job:** `langfuse-posture-check` in `.github/workflows/ci.yml`
**Command:** `python3 scripts/verify_langfuse_posture.py --dry-run --posture development`
**Required result:** Script exits 0

**Pre-release:** Run without `--dry-run` against live cluster before tagging.

### 18.6 License Header Check

**CI job:** `license-check` in `.github/workflows/ci.yml`
**Scope:** `find src/ -name '*.py'` — checks for "Apache License" or "Copyright 2026"
**Required result:** All three new source files pass

**Note:** Test files under `tests/` are not scanned by the CI license check. Headers are not required there.

### 18.7 Integration Test Environment Requirements

| Requirement | Value |
|---|---|
| Redis | `fakeredis` for unit tests; real Redis for integration tests |
| KMS | HMAC-SHA256 stub (`CAGE_ENV=test`) for unit tests; real KMS for integration tests |
| WORM storage | In-memory mock for unit tests; real GCS bucket for integration tests |
| OPA | Real OPA binary for Rego syntax check; mocked for unit tests |
| `CAGE_DEPLOYMENT_REGION` | Set to `US_FED` for unit tests; all three regions tested in integration suite |

---

## 19. Compliance Traceability Matrix

This matrix maps every ISO 42001 control addressed by this plan to its implementation artifact, test coverage, and Lula assertion.

| Control | Clause | Implementation Artifact | Test Coverage | Lula Assertion | Gate |
|---|---|---|---|---|---|
| Resource Management — Token Quota | A.4 | `token_quota_proxy.py` (Redis Lua counters) | `test_token_quota_proxy.py` | `lula-validation-a53.yaml` (A.5.3 monitoring) | U-02 |
| UCA Risk Logging | 6.1 | `uca_logger.py` (KMS-signed WORM records) | `test_uca_logger.py` | `lula-validation-a53.yaml` | U-02 |
| PII Leak Mitigation | A.6 / A.9.2 | `pii_sanitizer.py` (pre-ledger regex) | `test_pii_sanitizer.py` | `lula-validation-a92.yaml` | U-03 |
| Prompt Injection Blocking | A.2 / A.5.2 | OPA `tool_approved` rule + NeMo | 3-step audit suite Step 1 | `lula-validation-a52.yaml` | U-01 |
| Cross-Agent Propagation Prevention | AARM-V4 | `token_quota_proxy.py` (step limit) | `test_token_quota_proxy.py` | `lula-validation-aarm-vectors.yaml` | U-04 |
| Data Exfiltration Prevention | AARM-V10 | `pii_sanitizer.py` | `test_pii_sanitizer.py` | `lula-validation-aarm-vectors.yaml` | U-04 |
| Operational Boundaries | A.2 | OPA `tool_approved` rule | `test_system_authz.py` (existing) | `lula-validation-ac3.yaml` (US_FED) | F-01 |
| Data Residency — EU | GDPR Art. 44 | `_get_worm_bucket()` EU_ECB guard | `test_uca_logger.py` (region mapping) | N/A — verified by config | E-02 |
| Data Residency — APAC | MAS TRM §4.2 | `_get_worm_bucket()` APAC_MAS guard | `test_uca_logger.py` (region mapping) | N/A — verified by config | A-02 |
| Secret Hygiene | §9 (.clinerules) | D-01 remediation (history rewrite) | Secret detection scan | N/A | U-07, U-11 |
| Pod Security | PSA | D-07 remediation (namespace labels) | `kubectl get namespace` | N/A — verified by kubectl; `lula-validation-cm6.yaml` is US_FED-only | U-18 |
| Vulnerability Scanning | Universal (Trivy) | D-06 remediation (security-scanner-cronjob) | Trivy scan | N/A — verified by Trivy scan; `lula-validation-ra5.yaml` is US_FED-only | U-17 |
| HMAC Seal Enforcement | A.2 | D-04 remediation (Terraform wiring) | Seal verification (Track C) | N/A — verified by curl test | U-15, U-16 |

### 19.1 OSCAL Component Update Obligation

Per `docs/CHANGE_MANAGEMENT_PROCESS.md` §9.3, the OSCAL component definition for `CTRL_TQP_007` must be committed to `compliance/oscal/` within 2 business days of the Track A PR merge. This is a follow-on PR obligation, not a blocker for the v2.0.0 tag.

The OSCAL component entry must include:
- `control-id: CTRL_TQP_007`
- `iso-clause: A.4`
- `implementation-status: implemented`
- `description: Per-session token and step-count quota enforcement via Redis atomic Lua counters`
- `enforcement-tier: 2`
- `primary-enforcer: Python TokenQuotaProxy`
- `secondary-enforcer: OPA quota_within_limits rule (pending runtime injection)`

---

## 20. Branch and PR Strategy

### 20.1 Branch Summary

| Branch | Source | Target | Merge Strategy | Purpose |
|---|---|---|---|---|
| `feat/TQP-001-token-quota-proxy` | `main` | `main` | Squash | Token Quota Proxy feature (Track A) |
| `fix/v2-p0-blockers` | `rc-v2.0.0` | `rc-v2.0.0` | Squash | P0/P1 blocker remediation (Track B) |
| `main` → `rc-v2.0.0` sync | `main` | `rc-v2.0.0` | `--no-ff` merge commit | **Critical Phase E2:** brings Track A feature commits into the release branch before tagging |
| `rc-v2.0.0` | `main` | `main` | Merge commit | Post-release: merge release boundary back to main (Phase E6) |

> **Topology invariant:** The `v2.0.0` annotated tag must be applied to a commit on `rc-v2.0.0` that is a descendant of both the Track A squash commit on `main` AND the Track B squash commit on `rc-v2.0.0`. Phase E2 establishes this invariant.

### 20.2 Commit Message Registry

All commit messages in this plan have been validated against the 72-character limit and imperative mood requirement per `.clinerules` §1.1–1.6.

| Phase | Commit Message | Length | Valid |
|---|---|---|---|
| 1a | `feat(governance): add pii sanitizer with regex redaction pipeline` | 63 | ✓ |
| 1b | `feat(governance): add token quota proxy with redis atomic counters` | 66 | ✓ |
| 1c | `feat(governance): add uca logger with kms signing and worm persistence` | 71 | ✓ |
| 1d | `chore(governance): add token quota threshold config yaml` | 57 | ✓ |
| 2a | `feat(governance): integrate token quota proxy into inference pipeline` | 70 | ✓ |
| 2b | `feat(governance): pre-warm quota proxy in hybrid server lifespan` | 65 | ✓ |
| 2c | `feat(governance): add quota rego rules to system-authz` | 53 | ✓ (corrected from 74-char original) |
| 2d | `chore(governance): add ctrl-tqp-007 to governance control registry` | 66 | ✓ |
| 3a | `test(governance): add unit tests for pii sanitizer redaction pipeline` | 70 | ✓ |
| 3b | `test(governance): add unit tests for token quota proxy circuit breaker` | 71 | ✓ |
| 3c | `test(governance): add unit tests for uca logger compliance records` | 67 | ✓ |
| 4a | `docs(compliance): update changelog for token quota proxy cat-n change` | 70 | ✓ |
| 4b | `chore(governance): add ctrl-tqp-007 to regional compliance baselines` | 70 | ✓ |
| Squash PR | `feat(governance): add token quota proxy with UCA logging` | 56 | ✓ (corrected from 79-char original) |
| B1 | `fix(infra): remove committed secrets from working tree` | 52 | ✓ |
| B4a | `fix(infra): wire cage routing seal secret through terraform module` | 65 | ✓ |
| B4b | `fix(infra): trigger cloud build for governed financial advisor image` | 67 | ✓ |
| B4c | `fix(infra): apply pod security admission labels to namespaces` | 61 | ✓ |
| B4d | `fix(infra): apply security scanner cronjob to governance-stack` | 62 | ✓ |
| B squash | `fix(infra): resolve p0 p1 blockers for v2.0.0 stable release` | 61 | ✓ |

### 20.3 PR Template Checklist (Track A)

The following sections of `.github/pull_request_template.md` must be completed for the Track A PR:

**Summary:** One paragraph describing the Token Quota Proxy feature, its ISO 42001 Annex A.4 evidence role, and the three new components added.

**Type of Change:** `feat` (new feature), compliance/governance, tests checked.

**Related Issues / ADRs:** `Closes #TQP-001`, `[CR-2026-TQP-001]`

**Changes Made:**
- `src/gateway/governance/pii_sanitizer.py` — new PII sanitization pipeline (Annex A.6)
- `src/gateway/governance/token_quota_proxy.py` — new stateful circuit breaker (Annex A.4)
- `src/gateway/governance/uca_logger.py` — new UCA compliance record logger (Clause 6.1)
- `config/thresholds/token_quota.yaml` — new quota configuration
- `src/gateway/server/inference_proxy.py` — quota check inserted as step 2
- `src/gateway/server/hybrid_server.py` — pre-warming in lifespan hook
- `deployment/system_authz.rego` — quota and tool-approval Rego rules
- `src/gateway/governance/constants.py` — `CTRL_TQP_007` enum entry

**Testing:** Unit tests (3 new files), 3-step audit suite, full CI, Langfuse posture.

**Compliance and Security Checklist:**
- No secrets or credentials in committed files ✓
- Network policy unchanged ✓
- OPA policy changes reviewed for correctness ✓
- Data residency: new WORM paths gated on `CAGE_DEPLOYMENT_REGION` ✓
- ISO 42001 / CSA AARM: Lula re-run required post-merge (deferred) ✓
- No region-specific behaviour without `CAGE_DEPLOYMENT_REGION` guard ✓

**Cross-Region Impact:**
- US_FED: `CTRL_TQP_007` added to `US_FED_BASELINE.json`; WORM bucket uses `OSCAL_S3_BUCKET_US_FED`
- EU_ECB: `CTRL_TQP_007` added to `EU_ECB_BASELINE.json`; WORM bucket uses `OSCAL_S3_BUCKET_EU_ECB` (europe-west1)
- APAC_MAS: `CTRL_TQP_007` added to `APAC_MAS_BASELINE.json`; WORM bucket uses `OSCAL_S3_BUCKET_APAC_MAS` (asia-southeast1)

**Deployment Notes:**
- New environment variables (all have safe defaults):
  - `STEP_QUOTA_MAX` (default: 12)
  - `TOKEN_QUOTA_MAX` (default: 100000)
  - `SESSION_TTL_SECONDS` (default: 3600)
  - `OSCAL_S3_BUCKET_US_FED`, `OSCAL_S3_BUCKET_EU_ECB`, `OSCAL_S3_BUCKET_APAC_MAS` (fall back to `OSCAL_S3_BUCKET`)

---

## 21. Risk Register and Rollback Procedures

### 21.1 Risk: Redis Unavailability During Quota Check

**Probability:** Low (Redis is a managed service with HA)
**Impact:** High (all requests blocked — fail-CLOSED)
**Mitigation:** Redis HA configuration; circuit breaker timeout set to 100ms; alert on Redis connection errors
**Rollback:** Set `STEP_QUOTA_MAX=999999` and `TOKEN_QUOTA_MAX=999999` as emergency bypass (requires gateway pod restart); open incident ticket; restore Redis

### 21.2 Risk: KMS Unavailability During UCA Signing

**Probability:** Low
**Impact:** Medium (UCA records not signed; block still enforced)
**Mitigation:** HMAC-SHA256 stub fallback in test mode; production KMS has SLA
**Rollback:** UCA records written with stub signature; KMS signing retried on next event; no action required for block enforcement

### 21.3 Risk: WORM Write Failure

**Probability:** Low
**Impact:** Low (block still enforced; audit trail incomplete)
**Mitigation:** Structured stderr logging on write failure; GCS bucket has retry policy
**Rollback:** Replay failed UCA records from stderr logs using `scripts/replay_failed_scores.py` pattern

### 21.4 Risk: Git History Rewrite Corrupts Repository (D-01 Phase 3)

**Probability:** Low (if procedure followed correctly)
**Impact:** Critical (repository unusable)
**Mitigation:** Create backup tag before running `git filter-repo`; test on a clone first
**Rollback:**
1. Restore from backup tag: `git reset --hard backup/pre-filter-repo-{date}`
2. Force-push backup to remote
3. Re-enable branch protection
4. Investigate and fix `secrets.txt` replacement file before retrying

### 21.5 Risk: PSA Labels Break Existing Pods (D-07)

**Probability:** Medium (if existing pods violate `restricted` policy)
**Impact:** High (pods evicted from `governance-stack` namespace)
**Mitigation:** Run `kubectl --dry-run=server apply -f deployment/k8s/pod-security-admission.yaml` first; audit existing pods for PSA compliance before applying
**Rollback:**
1. Remove PSA labels: `kubectl label namespace governance-stack pod-security.kubernetes.io/enforce-`
2. Investigate non-compliant pods
3. Fix pod specs to comply with `restricted` policy
4. Re-apply PSA labels

### 21.6 Risk: Lula Assertion Fails Post-Merge

**Probability:** Medium (new components may affect metric endpoints)
**Impact:** High (blocks v2.0.0 tag)
**Mitigation:** Run Lula assertions in dry-run mode against staging before production
**Rollback:**
1. Identify failing metric endpoint (e.g., `compliance-bridge /v1/metrics/A.9.2`)
2. Diagnose compliance gap (e.g., PII sanitizer not applied in all code paths)
3. Open targeted fix PR
4. Re-run Lula assertion after fix merged

### 21.7 Risk: Seal Enforcement Breaks Existing Clients (D-04)

**Probability:** Medium (clients not yet sending seal tokens)
**Impact:** High (all unsigned requests return 403)
**Mitigation:** Verify all clients send seal tokens before switching from `log` to `enforce` mode
**Rollback:**
1. Set `CAGE_SEAL_ENFORCEMENT=log` in gateway pod environment
2. Apply: `kubectl set env deployment/gateway CAGE_SEAL_ENFORCEMENT=log -n governance-stack`
3. Investigate unsigned clients; update them to send seal tokens
4. Switch back to `enforce` mode

### 21.8 Risk: Token Quota Proxy Introduces Latency Regression

**Probability:** Low (Lua script is O(1); Redis round-trip is ~1ms)
**Impact:** Medium (SLA breach if latency exceeds threshold)
**Mitigation:** Benchmark `check_and_increment` latency in integration tests; compare against baseline in `scratch/latency_baseline_v2.0.x.json`
**Rollback:** Disable quota check by setting `STEP_QUOTA_MAX=999999` and `TOKEN_QUOTA_MAX=999999`; investigate Redis latency

### 21.9 Rollback Decision Matrix

| Scenario | Rollback Action | Responsible |
|---|---|---|
| Redis unavailable | Emergency bypass env vars; restore Redis | Infrastructure team |
| KMS unavailable | No action (stub fallback active) | — |
| WORM write failure | Replay from stderr logs | QA team |
| History rewrite corruption | Restore from backup tag | Release manager |
| PSA labels break pods | Remove labels; fix pod specs | Infrastructure team |
| Lula assertion fails | Fix PR; re-run assertion | QA / compliance team |
| Seal enforcement breaks clients | Switch to `log` mode; fix clients | Gateway team |
| Latency regression | Emergency bypass env vars; investigate | Gateway team |

---

## 22. Monitoring and Alerting

### 22.1 OTel Span Attributes Added by Token Quota Proxy

Every request processed by the Token Quota Proxy emits the following OTel span attributes via `stamp_iso_control()`:

| Attribute | Value (PASS) | Value (BLOCK) |
|---|---|---|
| `iso42001.control` | `A.4` | `A.4` |
| `iso42001.tier` | `2` | `2` |
| `iso42001.outcome` | `PASS` | `BLOCK` |
| `quota.step_count` | current step count | step count at block |
| `quota.token_count` | current token count | token count at block |
| `quota.block_reason` | — | `step_count` or `token_count` |
| `agent.id` | agent UUID | agent UUID |

### 22.2 Metrics to Monitor

| Metric | Source | Alert Threshold | Alert Action |
|---|---|---|---|
| `quota_exceeded_total` | OTel counter on 429 responses | >10/min per agent | Investigate agent loop; check for infinite-loop pattern |
| `redis_connection_errors_total` | Redis client error counter | >0 | Page infrastructure team; Redis HA failover |
| `uca_worm_write_failures_total` | UCA logger error counter | >0 | Alert QA team; replay from stderr logs |
| `quota_step_count_p99` | OTel histogram | >10 (approaching limit) | Review agent session design |
| `gateway_latency_p99` | OTel histogram | >500ms (regression) | Investigate Redis latency; consider bypass |

### 22.3 Langfuse Trace Monitoring

UCA events are correlated with Langfuse traces via the `compliance_event_id` field. The Langfuse evaluation pipeline (`scripts/evaluate_langfuse_traces.py`) should be updated to flag traces where `quota_exceeded` UCA records exist, enabling post-hoc analysis of blocked agent sessions.

### 22.4 WORM Ledger Audit Trail

All UCA records are written to the WORM ledger at `uca-records/{YYYY-MM-DD}/{event_id}.yaml`. The audit trail can be queried via:

```
gsutil ls gs://{OSCAL_S3_BUCKET}/uca-records/$(date +%Y-%m-%d)/
```

For compliance audits, the full record set for a date range can be exported and verified against the KMS signing key.

---

## 23. Non-Critical Gaps — Deferred Items

The following gaps are acceptable to defer past the v2.0.0 stable tag. They are either region-specific (not universal blockers) or explicitly deferred by the implementation plan. All are sourced from `plans/release-readiness-gap-analysis.md` §Non-Critical Gaps.

### 23.1 UCA-4 Not Added to `stpa_control_structure.yaml` (U-09)

**Deferral rationale:** The Token Quota Proxy handles UCA-4 directly via Python enforcement. The STPA model is supplementary evidence. The `stpa-freshness-check` CI job passes as long as `config/stpa_control_structure.yaml` is not modified by the Track A PR.

**Deferral condition:** If `config/stpa_control_structure.yaml` is NOT touched by the PR, the CI job passes.

**Follow-on action:** A follow-on PR can add UCA-4 to the STPA model if the compliance team requires it. Regenerate `generated_stpa_validator.py` using `python src/gateway/governance/stpa_compiler.py` after modifying the STPA model.

**Risk:** LOW — the Token Quota Proxy handles UCA-4 directly; the STPA model is supplementary evidence.

### 23.2 NIST SP 800-53 Lula Assertions and Coverage (F-01, F-02 — US_FED Only)

**Deferral rationale:** Currently 24% NIST SP 800-53 coverage at `v2.0.0-dev.1`. Gate F-02 requires ≥45% for US_FED stable release. This blocks US_FED-specific deployment only, not the global stable release.

**Follow-on action:** Document additional implemented controls in OSCAL SSP; activate stub Lula manifests per `compliance/lula/README.md`; re-run `oscal_ssp_exporter.py` to verify ≥45%.

**Risk:** MEDIUM for US_FED deployment — must be resolved before US_FED production promotion.

### 23.3 ATO Process Initiation (F-03 — US_FED Only)

**Deferral rationale:** AO role is currently TBD per `docs/V2_RELEASE_PLAN.md` §8.7. This blocks US_FED-specific deployment only.

**Follow-on action:** Designate AO; compile ATO package from `compliance/pia/`, `compliance/sar/SAR_2026Q1.md`, `docs/POAM.md`; submit to AO.

**Risk:** HIGH for US_FED deployment — ATO is a hard regulatory requirement.

### 23.4 EU AI Act, DORA, SR 26-2 Sentinel (E-01, E-03, E-04 — EU_ECB Only)

**Deferral rationale:** These are EU_ECB-specific gates; not universal blockers.

**Follow-on actions:**
- E-01: Verify no new High-Risk AI behaviour introduced; FRIA attestation not required for quota enforcement
- E-03: Verify `enable_audit_logging = true` in [`eu-dev.tfvars`](../infra/targets/gcp-gke/eu-dev.tfvars)
- E-04: Verify `"no legal force"` sentinel not removed from EU baseline

**Risk:** HIGH for EU_ECB deployment — must be resolved before EU_ECB production promotion.

### 23.5 MAS FEAT, MAS Notice 655, SR 26-2 Sentinel (A-01, A-03, A-04 — APAC_MAS Only)

**Deferral rationale:** These are APAC_MAS-specific gates; not universal blockers.

**Follow-on actions:**
- A-01: Verify MAS FEAT posture unaffected by quota enforcement addition
- A-03: Verify `enable_audit_logging = true` in [`apac-dev.tfvars`](../infra/targets/gcp-gke/apac-dev.tfvars)
- A-04: Verify `"no legal force"` sentinel not removed from APAC baseline

**Risk:** HIGH for APAC_MAS deployment — must be resolved before APAC_MAS production promotion.

### 23.6 OSCAL Component Update for CTRL_TQP_007

**Deferral rationale:** Per `docs/CHANGE_MANAGEMENT_PROCESS.md` §9.3, OSCAL updates for control implementation changes must be committed within 2 business days of PR merge (not required in the same PR).

**Follow-on action:** Open follow-on PR within 2 business days of Track A merge; add `CTRL_TQP_007` component definition to `compliance/oscal/` (see §19.1 for required fields).

**Risk:** LOW — 2-business-day window is a process obligation, not a release blocker.

### 23.7 OPA Runtime Integration for Quota Rego Rules

**Deferral rationale:** The new Rego rules (`quota_within_limits`, `token_quota_within_limits`, `tool_approved`) are dead code unless [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) injects Redis session state into the OPA `input` document. The Python `TokenQuotaProxy` is the primary enforcer; OPA rules provide secondary declarative evidence.

**Follow-on action:** Open follow-on PR to inject `sequence_step_count`, `accumulated_tokens`, and `token_quota_max` from Redis into the OPA `input` document in `governance_middleware.py`. Document `CTRL_TQP_007` as "Python DGE enforcer — OPA rules are secondary evidence layer" in the OSCAL component definition until injection is implemented.

**Risk:** LOW — Python enforcement is complete and correct; OPA rules are supplementary.

---

## 24. Success Metrics and Acceptance Criteria

### 24.1 Track A Success Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| Unit test pass rate | 100% (0 failures) | `uv run pytest tests/ -m local -v` |
| License header compliance | 100% of new `.py` files in `src/` | CI `license-check` job |
| Commit message compliance | 100% (all ≤72 chars, imperative mood) | `commit-msg` hook |
| PII sanitization coverage | 5 pattern types, 0 false positives | `test_pii_sanitizer.py` |
| Quota enforcement accuracy | Step 13 blocked; steps 1–12 allowed | `test_token_quota_proxy.py` |
| UCA record schema compliance | 100% conformance to ISO 42001 Clause 6.1 | `test_uca_logger.py` |
| Region bucket mapping | Correct bucket for all 3 regions | `test_uca_logger.py` |
| STPA freshness | CI job green | `stpa-freshness-check` CI job |
| Langfuse posture | Script exits 0 | `langfuse-posture-check` CI job |

### 24.2 Track B Success Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| Committed secrets | Zero matches | `git log --all -S "CYBERNETIC_GOVERNANCE_2025"` |
| Credential rotation | All 5 types rotated | Out-of-band verification |
| Pod availability | READY 1/1, AVAILABLE 1 | `kubectl get deployment governed-financial-advisor` |
| Seal secret length | ≥64 chars each | `kubectl get secret ... \| base64 -d \| wc -c` |
| PSA labels | Correct on all 3 namespaces | `kubectl get namespace -L pod-security.kubernetes.io/enforce` |
| Security scanner | CronJob exists | `kubectl get cronjob security-scanner-cronjob` |

### 24.3 Track C Success Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| Unsigned request | HTTP 403 | `curl` test |
| Signed request | HTTP 200 | `curl` test with seal token |
| Remote verification | All checks pass | `python3 scripts/verify_remote.py` |
| Langfuse connectivity | Confirmed | `python3 scripts/verify_langfuse_posture.py` |

### 24.4 Track D Success Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| Lula A.5.2 assertion | PASS | `lula validate -f compliance/lula/lula-validation-a52.yaml` |
| Lula A.5.3 assertion | PASS | `lula validate -f compliance/lula/lula-validation-a53.yaml` |
| Lula A.9.2 assertion | PASS | `lula validate -f compliance/lula/lula-validation-a92.yaml` |
| Lula AARM assertion | PASS | `lula validate -f compliance/lula/lula-validation-aarm-vectors.yaml` |
| SBOM generation | No errors; no new CRITICAL CVEs | `python scripts/generate_sbom.py` + Trivy |
| Full test suite | 0 failures | `uv run pytest tests/ --run-integration -v` |
| STPA freshness | PASS | `python scripts/check_stpa_freshness.py --verbose` |

### 24.5 Track E Success Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| Annotated tag | `v2.0.0` exists on origin | `git ls-remote --tags origin v2.0.0` |
| Tag format | `chore(release)` type, annotated | `git cat-file -p v2.0.0` |
| GitHub Release | Published as Latest | GitHub UI / `gh release view v2.0.0` |
| Post-release merge | `rc-v2.0.0` merged to `main` | `git log --merges main` |

---

## 25. Release Decision Criteria

### 25.1 v2.0.0 Stable Tag — Go/No-Go Criteria

The v2.0.0 stable tag **MAY be applied** when ALL of the following conditions are true:

**Track A complete:**
- [ ] Token Quota Proxy PR squash-merged to `main`
- [ ] CI all green: `license-check`, `pytest-logic`, `stpa-freshness-check`, `langfuse-posture-check`
- [ ] `feat/TQP-001-token-quota-proxy` branch deleted from remote

**Track B complete:**
- [ ] `git log --all -S "CYBERNETIC_GOVERNANCE_2025" --oneline` → zero output (U-07, U-11)
- [ ] All five credential types rotated
- [ ] `governed-financial-advisor` READY 1/1, AVAILABLE 1 (U-12)
- [ ] `CAGE_ROUTING_SEAL_SECRET` ≥64 chars in `advisor-secrets` (U-13)
- [ ] `GOVERNANCE_SALT` ≥64 chars in `advisor-secrets` (U-14)
- [ ] `security-scanner-cronjob` exists in `governance-stack` (U-17)
- [ ] PSA labels applied to all three namespaces (U-18)
- [ ] `fix/v2-p0-blockers` branch deleted from remote

**Track C complete:**
- [ ] Unsigned request → 403 (U-15)
- [ ] Valid signed request → 200 (U-16)

**Track D complete:**
- [ ] All four universal Lula assertions return PASS (U-01 through U-04)
- [ ] SBOM generated; Trivy scan passes (U-05, U-06)
- [ ] Full test suite: 0 failures (U-08)
- [ ] STPA freshness check passes (U-09)
- [ ] Langfuse posture verified (U-10)
- [ ] `terraform.auto.tfvars` confirmed gitignored (U-21)

**Release manager sign-off:**
- [ ] Release manager has reviewed all gate results
- [ ] CHANGELOG.md `[CR-2026-TQP-001]` entry updated with actual Lula validation results
- [ ] No open P0 or P1 issues in the issue tracker

### 25.2 Token Quota Proxy PR — Independent Merge Criteria

The Token Quota Proxy PR (`feat/TQP-001-token-quota-proxy`) **MAY be merged to `main` independently** of the P0 blockers when:

- [ ] All Track A phases (1a through 5) complete
- [ ] CI all green on the PR
- [ ] At least one maintainer review approval obtained
- [ ] No blocking review comments outstanding
- [ ] Squash PR title ≤72 chars: `feat(governance): add token quota proxy with UCA logging`

### 25.3 Region-Specific Deployment — Additional Criteria

Before promoting to any region-specific production environment, all universal gates (U-01 through U-22) must be green PLUS the applicable region gates (F-01 through F-04 for US_FED; E-01 through E-04 for EU_ECB; A-01 through A-04 for APAC_MAS).

### 25.4 Final Release Decision Statement

**Recommendation: CONDITIONALLY READY**

The Token Quota Proxy implementation plan is a high-quality, compliance-aware plan that correctly addresses ISO 42001 Annex A.4, Clause 6.1, Annex A.6, and Annex A.2. The plan may be executed immediately on Track A (Token Quota Proxy PR) and Track B (P0/P1 blocker remediation) in parallel.

The v2.0.0 stable tag cannot be applied until all five pre-existing P0/P1 blockers (D-01, D-02, D-04, D-06, D-07) are resolved via Track B, and all four universal Lula assertions pass via Track D.

This document is the single authoritative roadmap. No other document defines the scope of work required for the v2.0.0 stable tag.

---

*Document version 4.0.0 — Written from scratch integrating `plans/token-quota-proxy-impl-plan.md` (original) and `plans/release-readiness-gap-analysis.md` v1.0.0 (2026-06-08). All gap analysis findings, deficiencies, and recommendations are addressed in the sections above.*
