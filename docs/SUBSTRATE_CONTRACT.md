# CAGE Substrate Contract

**Version:** 1.0
**Status:** Active — Phase A implementation
**Last updated:** 2026-08-28
**Cross-reference:** [`docs/CAGE_OPEN_INTEROP_SPEC.md §1`](CAGE_OPEN_INTEROP_SPEC.md) (Platform Overview)

---

## Overview

The CAGE Substrate Contract is the versioned, documented API surface that external
policy authors (writing in ACS, AAIF, OSCAL, Lula, or native CAGE YAML) can target
when integrating with the CAGE governance substrate.

The contract defines:

1. **Policy ingestion surface** — how external specs enter the substrate
2. **Governance check surface** — how enforcement decisions are made
3. **Routing seal contract** — how request integrity is verified
4. **Versioning guarantees** — what stability is promised across versions
5. **Deprecation policy** — how breaking changes are communicated

---

## 1. Policy Ingestion Surface

### 1.1 Endpoint

```
POST /governance/ingest-policy
Content-Type: application/json
```

> **Status: Specification Only.** This endpoint is not yet implemented in the gateway. The internal policy translation module exists at `src/gateway/governance/ingress/policy_translator.py` but no HTTP route has been created.

Accepts any supported policy specification format and returns compiled enforcement
artifacts plus a `policy_version_id` for pinning.

**Request body:**

```json
{
  "spec": { ... }
}
```

The `spec` field accepts any of the following formats (auto-detected):

| Format | Detection signal | Spec reference |
|---|---|---|
| Microsoft ACS | `behaviorDeclarations` key | https://github.com/microsoft/agent-control-specification |
| Linux Foundation AAIF | `governedRunLoop` key | AAIF working group |
| OSCAL 1.1.x | `oscal-version` key | https://pages.nist.gov/OSCAL/ |
| Lula validation manifest | `kind: LulaValidation` | https://lula.dev |
| Native CAGE YAML | (fallback) | `config/stpa_control_structure.yaml` schema |

**Response:**

```json
{
  "policy_version_id": "a1b2c3d4e5f6a7b8",
  "format_detected": "acs",
  "artifacts": {
    "opa_content": "...",
    "nemo_content": "...",
    "python_content": "...",
    "langgraph_content": "..."
  },
  "warnings": [],
  "errors": []
}
```

### 1.2 Policy Version ID

The `policy_version_id` is a 16-character hex prefix of the SHA-256 hash of the
compiled OPA policy content. It is stable across identical inputs and can be used to:

- Pin a specific policy version in `validate_action()` calls
- Detect policy drift in CI/CD pipelines (see [`scripts/check_policy_drift.py`](../scripts/check_policy_drift.py))
- Audit which policy version was active at a given point in time

### 1.3 Get Active Policy Version

```
GET /governance/policy-version
```

Returns the currently active policy version and registry hash:

```json
{
  "policy_version_id": "a1b2c3d4e5f6a7b8",
  "active_region": "US_FED",
  "active_hash": "sha256-hex-of-active-registry"
}
```

The `active_hash` is the SHA-256 hash of the active `ControlRegistry` regional
profile JSON (see [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py)).

---

## 2. Governance Check Surface

### 2.1 Endpoint

```
POST /governance/validate-action
Content-Type: application/json
```

The primary enforcement endpoint. Every agent action must pass through this endpoint
before execution.

**Request body:**

```json
{
  "action": "execute_trade",
  "params": {
    "amount": 50000,
    "symbol": "AAPL",
    "trader_role": "junior"
  },
  "policy_version_id": "a1b2c3d4e5f6a7b8"
}
```

The `policy_version_id` field is optional. If provided, the governance engine
validates that the active policy version matches before evaluating. If the version
has changed, the request is rejected with HTTP 409 Conflict.

**Response:**

```json
{
  "verdict": "ALLOW | DENY | REQUIRE_APPROVAL | DEFER",
  "violations": [],
  "audit_id": "uuid",
  "policy_version_id": "a1b2c3d4e5f6a7b8",
  "routing_seal": "hmac-sha256-hex"
}
```

### 2.2 Verdict Semantics

Canonical four-state vocabulary — see [`src/gateway/governance/decisions.py`](../src/gateway/governance/decisions.py):

| Verdict | Meaning | HTTP status |
|---|---|---|
| `ALLOW` | All governance tiers passed; action may proceed; routing seal issued | 200 |
| `DENY` | One or more governance tiers rejected the action; no seal issued | 403 |
| `REQUIRE_APPROVAL` | Action is understood but requires explicit human sign-off before execution; routes to HITL approval queue | 202 |
| `DEFER` | Action cannot be evaluated — trusted context or evidence is missing; routes to DeferQueue for automated data-hydration (not human triage) | 202 |

### 2.3 Governance Pipeline Tiers

Before `validate_action()` is invoked, requests are screened by pre-pipeline layers (Aho-Corasick / prompt-injection detection and NeMo Guardrails, including Presidio PII masking). `validate_action()` itself then runs the 8-tier, two-phase governance pipeline (`run_pipeline()` in [`src/gateway/governance/governor/pipeline.py`](../src/gateway/governance/governor/pipeline.py), matching `TIER_LABELS` in [`proof/model.py`](../proof/model.py)), where Phase 1 read-only stages execute sequentially first and Phase 2 mutating stages are gated by `phase2_mode()`: a `HARD` Phase 1 finding skips Phase 2, any other Phase 1 finding (or `Profile.DRY_RUN`) previews it side-effect-free and reports `barrier_preview`, and only a clean Phase 1 under `FULL` / `POST_HITL` commits:

| Tier | Phase | Name | Implementation |
|---|---|---|---|
| *(pre-pipeline)* | Layer 0 | Aho-Corasick / Prompt Injection Detection | [`src/gateway/governance/prompt_injection_detector.py`](../src/gateway/governance/prompt_injection_detector.py), [`src/gateway/governance/text_filter.py`](../src/gateway/governance/text_filter.py) |
| *(pre-pipeline)* | Layer 0 | NeMo Guardrails (incl. Presidio PII masking) | [`src/integrations/nemo/manager.py`](../src/integrations/nemo/manager.py) |
| **Tier 0.5** | Phase 1 (Read-Only) | **FTRA — Forward-Looking Trajectory Reachability Analyzer** (whole-graph pre-execution node + per-request `FtraStage` boundary check) | [`src/gateway/governance/governor/stages/ftra.py`](../src/gateway/governance/governor/stages/ftra.py), [`src/gateway/governance/ftra/node_factory.py`](../src/gateway/governance/ftra/node_factory.py), [`src/gateway/governance/ftra/graph_analyzer.py`](../src/gateway/governance/ftra/graph_analyzer.py), [`src/gateway/governance/ftra/classifier.py`](../src/gateway/governance/ftra/classifier.py) |
| **Tier 1** | Phase 1 (Read-Only) | STPA/STAMP UCA validation | [`src/gateway/governance/governor/stages/stpa.py`](../src/gateway/governance/governor/stages/stpa.py), [`src/gateway/governance/stpa_validator.py`](../src/gateway/governance/stpa_validator.py) |
| **Tier 3b** | Phase 1 (Read-Only) | OPA policy evaluation | [`src/gateway/governance/governor/stages/opa.py`](../src/gateway/governance/governor/stages/opa.py), OPA `deployment/system_authz.rego` |
| **Tier 2** | Phase 1 (Read-Only) | Agent confidence | [`src/gateway/governance/governor/stages/confidence.py`](../src/gateway/governance/governor/stages/confidence.py) |
| **Tier 5** | Phase 1 (Read-Only) | Multi-Agent Consensus (10 s per-critic timeout) | [`src/gateway/governance/consensus/engine.py`](../src/gateway/governance/consensus/engine.py) |
| **Tier 6** | Phase 1 (Read-Only) | DoWhy Causal Gatekeeper | [`src/gateway/governance/causal/gatekeeper.py`](../src/gateway/governance/causal/gatekeeper.py) |
| **Tier 3a** | Phase 2 (Mutating) | Control Barrier Function (Lua atomic check+commit) | [`src/gateway/governance/safety/cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) |
| **Tier 4** | Phase 2 (Mutating) | Fiscal Limit Pre-Reservation | [`src/cage_finance/safety/fiscal_limit_guard.py`](../src/cage_finance/safety/fiscal_limit_guard.py), [`src/cage_finance/tiers/fiscal_tier.py`](../src/cage_finance/tiers/fiscal_tier.py) |

> PII sanitization (`src/gateway/governance/pii_sanitizer.py`) and confabulation scoring (`src/gateway/governance/confabulation_scorer.py`) are standalone modules invoked outside `run_pipeline()` — PII sanitization runs on audit records inside `src/gateway/governance/uca_logger.py`, and confabulation scoring is a Langfuse observability metric.

> **Tier 0.5 — FTRA formal-model coverage:** FTRA (`ftra`, Tier 0.5) is included in the 8-tier `TIERS` state tuple in [`proof/model.py`](../proof/model.py) for `NoDirectBind` BFS reachability verification.

> **Tier 3a / Tier 4 — CBF effective-balance & Phase 2 reservation note:** The CBF ([`src/gateway/governance/safety/cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py)) previews and commits separately. `verify_action()` is a pure, side-effect-free preview (`admits(balance, cost)`); it never debits anything. Intra-window double-spend protection lives in Redis: the commit path (`atomic_verify_and_commit()`, called by `commit_barrier`) nets the running `cbf:debits:total` from the reconciled scalar inside its Lua script and ledgers the admitted debit under its `debit_id` (`cbf:debits` HASH, `cbf:debits:by_time` ZSET); the reconciliation daemon settles those debits with `settle_debits_sync()` only up to the custodian's signed `settled_through` minus a clock-skew margin ([ADR-010](adr/ADR-010-settlement-aware-debit-ledger.md), [`debit_ledger.py`](../src/gateway/governance/safety/debit_ledger.py)). Redis access for Tier 4 is **read-write** (`WATCH/MULTI/EXEC`).

> **Two-Phase Pipeline & Saga Rollback Semantics:** In CAGE v3.0.1, `run_pipeline()` decouples into Phase 1 (read-only validation) and Phase 2 (atomic state mutations via `ReservationScope`). All validation checks run in Phase 1 before balance debits (Tier 3a) or daily limit reservations (Tier 4) occur, eliminating downstream budget leakage. On compensating rollbacks, `FiscalLimitGuard.rollback_state()` and `release()` validate window-key existence to prevent negative counter underflow across TTL boundaries.

> **Tier 5 — Consensus degraded-quorum routing:** The `ERROR + APPROVE` verdict combination is explicitly routed to `ESCALATE` (HITL) before the catch-all case in [`src/gateway/governance/consensus/engine.py`](../src/gateway/governance/consensus/engine.py) (`CONSENSUS_CRITIC_TIMEOUT_S`, default `10.0`s).

> **KMS signing contract — `signed_at` staleness rejection:** `KmsSigner.sign()` embeds `"signed_at": int(time.time())` in every reconciliation payload. `KmsSigner.verify()` raises `ValueError` if `now - signed_at > MAX_KMS_PAYLOAD_AGE_SECONDS` (300 s). Payloads missing `signed_at` are rejected as malformed.

---

## 3. Caller Authentication and Routing Seal Contract

### 3.1 Caller authentication

Callers are authenticated by Linkerd mTLS workload identity, not by a request
header secret (POAM-2026-080). The gateway admits a non-open request only if
the proxy-set `l5d-client-id` header carries an identity listed in
`CAGE_TRUSTED_CLIENT_IDENTITIES`; otherwise it returns HTTP 403.
`CAGE_TRUSTED_CLIENT_IDENTITIES` is required in every environment and the
gateway always enforces workload identity (`WorkloadIdentityMiddleware` and
`extract_client_identity(scope)`).

**Implementation:** [`workload_identity.py`](../src/gateway/server/workload_identity.py)

### 3.2 Governor routing seal

After all tiers pass, the governor issues a KMS-signed routing seal (JWT,
v3 format) bound to the action, its parameters and the evidence record. The
seal stays inside the gateway: the actuator path verifies and consumes it
(single use) before dispatch, e.g. `verify_and_consume_seal()` in
[`tool_provider.py`](../src/cage_finance/tools/tool_provider.py).

**Implementation:** [`routing_seal.py`](../src/gateway/governance/routing_seal.py)

### 3.3 Seal Lifetime

Routing seals carry a **30-second TTL** by default (`GOVERNANCE_SEAL_TTL_S`, per [`routing_seal.py`](../src/gateway/governance/routing_seal.py)). Replayed or expired seals are rejected.

---

## 4. Versioning Guarantees

### 4.1 Stable Surface (no breaking changes without major version bump)

The following are guaranteed stable across minor versions:

- `POST /governance/ingest-policy` request/response schema
- `POST /governance/validate-action` request/response schema
- `policy_version_id` format (16-char hex prefix of SHA-256)
- Caller authentication by Linkerd workload identity (`l5d-client-id`, `CAGE_TRUSTED_CLIENT_IDENTITIES`)
- `GovernanceControl` enum values (`CTRL_*` identifiers)
- UCA YAML schema (`config/stpa_control_structure.yaml`)

### 4.2 Experimental Surface (may change in minor versions)

The following may change without a major version bump:

- AGP Semantic Policy output format (`config/agp/generated_semantic_policy.txt`)
- Webhook payload schema (additive changes only; no field removals without notice)
- Internal tier ordering within the 8-tier pipeline (`Tier 0.5` through `Tier 6`)

### 4.3 Version Pinning

Use `policy_version_id` in `validate_action()` calls to pin a specific compiled
policy version. This ensures that policy changes do not silently affect in-flight
agent workflows.

---

## 5. Deprecation Policy

1. **Deprecated endpoints** are announced in `CHANGELOG.md` with a minimum 90-day
   notice period before removal.
2. **Deprecated fields** in request/response schemas are marked with
   `"deprecated": true` in the JSON Schema and removed after 90 days.
3. **Breaking changes** to the stable surface require a major version bump
   (e.g., `v1.0` → `v2.0`) and a minimum 180-day migration window.
4. **Emergency deprecations** (security-critical) may have shorter notice periods;
   operators are notified via the security advisory channel.

---

## 6. Compliance Obligations for Policy Authors

When submitting policies via `POST /governance/ingest-policy`:

- **ACS/AAIF specs:** No OSCAL update required. Compiled artifacts are subject to
  the same NIST SP 800-53 control obligations as native CAGE YAML.
- **OSCAL specs:** The OSCAL component definition in `compliance/oscal/` must be
  updated within 2 business days of PR merge (Cat-N obligation).
- **Lula specs:** A Lula validation update in `compliance/lula/` must be included
  in the same PR or flagged for a follow-on PR.
- **All formats:** Compiled OPA artifacts are subject to the policy drift gate
  (`scripts/check_policy_drift.py`) in CI.

---

## 7. References

| Document | Role |
|---|---|
| [`docs/CAGE_OPEN_INTEROP_SPEC.md`](CAGE_OPEN_INTEROP_SPEC.md) | Full external API surface contract |
| [`src/gateway/governance/ingress/policy_translator.py`](../src/gateway/governance/ingress/policy_translator.py) | Unified ingress pipeline |
| [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py) | `ControlRegistry` and `GovernanceControl` enum |
| [`src/gateway/governance/governor/governor.py`](../src/gateway/governance/governor/governor.py) | `validate_action()` — the single choke point |
| [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) | Routing seal implementation |
| [`scripts/check_policy_drift.py`](../scripts/check_policy_drift.py) | Policy drift detection gate |
