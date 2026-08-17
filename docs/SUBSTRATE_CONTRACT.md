# CAGE Substrate Contract

**Version:** 1.0
**Status:** Active — Phase A implementation
**Last updated:** 2026-08-05
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

Before `validate_action()` is invoked, requests are screened by pre-pipeline layers (Aho-Corasick / prompt-injection detection and NeMo Guardrails, including Presidio PII masking). `validate_action()` itself then runs the 8-tier governance pipeline (FTRA pre-pipeline boundary gate plus 7 in-pipeline tiers via `SymbolicGovernor._run_checks()`), with Tiers 2 and 4 executing concurrently:

| Stage | Name | Implementation |
|---|---|---|
| *(pre-pipeline)* | Aho-Corasick / Prompt Injection Detection | [`prompt_injection_detector.py`](../src/gateway/governance/prompt_injection_detector.py), [`text_filter.py`](../src/gateway/governance/text_filter.py) |
| *(pre-pipeline)* | NeMo Guardrails (incl. Presidio PII masking) | [`nemo/manager.py`](../src/gateway/governance/nemo/manager.py) |
| **Pre-Pipeline Boundary Gate** | **FTRA — Forward-Looking Trajectory Reachability Analyzer** (operates on the whole execution graph before per-tool-call checks begin; NOT a peer of Tiers 0–6b) | **[`ftra/node_factory.py`](../src/gateway/governance/ftra/node_factory.py), [`ftra/graph_analyzer.py`](../src/gateway/governance/ftra/graph_analyzer.py), [`ftra/classifier.py`](../src/gateway/governance/ftra/classifier.py)** |
| Tier 0 | STPA/STAMP UCA validation | [`generated_stpa_validator.py`](../src/gateway/governance/generated_stpa_validator.py) |
| Tier 1 | Agent confidence pre-check | [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py) |
| Tier 2 / 4 | CBF + OPA (concurrent) | [`cbf.py`](../src/gateway/governance/cbf.py), OPA `system_authz.rego` |
| Tier 3 | Fiscal Limit Pre-Reservation | [`fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py) |
| Tier 5 | Multi-Agent Consensus | [`consensus.py`](../src/gateway/governance/consensus.py) |
| Tier 6 | DoWhy Causal Gatekeeper | [`causal_gatekeeper.py`](../src/gateway/governance/causal_gatekeeper.py) |
| Tier 6b | Adaptive FRIA Enforcement | [`normative_provider.py`](../src/gateway/governance/normative_provider.py) |

> PII sanitization (`pii_sanitizer.py`) and confabulation scoring (`confabulation_scorer.py`) are standalone modules invoked outside `_run_checks()` — PII sanitization runs on audit records inside `uca_logger.py`, and confabulation scoring is a Langfuse observability metric.

> **Pre-Pipeline Boundary Gate — FTRA BFS-exclusion caveat:** FTRA (the Pre-Pipeline Boundary Gate) is **not** included in the 21-state BFS automaton used for NoDirectBind reachability verification. This is a documented under-approximation; the BFS covers the governance state machine only. Gap closure requires integrating FTRA into the state tuple or enforcing it at the controller boundary. TLA+/Alloy full-implementation modelling is future work.

> **Tier 2/4 — CBF effective-balance note:** The CBF (`cbf.py`) now tracks `_local_debits` intra-window. `verify_action()` computes `effective_balance = snapshot_balance - self._local_debits` for all threshold checks; `reset_local_debits()` is called by the reconciliation daemon on each KMS snapshot refresh. Redis access for Tier 4 is **read-write** (`WATCH/MULTI/EXEC`).

> **Tier 3 — Saga-atomicity gap and rollback stub:** The residual distributed-transaction atomicity failure (previously labelled "TOCTOU gap") is correctly a **saga-atomicity gap**: Tier 3a (`atomic_verify_and_commit()`) debits the balance before downstream tiers execute. `FiscalLimitGuard.rollback_state(amount, audit_id)` is the Saga compensation stub — it reverses the Redis debit, logs `[SAGA-ROLLBACK]`, and re-raises on Redis failure.

> **Tier 5 — Consensus degraded-quorum routing:** The `ERROR + APPROVE` verdict combination is now explicitly routed to `ESCALATE` (HITL) before the catch-all case in `consensus.py`.

> **KMS signing contract — `signed_at` staleness rejection:** `KmsSigner.sign()` embeds `"signed_at": int(time.time())` in every reconciliation payload. `KmsSigner.verify()` raises `ValueError` if `now - signed_at > MAX_KMS_PAYLOAD_AGE_SECONDS` (300 s). Payloads missing `signed_at` are rejected as malformed.

---

## 3. Routing Seal Contract

### 3.1 Header

```
X-CAGE-Routing-Seal: <hmac-sha256-hex>
```

The routing seal is an HMAC-SHA256 signature over the canonical request payload,
computed using the deployment's routing seal key (loaded from Kubernetes Secret).

**Purpose:** Proves that the request passed through the CAGE governance pipeline
and was not injected directly into the backend, bypassing governance.

### 3.2 Verification

Backend services **must** verify the routing seal before processing any request.
Requests without a valid seal must be rejected with HTTP 403.

**Implementation:** [`routing_seal.py`](../src/gateway/governance/routing_seal.py)

### 3.3 Seal Lifetime

Routing seals carry a **30-second TTL** (`<expire_ts_hex>.<action_slug>.<hmac_hex>` format, per [`routing_seal.py`](../src/gateway/governance/routing_seal.py)). Replayed or expired seals are rejected by the backend with HTTP 403.

---

## 4. Versioning Guarantees

### 4.1 Stable Surface (no breaking changes without major version bump)

The following are guaranteed stable across minor versions:

- `POST /governance/ingest-policy` request/response schema
- `POST /governance/validate-action` request/response schema
- `policy_version_id` format (16-char hex prefix of SHA-256)
- `X-CAGE-Routing-Seal` header name and HMAC-SHA256 algorithm
- `GovernanceControl` enum values (`CTRL_*` identifiers)
- UCA YAML schema (`config/stpa_control_structure.yaml`)

### 4.2 Experimental Surface (may change in minor versions)

The following may change without a major version bump:

- AGP Semantic Policy output format (`config/agp/generated_semantic_policy.txt`)
- Webhook payload schema (additive changes only; no field removals without notice)
- Internal tier ordering within the 8-tier pipeline (FTRA + 7 in-pipeline tiers)

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
| [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py) | `validate_action()` — the single choke point |
| [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) | Routing seal implementation |
| [`scripts/check_policy_drift.py`](../scripts/check_policy_drift.py) | Policy drift detection gate |
