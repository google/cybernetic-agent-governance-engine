# Verdict Systems (provider_08) Partner Integration Specification & Runbook

**Partner:** Verdict Systems — https://verdict.systems
**Slot:** `provider_08` · **Seam:** `NormativeProvider` (3 endpoints)
**Base URL:** `https://verdict.systems/api/cage` · **Discovery:** `GET /api/cage`
**Tier disclosed by partner:** public sandbox (ephemeral ECDSA P-256 signer, Sigstore Rekor anchoring, no retention); production tenants attach retention policy, custodian identity and a hardware-backed signer.

## Executive Summary

Verdict is an external evidence-custody layer. CAGE governs at the point of
inference; Verdict holds the record of what the gate saw and what was sealed,
outside the kernel that produced it. The integration is deliberately narrow:

- Verdict **never** receives Layer-2 domain payloads beyond what CAGE already
  places in `action_context` (ADR-008 "No Domain Leakage" honoured by pass-through).
- Verdict **never** adjudicates substance. Its gate is structural
  (record-completeness) and labels itself so on every call.
- Verdict **never** blocks silently: every non-`ALLOW` outcome carries a finding
  code from the fail-closed table in `src/integrations/provider_08/README.md`.

## §1 — Composition Safety Invariant

`ALLOW` from Verdict is necessary, not sufficient. CAGE mints the
ConsequenceToken (kernel `consequence_token_service`) bound to Verdict's
`authority_record_id` and `authority_state_version`; the execution adapter
still verifies and consumes the token. A Verdict `ALLOW` with a failed mint is
`admitted=False`.

## §2 — Canonical Wire Contract

### 2.1 `GET /legal-baseline/{region}`
Regions: `US_FED`, `EU_ECB`, `APAC_MAS` (case-insensitive, `-`→`_`).
Profiles are byte-for-byte copies of CAGE `config/compliance/*_BASELINE.json`
at a pinned upstream commit (`profile._upstream_commit`), plus `_provider`,
`_upstream_repo`, `_upstream_license` keys. Strong ETag = SHA-256 of the
sorted-key canonical profile. `404 unknown_region` lists valid regions.

### 2.2 `POST /validate/fria` (alias `POST /validate`)
Body: CAGE `action_context` (JSON object, ≤64 KiB). Region resolution order:
`deployment_region` → `governance.deployment_region` → `region` →
`X-CAGE-Region` header → provider default (`EU_ECB`).

Findings (OSCAL `status` ∈ pass/fail/not_applicable/error; `severity` ∈ info/review/blocked):

| Code | Fails when | Severity | Control |
|---|---|---|---|
| `RECORD_THREAD_ID` | no `thread_id`/`correlation_id`/`scenario_id` | blocked | CTRL_TEL_003 |
| `RECORD_ACTION` | no `action` | blocked | CTRL_TEL_003 |
| `RECORD_ACTION_HASH` | malformed digest → blocked; absent → review | blocked / review | CTRL_TEL_003 |
| `RECORD_ACTOR` | no `agent_id`/`actor_id`/`operator_urn`/`executor_id` | review | CTRL_AGT_001 |
| `RECORD_POLICY_VERSION` | no `policy_version` | review | CTRL_OPA_005 |
| `OVERSIGHT_MARKER` | ceiling matches `^(HIGH|CRITICAL|SEVERE|IRREVERSIBLE)` and no `approval_id`/`human_approval`/`human_review`/`human_oversight` | review | CTRL_FRIA_006 (EU) / CTRL_MRM_004 |
| `SUBSTANTIVE_REVIEW_NOT_EVALUATED` | always `not_applicable` — scope disclosure | info | — |

Decision: any blocked → `REFUSE`; else any review → `ESCALATE` (`hold_ttl_seconds: 300`); else `ALLOW`.
`authority_record_id = "vfria_" + sha256(canonical{provider, region, baseline_sha256, thread_id, action_hash, decision, findings[code,status,severity], validated_at})[:32]`.

### 2.3 `GET|POST /evidence-chain/{thread_id}`
Input: `evidence_hash` (64 hex) as query string (GET, provider_01 style) or JSON body (POST, provider_07 style). Output `seal_hash` = SER record commitment (Merkle root over the payload hash); `transparency_anchor` is the Rekor entry or `{status: "deferred", reason}`; `seal_status` says which.

## §3 — Authentication & Transport

`Authorization: Bearer <key>` on the gate and seal endpoints. Keys are issued
per deployment by Verdict, compared in constant time over SHA-256 digests;
only a 12-hex `key_id` is logged. With no key configured on the Verdict side the
keyed endpoints answer **503**, never 200. Rate limits are per key
(gate 600/min, seal 60/min by default; `429` + `Retry-After`).

## §4 — Decision Mapping Rules

See `src/integrations/provider_08/README.md` § Fail-Closed Behavior Specification.
Verdict's own findings are appended after the CAGE-level finding with
`"provider": "provider_08"` so the evidence stream preserves the external view.

## §5 — Hostile Validation Test Plan

| Vector | Expected |
|---|---|
| Timeout / partition on `/validate/fria` | `ENDPOINT_ERROR`, `admitted=False` |
| 401 (bad key), 429 (limit), 5xx | `ENDPOINT_ERROR` carrying the status |
| `decision` missing, lower-case, unknown, or null | `PARSE_ERROR`, `admitted=False` |
| `ALLOW` with empty `authority_record_id` | mint raises → `CONSEQUENCE_TOKEN_MINT_FAILED` |
| Replay of a prior `ALLOW` | ConsequenceToken single-use consumption in CAGE (Redis-Lua) |
| Anchor deferred | default: seal recorded, `EvidenceSeal.error=None`; `PROVIDER_08_REQUIRE_ANCHOR=true`: `error=PROVIDER_08_ANCHOR_DEFERRED` |
| Baseline drift | ETag/`profile_sha256` change → `NormativeDaemon` reconfigures `ControlRegistry` |

All vectors are exercised hermetically in `tests/integrations/provider_08/`.

## §6 — Contacts

Technical: evidence@verdict.systems · Integration page: https://verdict.systems/integrations/cage
