# Provider 01 — Normative Compliance Provider (Synchronous Gate)

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint** — every URL below is a placeholder. Adopters
> should treat this as an integration pattern to adapt, not a hosted service.
>
> **Naming note:** The vendor name for this integration is **FlowSignal**. The
> package path `provider_01` is retained for import stability across branches
> and test fixtures.

| Property | Value |
|---|---|
| Protocol | [`NormativeProvider`](../../gateway/governance/normative_provider.py) |
| Integration style | Synchronous gate, remote HTTP, on the request hot path |
| Class | `Provider01NormativeProvider` ([`provider.py`](provider.py)) |
| Contract versions | `v0.2` (default compatibility path) / `v0.3` (opt-in strict mode via `PROVIDER_01_CONTRACT_VERSION=v0.3`; [`FLOWSIGNAL_PHASE3_V03_ADDENDUM.md`](../../../docs/partners/provider_01/FLOWSIGNAL_PHASE3_V03_ADDENDUM.md)) |
| Status | `INTERFACE READY` — HTTP client fully implemented; no endpoint configured |
| Factory names | `provider_01`, alias `p01` |
| Conformance suite | Registered in `NORMATIVE_PROVIDERS` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py)) |

## Endpoints

Base URL from `CAGE_NORMATIVE_ENDPOINT` (placeholder:
`https://api.example.com/normative`). Auth is
`Authorization: Bearer <key>` from `CAGE_NORMATIVE_API_KEY_SECRET` (plus optional
`X-Serverless-Authorization: Bearer <token>` from `CAGE_NORMATIVE_GCP_ID_TOKEN`
for Cloud Run DRS ingress). Validation path defaults to `/cage/validate`
(`CAGE_NORMATIVE_VALIDATE_PATH`, cut over from legacy `/validate/fria` in Phase 3
v0.2) and sends the 37-field `CageAuthorityDetermineRequest` payload constructed by
[`_build_cage_authority_request()`](provider.py). Timeout defaults to 5s
(`CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS`).

| Method | Path | Protocol method | Returns |
|---|---|---|---|
| `GET` | `/legal-baseline/{region}` | `fetch_baseline()` | `NormativeBaseline` |
| `POST` | `/cage/validate` | `validate_fria()` | `ValidationResult` |
| `GET` | `/evidence-chain/{thread_id}` | `submit_evidence()` | `EvidenceSeal` |

## Contract Versions (`v0.2` vs. Opt-In `v0.3`)

`Provider01NormativeProvider` reads `PROVIDER_01_CONTRACT_VERSION` (default `"v0.2"`, accepting **only** `"v0.2"` or `"v0.3"` and raising `ValueError` fail-closed on any other value):

- **`v0.2` (compatibility default while partner sandbox serves Phase 3 `v0.2`):** Preserves Phase 3 `v0.2` payload construction for live compatibility. If an `ALLOW` response includes a valid future UTC-offset `authority_receipt.valid_until` / `authority_receipt.expires_at` / `receipt_valid_until`, it is parsed and propagated as `receipt_expires_at` (`rec_exp` claim). Retirement of `"v0.2"` at partner sandbox cutover is tracked and mechanically gated by `POAM-2026-218` ([`test_provider_01_v03_readiness.py`](../../../tests/integrations/provider_01/test_provider_01_v03_readiness.py)).
- **`v0.3` (opt-in strict mode — `POAM-2026-113` & `POAM-2026-156` item 2):**
  1. **Verified caller identity:** Derives `actor_id`, `actor_authenticated`, and `kya_status` strictly from server-verified `operator_urn` / `actor_id` in the governance envelope. Missing, whitespace, or conflicting caller identities fail closed (`PROVIDER_01_UNVERIFIED_CALLER`) **before** any HTTP call.
  2. **Server-bound `target` & explicit verified facts:** Populates `target` strictly from server-configured `bound_target` (`PROVIDER_01_BOUND_TARGET`, never caller-supplied `params["target"]`) and refuses all synthetic `v0.2` defaults, requiring explicit verified `mandate_id`, `mandate_status`, `mandate_max_amount`, `mandate_valid_until`, `permitted_source_accounts`, `permitted_counterparty_class`, `source_account`, `beneficiary`, `counterparty_status`, `account_status`, `screening_status`, `screening_captured_at`, `screening_max_age_seconds`, and `screening_source` (`PROVIDER_01_MISSING_VERIFIED_FACT`, naming missing fields).
  3. **Mandatory receipt expiry (`rec_exp`):** Requires an RFC 3339 / ISO-8601 UTC-offset future timestamp in `authority_receipt.valid_until` (or `authority_receipt.expires_at` / `receipt_valid_until`) on every `ALLOW`, failing closed with `CONSEQUENCE_TOKEN_MINT_FAILED` otherwise and propagating `receipt_expires_at` so `ConsequenceGateway` retains the single-use Redis marker across the receipt's full remaining validity plus skew buffer.

## Verdict vocabulary

`ALLOW` / `REFUSE` / `ESCALATE` — matched case-insensitively via
`.upper().strip()` in [`_map_provider_01_decision()`](provider.py).

| `decision` | `admitted` | Finding code | Severity | Effect |
|---|---|---|---|---|
| `ALLOW` | `True` | `CONSEQUENCE_TOKEN` | `info` | ConsequenceToken JWS minted (carrying `rec_exp` when receipt expiry is present) and attached |
| `REFUSE` | `False` | `PROVIDER_01_REFUSE` | `blocked` | Hard deny |
| `ESCALATE` | `False` | `EXTERNAL_HOLD` | `review` | `needs_human_review: True` → parks in `DeferQueue` |

> **`REVIEW` is not part of this vocabulary.** `PASS` / `REVIEW` / `BLOCKED`
> belongs to [`provider_06`](../provider_06/README.md). A `REVIEW` string on
> this contract is unrecognized and fails closed. Map an upstream `REVIEW` to
> `ESCALATE` — both reach the same `DeferQueue` outcome.

## Fail-closed behavior

All of these yield `ValidationResult(admitted=False)`:

| Condition | Finding code | Severity |
|---|---|---|
| `v0.3` request with missing/conflicting verified `operator_urn` / `actor_id` | `PROVIDER_01_UNVERIFIED_CALLER` | `blocked` |
| `v0.3` request missing `PROVIDER_01_BOUND_TARGET` or any required verified fact | `PROVIDER_01_MISSING_VERIFIED_FACT` | `blocked` |
| `decision` field absent from a 200 response | `cage.endpoint_error` | `blocked` |
| `decision` present but unrecognized | `PARSE_ERROR` | `blocked` |
| `ALLOW` without `authority_receipt.id` / `authority_receipt_id` | `CONSEQUENCE_TOKEN_MINT_FAILED` | `blocked` |
| `v0.3` `ALLOW` without valid future UTC-offset receipt expiry | `CONSEQUENCE_TOKEN_MINT_FAILED` | `blocked` |
| Non-2xx status, transport error, unexpected exception | `ENDPOINT_ERROR` | `blocked` |

### Per-determination receipt ID & receipt validity on `ALLOW`

On `ALLOW`, [`mint_consequence_token_finding()`](../../gateway/governance/consequence_token_service.py)
(invoked from [`_map_provider_01_decision()`](provider.py)) binds single-use
consumption to `authority_receipt.id` (or `authority_receipt_id`), never to
`authority_record_id` (which may name a multi-payment mandate):

- **`authority_receipt.id` / `authority_receipt_id` — required in all contract versions.** Minting fails closed with `CONSEQUENCE_TOKEN_MINT_FAILED` without it.
- **`authority_receipt.valid_until` / `expires_at` — required in `v0.3` (optional in `v0.2`).** Propagated into `ConsequenceTokenClaims.rec_exp` so `ConsequenceAuthorityStore.consume_once()` retains the `SET NX EX` single-use marker across `max(store.ttl_seconds, (rec_exp - now) + 30)`.
- `authority_state_version` — nullable, does not block.

A mint failure is not downgraded to a warning:
[`validate_fria()`](provider.py) detects the
`CONSEQUENCE_TOKEN_MINT_FAILED` finding and forces `admitted` back to `False`.

### On the governor path (CAGE note)

The kernel `fria` tier ([`FriaTier`](../../gateway/governance/jurisdiction/eu_ai_act/fria_tier.py))
sends the workload identity the gateway verified for the request as `actor_id`
and `operator_urn` (wire `actor_id`; empty when there is none, never a request
value), the active trace id as `correlation_id` (wire `execution_id`, and
`approval_id` when none is given), and the request's thread id
(GHSA-f6xq-23f7-9grm).

An admission contributes no violation, so the tier reads only `admitted`: the
minted ConsequenceToken is not carried to the routing seal (decision D2,
POAM-2026-089). It is verified and consumed only by `ConsequenceGateway`, for
callers that present one. Partner documents that describe the token on the
`ALLOW` path describe that gateway path. Under `v0.3`, `target` comes strictly
from `PROVIDER_01_BOUND_TARGET` (`bound_target`), tracked in `POAM-2026-113` and
`POAM-2026-218` ([`docs/POAM.md`](../../../docs/POAM.md)).

## Wire contract change in the backward-compatibility remediation

**Yes — this adapter's wire contract changed.** The legacy binary
`admitted`/`findings` fallback was removed, making `decision` mandatory. A
response that lost its `decision` key was previously admitted on a truthy
`admitted` without passing through tri-state mapping or token minting; it now
fails closed. Tracked as **BC-03** in
[`docs/BREAKING_CHANGES.md`](../../../docs/BREAKING_CHANGES.md).

## Vendor isolation

This package must not be imported by the CAGE kernel. It is lazy-loaded by
`get_normative_provider()` in
[`normative_provider.py`](../../gateway/governance/normative_provider.py),
and its own imports of kernel dataclasses are deferred to call time.
