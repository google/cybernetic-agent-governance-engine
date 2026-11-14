# FlowSignal (provider_01) Phase 3 v0.3 Bilateral Wire-Contract Addendum

<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->
> [!NOTE]
> **Third-party integration material.** Its presence in this repository is not
> a Google certification or endorsement of the partner or its products. For the
> integration's current verification status, see
> [Live Verification Status](../README.md#live-verification-status).
<!-- /CAGE-PARTNER-CONTENT-HEADER -->

**Document Version:** 0.3  
**Parent Specification:** [`FLOWSIGNAL_PARTNER_SPECIFICATION.md`](FLOWSIGNAL_PARTNER_SPECIFICATION.md)  
**Status:** BILATERAL CONTRACT ADDENDUM — CAGE ADAPTER READY (`PROVIDER_01_CONTRACT_VERSION=v0.3`), PENDING PARTNER SANDBOX CUTOVER  
**Integration Slot:** `provider_01` (`NormativeProvider`)  
**Related POA&Ms:** `POAM-2026-113`, `POAM-2026-156` (item 2), `POAM-2026-218`  
**Last Updated:** 2026-11-14  

---

## §1 — Purpose & Scope

This bilateral addendum defines the **Phase 3 `v0.3` wire-contract revision** between Google CAGE and FlowSignal (`provider_01`) on `POST /cage/validate`. Phase 3 `v0.3` closes two structural gaps identified during Phase 3 `v0.2` qualification:

1. **Verified Request Fact Provenance (`POAM-2026-113`, GHSA-f6xq-23f7-9grm):** Under `v0.2`, CAGE populated `actor_authenticated`, `kya_status`, and `mandate_status` from static constants and filled absent mandate, screening, counterparty, and account fields with permissive fallback defaults (`DEFAULT-MANDATE`, `1000000.0`, `2099-12-31T23:59:59Z`, `UNRESTRICTED`, `CLEAR`, current timestamp), while reading `target` from caller-supplied `params`. Under `v0.3`, every authority-bearing fact must have verified provenance or fail closed before `POST /cage/validate` is dispatched.
2. **Receipt-Validity-Bounded Single-Use Consumption (`POAM-2026-156` item 2):** Under `v0.2`, FlowSignal `ALLOW` responses carried `authority_receipt.id` without a mandatory receipt expiry bound, so CAGE sized its single-use consumption marker (`consequence:token:<rec>`) only to the 60 s `ConsequenceToken` lifetime (`SET NX EX 90`). Under `v0.3`, every `ALLOW` response must declare an explicit RFC 3339 UTC-offset receipt validity upper bound (`authority_receipt.valid_until`), enabling CAGE to retain the single-use Redis marker across the **entire remaining validity of the receipt** plus clock-skew margin.

All Cloud Run Domain Restricted Sharing (DRS) dual-header authentication rules (`X-Serverless-Authorization` + `Authorization: Bearer`) and tri-state decision vocabulary (`ALLOW` / `ESCALATE` / `REFUSE`) in [`FLOWSIGNAL_PARTNER_SPECIFICATION.md`](FLOWSIGNAL_PARTNER_SPECIFICATION.md) remain unchanged.

---

## §2 — Request Wire Contract Changes (`CageAuthorityDetermineRequest` `v0.3`)

The 37-field JSON envelope on `POST /cage/validate` is preserved on the wire so FlowSignal's Pydantic model remains backwards-compatible at the transport layer, while CAGE enforces strict server-side provenance and eliminates all synthetic fallback defaults:

### 2.1 Server-Verified Caller Identity (`POAM-2026-113` Item 1)

| Field | `v0.2` Behavior (Retiring) | `v0.3` Strict Invariant |
|---|---|---|
| `actor_id` | `envelope.get("operator_urn", "")` (could be empty outside `FriaTier`) | Derived strictly from CAGE's server-verified `operator_urn` / `actor_id`. Empty, whitespace, or conflicting envelope identities fail closed locally with `PROVIDER_01_UNVERIFIED_CALLER` **before** any HTTP request. |
| `actor_authenticated` | Hard-coded `True` | Set to `True` **only** after `actor_id` is verified from CAGE workload identity; never asserted for anonymous callers. |
| `kya_status` | Hard-coded `"VERIFIED"` | Set to `"VERIFIED"` **only** from that verified workload identity. |

### 2.2 Server-Bound `target` & Elimination of Permissive Fact Defaults (`POAM-2026-113` Item 2)

1. **Server-Bound `target`:**
   - Under `v0.3`, `target` is populated strictly from CAGE's server-configured `PROVIDER_01_BOUND_TARGET` (`bound_target` constructor parameter on `Provider01NormativeProvider`), **never** from caller-supplied `params["target"]`.
   - Any caller-supplied `params["target"]` value is ignored under `v0.3`. If `bound_target` is unconfigured/empty, CAGE fails closed locally (`PROVIDER_01_MISSING_VERIFIED_FACT`, `missing_fields: ["bound_target"]`) before making any HTTP call.
2. **Mandatory Verified Institutional, Mandate, Account & Screening Facts (Zero Synthetic Defaults):**
   - CAGE removes all permissive `params.get(..., default)` fallbacks under `v0.3`. Every request must explicitly supply verified values for all 14 fields below, or CAGE fails closed locally before HTTP with `PROVIDER_01_MISSING_VERIFIED_FACT` enumerating every missing or invalid field:

| Field | Required Type & Validation under `v0.3` | Retired `v0.2` Fallback |
|---|---|---|
| `mandate_id` | Non-empty `str` | `"DEFAULT-MANDATE"` |
| `mandate_status` | Non-empty `str` (e.g. `"ACTIVE"`, `"EXPIRED"`, `"SUSPENDED"`) | Hard-coded `"ACTIVE"` |
| `mandate_max_amount` | Finite `float > 0` (booleans rejected) | `1000000.0` |
| `mandate_valid_until` | RFC 3339 / ISO-8601 `str` with explicit UTC offset (`Z` or `±HH:MM`) | `"2099-12-31T23:59:59Z"` |
| `permitted_source_accounts` | Non-empty `list[str]` of non-empty account IDs | `["DEFAULT"]` |
| `permitted_counterparty_class` | Non-empty `str` | `"UNRESTRICTED"` |
| `source_account` | Non-empty `str` | `"DEFAULT"` |
| `beneficiary` | Non-empty `str` | `"UNKNOWN"` |
| `counterparty_status` | Non-empty `str` | `"UNKNOWN"` |
| `account_status` | Non-empty `str` | `"ACTIVE"` |
| `screening_status` | Non-empty `str` | `"CLEAR"` |
| `screening_captured_at` | RFC 3339 / ISO-8601 `str` with explicit UTC offset (`Z` or `±HH:MM`) | `datetime.now(timezone.utc)` |
| `screening_max_age_seconds` | Positive `int > 0` (booleans rejected) | `3600` |
| `screening_source` | Non-empty `str` | `"CAGE-INTERNAL"` |

FlowSignal's `v0.3` validator should likewise reject synthetic placeholder literals (`DEFAULT-MANDATE`, `2099-12-31T23:59:59Z`, `CAGE-INTERNAL`) if presented by a non-conformant client outside CAGE's strict adapter.

---

## §3 — Response Wire Contract Changes (`ALLOW` Receipt Validity — `POAM-2026-156` Item 2)

### 3.1 Mandatory `authority_receipt.valid_until` on `ALLOW`

Every `200 OK` response from `POST /cage/validate` with `"decision": "ALLOW"` MUST carry both a unique per-determination receipt identifier and an explicit RFC 3339 UTC-offset validity upper bound:

```json
{
  "decision": "ALLOW",
  "authority_record_id": "MANDATE-TREASURY-001",
  "authority_state_version": "42",
  "authority_receipt": {
    "id": "rcpt-0192f4c8-7b2a-7d11-9e40-8c3b1f0042a1",
    "valid_until": "2026-11-14T20:10:00Z"
  }
}
```

### 3.2 Field & Enforcement Semantics

1. **Accepted Field Paths:** CAGE reads `authority_receipt.valid_until` (canonical), falling back to `authority_receipt.expires_at` or top-level `receipt_valid_until`.
2. **Timestamp Format:** Must be an RFC 3339 / ISO-8601 string carrying an explicit UTC offset (`Z`, `+00:00`, or `±HH:MM`) that resolves to an epoch timestamp strictly greater than CAGE's evaluation clock (`epoch > now`). Timezone-naive timestamps (e.g. `"2026-11-14T20:10:00"`), bare dates, non-strings, and already-expired timestamps are rejected.
3. **Fail-Closed Enforcement on CAGE Side:**
   - Under `v0.3`, an `ALLOW` response missing a valid future UTC-offset receipt expiry is **rejected fail-closed** (`ValidationResult(admitted=False)`, finding code `CONSEQUENCE_TOKEN_MINT_FAILED`, message `"Provider 01 v0.3 ALLOW carries no valid receipt expiry ..."`). No `ConsequenceToken` is minted.
   - Under `v0.2` (transitional compatibility), if FlowSignal emits `authority_receipt.valid_until` early during canary rollout, CAGE parses and propagates it cleanly whenever valid.
4. **End-to-End Single-Use Marker Retention (`rec_exp`):**
   - CAGE embeds `rec_exp = int(valid_until.timestamp())` into the KMS-signed `ConsequenceToken` JWS payload (`ConsequenceTokenClaims.rec_exp`).
   - `ConsequenceToken.verify()` rejects any token whose `rec_exp` is non-integer, boolean, `<= 0`, `<= iat`, or already expired (`now > rec_exp`).
   - `ConsequenceGateway.evaluate()` refuses `claims.rec_exp <= now` **before** touching Redis, and calls `ConsequenceAuthorityStore.consume_once(claims.rec, binding, ttl_seconds=max(store.ttl_seconds, (claims.rec_exp - now) + 30))`.
   - Consequently, a receipt valid for 600 s retains its `consequence:token:<rec>` single-use marker for `>= 630` s (replica-acknowledged via `WAIT`), preventing replay or substitution if a second token is minted for the same still-valid receipt after the 90 s token-sized default window.

---

## §4 — Transition & `v0.2` Retirement Protocol (`POAM-2026-218`)

To keep CAGE's live partner harness (`ci-partner-integration.yml`) green while FlowSignal deploys Phase 3 `v0.3` to its Cloud Run staging service:

1. **Pre-Cutover (Current State):**
   - `Provider01NormativeProvider` defaults `PROVIDER_01_CONTRACT_VERSION` to `"v0.2"` while shipping full `"v0.3"` enforcement behind `PROVIDER_01_CONTRACT_VERSION=v0.3` and `PROVIDER_01_BOUND_TARGET=<target>`.
   - Both `POAM-2026-113` and `POAM-2026-156` (item 2) remain **Open** alongside `POAM-2026-218`.
2. **Cutover & Mandatory `v0.2` Deletion Gate:**
   - Once FlowSignal promotes Phase 3 `v0.3` on its staging Cloud Run endpoint, CAGE's cutover PR MUST simultaneously:
     1. Delete `"v0.2"`, `PROVIDER_01_CONTRACT_VERSION`, all permissive `params.get(..., default)` fallbacks in `_build_cage_authority_request()`, and optional-receipt-validity fallback in `src/integrations/provider_01/provider.py`, making strict `v0.3` the sole code path;
     2. Re-run live over-the-wire conformance (`ALLOW`, `REFUSE`, `ESCALATE`, receipt-validity marker retention, and fail-closed paths) against the staging sandbox; and
     3. Close `POAM-2026-113`, `POAM-2026-156` (item 2), and `POAM-2026-218` together.
   - CI enforces this atomicity via `test_poam_218_forbids_closing_poam_113_while_v02_dual_path_exists` in `tests/integrations/provider_01/test_provider_01_v03_readiness.py`: marking either `POAM-2026-113` or `POAM-2026-218` closed while `"v0.2"` or `PROVIDER_01_CONTRACT_VERSION` still exists in `provider.py` fails the build immediately.
