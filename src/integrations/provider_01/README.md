# Provider 01 — Normative Compliance Provider (Synchronous Gate)

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint** — every URL below is a placeholder. Adopters
> should treat this as an integration pattern to adapt, not a hosted service.

| Property | Value |
|---|---|
| Protocol | [`NormativeProvider`](../../gateway/governance/normative_provider.py:273) |
| Integration style | Synchronous gate, remote HTTP, on the request hot path |
| Class | `Provider01NormativeProvider` ([`provider.py`](provider.py:247)) |
| Status | `INTERFACE READY` — HTTP client fully implemented; no endpoint configured |
| Factory names | `provider_01`, alias `p01` |
| Conformance suite | Registered in `NORMATIVE_PROVIDERS` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py:48)) |

## Endpoints

Base URL from `CAGE_NORMATIVE_ENDPOINT` (placeholder:
`https://api.example.com/normative`). Auth is
`Authorization: Bearer <key>` from `CAGE_NORMATIVE_API_KEY_SECRET`. Timeout
defaults to 5s (`CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS`).

| Method | Path | Protocol method | Returns |
|---|---|---|---|
| `GET` | `/legal-baseline/{region}` | `fetch_baseline()` | `NormativeBaseline` |
| `POST` | `/validate/fria` | `validate_fria()` | `ValidationResult` |
| `GET` | `/evidence-chain/{thread_id}` | `submit_evidence()` | `EvidenceSeal` |

## Verdict vocabulary

`ALLOW` / `REFUSE` / `ESCALATE` — declared at
[`provider.py:74`](provider.py:74), matched case-insensitively via
`.upper().strip()` in [`_map_flowsignal_decision()`](provider.py:177).

| `decision` | `admitted` | Finding code | Severity | Effect |
|---|---|---|---|---|
| `ALLOW` | `True` | `CONSEQUENCE_TOKEN` | `info` | ConsequenceToken JWS minted and attached |
| `REFUSE` | `False` | `FLOWSIGNAL_REFUSE` | `blocked` | Hard deny |
| `ESCALATE` | `False` | `FLOWSIGNAL_HOLD` | `review` | `needs_human_review: True` → parks in `DeferQueue` |

> **`REVIEW` is not part of this vocabulary.** `PASS` / `REVIEW` / `BLOCKED`
> belongs to [`provider_06`](../provider_06/README.md). A `REVIEW` string on
> this contract is unrecognized and fails closed. Map an upstream `REVIEW` to
> `ESCALATE` — both reach the same `DeferQueue` outcome.

## Fail-closed behavior

All of these yield `ValidationResult(admitted=False)`:

| Condition | Finding code | Severity |
|---|---|---|
| `decision` field absent from a 200 response | `cage.endpoint_error` | `blocked` |
| `decision` present but unrecognized | `PARSE_ERROR` | `blocked` |
| `ALLOW` without `authority_record_id` | `CONSEQUENCE_TOKEN_MINT_FAILED` | `blocked` |
| Non-2xx status, transport error, unexpected exception | `ENDPOINT_ERROR` | `blocked` |

### `authority_record_id` is required on `ALLOW`

On `ALLOW`, [`_mint_consequence_token()`](provider.py:86) needs five inputs.
Two come from the CAGE-side FRIA payload (`actor_id`, `thread_id`); one is
computed (SHA-256 over the JCS-canonicalized payload); and two come from the
vendor response:

- **`authority_record_id` — required.** [`provider.py:128`](provider.py:128)
  raises without it.
- `authority_state_version` — nullable, does not block.

A mint failure is not downgraded to a warning:
[`validate_fria()`](provider.py:357) detects the
`CONSEQUENCE_TOKEN_MINT_FAILED` finding and forces `admitted` back to `False`.
So an `ALLOW` lacking `authority_record_id` fails closed even though the
response parsed cleanly — a **distinct** failure mode from a missing
`decision`.

## Wire contract change in the backward-compatibility remediation

**Yes — this adapter's wire contract changed.** The legacy binary
`admitted`/`findings` fallback was removed, making `decision` mandatory. A
response that lost its `decision` key was previously admitted on a truthy
`admitted` without passing through tri-state mapping or token minting; it now
fails closed. Tracked as **BC-03** in
[`docs/BREAKING_CHANGES_v3.md`](../../../docs/BREAKING_CHANGES_v3.md), with the
`authority_record_id`-on-`ALLOW` requirement documented alongside it.

## Vendor isolation

This package must not be imported by the CAGE kernel. It is lazy-loaded by
`get_normative_provider()` in
[`normative_provider.py`](../../gateway/governance/normative_provider.py:930),
and its own imports of kernel dataclasses are deferred to call time.
