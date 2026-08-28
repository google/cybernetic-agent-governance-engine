# Provider 02 — Certified Evidence Receipt (CER) Attestation Provider

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint** — every URL below is a placeholder. Adopters
> should treat this as an integration pattern to adapt, not a hosted service.

| Property | Value |
|---|---|
| Protocol | Vendor-specific attestation surface — **not** `NormativeProvider`, and **not** a subclass of the abstract [`AttestationProvider`](../../gateway/governance/attestation_provider.py:36) |
| Integration style | Out-of-band attestation; no per-transaction hot-path call |
| Classes | `Provider02AttestationProvider` ([`provider.py`](provider.py:137)), `Provider02Client` and `Provider02AttestationCallback` ([`adapter.py`](adapter.py:361)) |
| Status | HTTP clients implemented; no endpoint configured |
| Factory names | `provider_02`, alias `p02` (resolvable through `get_normative_provider()`, but it does not satisfy the `NormativeProvider` method set) |
| Conformance suite | Registered in `ATTESTATION_PROVIDERS`; covered by `test_attestation_providers_exist` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py:49)) |

## Verdict vocabulary

**None.** This provider does not emit a verdict and never produces a
`ValidationResult`. It certifies and verifies evidence rather than gating an
action, so there is no `admitted` mapping and nothing that can park in the
`DeferQueue`.

The nearest thing to an outcome is `CERVerification.valid` (a plain `bool`) plus
an optional `error` string ([`provider.py`](provider.py:100)).

## Two components

**1. `Provider02AttestationProvider`** — CER lifecycle.

| Method | Endpoint | Purpose |
|---|---|---|
| `certify_decision()` | `POST {base}/certifyDecision` | Submit a governance decision, receive a `CERReceipt` |
| `verify_cer()` | *(local)* → falls back to `GET {base}/verify/{hash}` | Verify against the cached JWK set; remote only when the cache is empty |
| `register_project_bundle()` | `POST {base}/registerProjectBundle` | Register a completed bundle |

JWKs are synced out-of-band by a background asyncio task
([`_jwk_sync_loop()`](provider.py:408)) on a 24h default TTL with `ETag`/`304`
handling, so hot-path verification makes no network call.

> **Implementation note, verified in code:** [`_verify_local()`](provider.py:274)
> is **not** a complete Ed25519 verification. It confirms the JWK cache is
> populated and that the certificate hash is 64 hex characters, then returns
> `valid=True`. The full signature check is marked as pending finalization of
> the API contract. Adopters must not read a `valid=True` from this path as
> cryptographic proof.

**2. `Provider02AttestationCallback`** — a LangGraph callback handler that
snapshots `AgentState` at governance-significant node boundaries
(`nemo_guardrail`, `evaluator`, `safety_check`, `governed_trader`, `explainer`,
`nemo_output_rail`), deep-copying to survive destructive in-place loop mutation,
and assembles an `AttestationBundle` DAG at graph completion.

Terminal paths classified: `happy_path`, `nemo_block`, `cbf_block`,
`loop_breaker`, `unknown`.

## Error semantics

Two different conventions coexist in this package — worth knowing before you
wire it up:

| Component | On HTTP/transport failure |
|---|---|
| `Provider02AttestationProvider` ([`provider.py`](provider.py:252)) | Returns a dataclass with `error` populated (`CERReceipt(error=...)`, `CERVerification(valid=False, ...)`) |
| `Provider02Client` ([`adapter.py`](adapter.py:536)) | **Raises** `Provider02Error` with `code="ENDPOINT_ERROR"` |

## Wire contract change in the backward-compatibility remediation

**No wire-contract change.** The only change touching this package was internal:
[`_hash_state()`](adapter.py:230) migrated to RFC 8785 JCS canonicalization, so
the `stateHash` digest values submitted in bundles differ from those produced by
earlier builds. The request and response *shapes* are unchanged.

## Configuration

Placeholder endpoints only. `PROVIDER_02_API_ENDPOINT`,
`PROVIDER_02_API_KEY_SECRET` / `PROVIDER_02_API_KEY`,
`PROVIDER_02_JWK_ENDPOINT`, `PROVIDER_02_JWK_CACHE_TTL_HOURS`,
`PROVIDER_02_TIMEOUT_SECONDS`, `PROVIDER_02_ATTESTATION_ENABLED` (default
`false`).

Secrets belong in `terraform.auto.tfvars` and reach pods via `secretKeyRef` —
never as literal values in committed files.
