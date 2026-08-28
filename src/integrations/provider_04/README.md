# Provider 04 — Attestation Provider + Envelope Mapper (Stub)

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint**. Adopters should treat this as an integration
> pattern to adapt, not a hosted service.

| Property | Value |
|---|---|
| Protocols | [`AttestationProvider`](../../gateway/governance/attestation_provider.py:36) (concrete subclass) **and** an envelope-mapper surface |
| Integration style | Out-of-band attestation, polled; plus bidirectional envelope translation |
| Classes | `Provider04AttestationProvider` ([`provider.py`](provider.py:53)), `Provider04EnvelopeMapper` ([`envelope_mapper.py`](envelope_mapper.py:44)) |
| Status | **Stub** — see below |
| Conformance suite | Registered in `ATTESTATION_PROVIDERS`; asserted to expose `fetch_attestations` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py:49)) |

## Verdict vocabulary

**None in the CAGE gate sense.** This provider never returns a
`ValidationResult` and cannot admit, deny, or defer an action.

It emits [`ExternalAttestation`](../../gateway/governance/governance_envelope.py)
entries whose `status` is drawn from the shared
[`AttestationStatus`](../../gateway/governance/governance_envelope.py:113)
enum — `VERIFIED`, `DENIED`, `STALE`, `DRIFT_DETECTED`, `ERROR` — which is a
*status* vocabulary embedded in a governance envelope, not a gate verdict.

In practice the current implementation emits none of these, because it returns
an empty list.

## Stub status

[`fetch_attestations()`](provider.py:76) **always returns `[]`**:

- With no endpoint configured, it logs at debug level and returns `[]`.
- With an endpoint configured, it logs "stub implementation" and still returns
  `[]` — the HTTP fetch is an explicit `TODO` pending a production API.

The aggregator can therefore be wired end-to-end without a live endpoint, but
this provider contributes no attestations to any envelope today.

## Envelope mapper

`Provider04EnvelopeMapper` is a plain class, not a subclass of any protocol
base — the "EnvelopeMapper" role is structural.

| Method | Direction | Behavior |
|---|---|---|
| `to_provider_04_format(envelope)` | CAGE → vendor | Wraps the signed `GovernanceEnvelope` dict under `cage_envelope`, adding `provider_04_version`, `digest`, and a `metadata` block |
| `from_provider_04_format(data)` | Vendor → CAGE | Reconstructs the `GovernanceEnvelope`; raises `ValueError` if `cage_envelope` is missing |

## Wire contract change in the backward-compatibility remediation

**No wire-contract change.** Neither module was modified by the remediation.
Because the fetch path is a stub returning `[]`, there is no live wire contract
to break.

## Configuration

Placeholder only: `PROVIDER_04_ATTESTATION_ENDPOINT`,
`PROVIDER_04_ATTESTATION_API_KEY_SECRET`,
`PROVIDER_04_ATTESTATION_TIMEOUT_SECONDS` (default `5.0`).

Secrets belong in `terraform.auto.tfvars` and reach pods via `secretKeyRef`.

## Implementing this for real

Follow the `httpx.AsyncClient` pattern in
[`provider_03/provider.py`](../provider_03/provider.py), keep the fetch
off the hot path (poll at boot and on an interval, cache in the aggregator),
and fail closed by emitting `AttestationStatus.ERROR` or `STALE` rather than
silently returning `[]` — an empty list is indistinguishable from "nothing to
attest", which is the weakness of the current stub.
