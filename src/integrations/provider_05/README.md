# Provider 05 — Veraxis Execution Integrity Protocol (VEIP)

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint**. Adopters should treat this as an integration
> pattern to adapt, not a hosted service.
>
> **Naming note:** The vendor name for this integration is **Veraxis Execution
> Integrity Protocol (VEIP)**. The package path `provider_05` is retained for
> import stability across branches and test fixtures.


| Property | Value |
|---|---|
| Protocol | [`AttestationProvider`](../../gateway/governance/attestation_provider.py:36) — **three** concrete subclasses, one per axiom |
| Integration style | Out-of-band attestation, served from a **seeded in-memory store** |
| Classes | `Provider05BlueprintProvider`, `Provider05KeyProvider`, `Provider05PhysicsProvider`, plus `Provider05Client` and `Provider05WarrantSource` |
| Status | Seeded / synthetic — the HTTP path is unimplemented (see below) |
| Conformance suite | Not in `NORMATIVE_PROVIDERS` or `ATTESTATION_PROVIDERS`; covered separately by `test_attestation_providers_exist`, which instantiates `Provider05BlueprintProvider` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py:103)) |

## The three axioms

| Provider | `provider_name` | `attestation_type` | Attests |
|---|---|---|---|
| [`Provider05BlueprintProvider`](blueprint_provider.py:41) | `provider_05-blueprint` | `BLUEPRINT` | Axiom 1 — Policy Legitimacy: a signed Authorizing Official risk-acceptance record backs the active threshold |
| [`Provider05KeyProvider`](key_provider.py) | `provider_05-key` | `KEY` | Axiom 2 — Identity Genesis: an admissibility grant exists for a SPIFFE ID at a consequence class |
| [`Provider05PhysicsProvider`](physics_provider.py) | `provider_05-physics` | `PHYSICS` | Axiom 3 — Substrate Integrity: vTPM status and eBPF anomaly count for the host node |

## Institutional warrants

The warrant model, standing verifier and evidence binding are vendor-neutral
kernel code in [`src/gateway/governance/warrant/`](../../gateway/governance/warrant/__init__.py).
This package only supplies warrants: [`Provider05WarrantSource`](warrant_source.py:74)
implements the kernel [`WarrantSource`](../../gateway/governance/seams/warrant.py:43)
seam. `fetch(norm_id)` returns the seeded warrant exactly as issued (declared
digest included) or `None`, which the kernel verifier treats as
`INELIGIBLE_MISSING`. The source never decides reliance eligibility itself.
`inject_fault()` takes the kernel `FaultMode` (`timeout`, `connection_error`,
`malformed_payload`, `unverified_source`) so every source-side fail-closed path
(`INELIGIBLE_UNRESOLVED`, `INELIGIBLE_STALE`) is exercised deterministically,
including end to end in
[`test_warrant_reliance_e2e.py`](../../../tests/governor/test_warrant_reliance_e2e.py).

A fourth `attestation_type`, `WARRANT`, is emitted by the kernel's
[`bind_warrant_to_attestation()`](../../gateway/governance/warrant/evidence.py:33),
with `provider_name` taken from `Provider05WarrantSource.provider_name`
(`provider_05_warrant`). Its status is always `UNVERIFIED`: the declared digest
proves the warrant is internally consistent, not who issued it (issuer
signatures are v0.2). Reliance eligibility travels in
`metadata["reliance_status"]`; an ineligible warrant is never emitted as
`DENIED`, because ineligibility is not an institutional verdict. The kernel
returns these attestations with every `validate_action` ALLOW / NARROW for an
action a warranted norm governs, and the gateway signs them into the
`GovernanceEnvelope`.

Independently of the envelope, each evaluation becomes a kernel
[`RelianceRecord`](../../gateway/governance/warrant/reliance.py) naming this
source (`provider_name: provider_05_warrant`). It is written into the routing
seal's evidence record (covered by `record_hash`), the DEFER token and its
`GOVERNANCE_DEFERRAL` evidence event, or the refusal receipt, with the same
fields whether the warrant was eligible or not, and always
`verification_status: UNVERIFIED`.

### Freshness (60 s window)

The kernel never relies on a warrant state from this source for more than
`warrant.max_age_seconds` (60 s, the Warrant Contract v0.1 Q2 window) after
CAGE received it. [`WarrantCache`](../../gateway/governance/warrant/cache.py)
wraps `Provider05WarrantSource`, records `observed_at` (CAGE's receipt time;
the 11-field v0.1 schema has no issuer `state_as_of`) and re-fetches once the
window has elapsed. A re-fetch that fails or exceeds
`warrant.fetch_timeout_seconds` (2 s) makes the norm `INELIGIBLE_STALE`
(DEFER); the source cannot extend the window. The kernel timeout bounds every
fetch, whatever `PROVIDER_05_TIMEOUT_SECONDS` says. `observed_at`,
`age_seconds` and `max_age_seconds` are in every reliance record.

## Verdict vocabulary

**No gate verdict.** These providers never return a `ValidationResult`. They
emit `ExternalAttestation` entries carrying a status from the shared
[`AttestationStatus`](../../gateway/governance/governance_envelope.py:113) enum.

| Status | Emitted when |
|---|---|
| `VERIFIED` | Blueprint: record found and no drift · Key: `grant.admitted` is true · Physics: `vtpm_status == "VERIFIED"` **and** `ebpf_anomaly_count == 0` |
| `DENIED` | Key: grant present but `admitted` false · Physics: vTPM not verified or any eBPF anomaly |
| `STALE` | Any provider: the underlying record was not found |
| `DRIFT_DETECTED` | Blueprint only: the active runtime threshold differs from the signed value by more than `1e-6` |
| `ERROR` | Defined in the enum; not emitted by these three providers |

### Warrant vocabularies

The kernel warrant model ([`model.py`](../../gateway/governance/warrant/model.py:52))
carries two further enums, distinct from `AttestationStatus`:

- `WarrantStatus` — `ACTIVE`, `SUSPENDED`, `REVOKED`
- `RelianceStatus` — `ELIGIBLE`, `INELIGIBLE_MISSING`, `INELIGIBLE_EXPIRED`,
  `INELIGIBLE_REVOKED`, `INELIGIBLE_OUT_OF_SCOPE`,
  `INELIGIBLE_VERSION_MISMATCH`, `INELIGIBLE_UNRESOLVED`, `INELIGIBLE_STALE`

## Seeded / synthetic data

[`Provider05Client`](client.py:115) holds three in-memory dicts populated
through `seed_risk_acceptance()`, `seed_admissibility_grant()`, and
`seed_substrate_attestation()`. [`Provider05WarrantSource`](warrant_source.py:74)
holds warrants keyed by `norm_id`, populated through
[`seed()`](warrant_source.py:56).

Every getter follows the same shape: return the seeded record if present;
otherwise, if no endpoint is configured, return `None`. **The live HTTP branch
is a comment placeholder that also returns `None`**
([`client.py`](client.py:153); [`warrant_source.py`](warrant_source.py:64)
also logs a warning) — so configuring `PROVIDER_05_ATTESTATION_ENDPOINT`
changes nothing today. A `None` lookup
surfaces upstream as a `STALE` attestation, which is the fail-closed direction.

This is the only provider in the directory whose data is intentionally
synthetic rather than merely unconfigured.

## Wire contract change in the backward-compatibility remediation

**No wire-contract change.** The dataclass `to_canonical_bytes()` methods use
RFC 8785 JCS, so digest values are stable under the current canonicalization,
and there is no live wire path to break.

## Configuration

Placeholder only: `PROVIDER_05_ATTESTATION_ENDPOINT`,
`PROVIDER_05_API_KEY_SECRET`, `PROVIDER_05_TIMEOUT_SECONDS` (default `5.0`).
