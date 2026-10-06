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
| Classes | `Provider05BlueprintProvider`, `Provider05KeyProvider`, `Provider05PhysicsProvider`, plus `Provider05Client` and `VeipWarrantSource` |
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
This package only supplies warrants: [`VeipWarrantSource`](warrant_source.py:43)
implements the kernel [`WarrantSource`](../../gateway/governance/seams/warrant.py:43)
seam. `fetch(norm_id)` returns the seeded warrant exactly as issued (declared
digest included) or `None`, which the kernel verifier treats as
`INELIGIBLE_MISSING`. The source never decides reliance eligibility itself.

A fourth `attestation_type`, `WARRANT`, is emitted by the kernel's
[`bind_warrant_to_attestation()`](../../gateway/governance/warrant/evidence.py:33),
with `provider_name` taken from `VeipWarrantSource.provider_name`
(`provider_05_warrant`). Its status is always `UNVERIFIED`: the declared digest
proves the warrant is internally consistent, not who issued it (issuer
signatures are v0.2). Reliance eligibility travels in
`metadata["reliance_status"]`; an ineligible warrant is never emitted as
`DENIED`, because ineligibility is not an institutional verdict.

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
  `INELIGIBLE_VERSION_MISMATCH`, `INELIGIBLE_UNRESOLVED`

## Seeded / synthetic data

[`Provider05Client`](client.py:115) holds three in-memory dicts populated
through `seed_risk_acceptance()`, `seed_admissibility_grant()`, and
`seed_substrate_attestation()`. [`VeipWarrantSource`](warrant_source.py:43)
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
