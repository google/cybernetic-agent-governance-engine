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
| Protocol | [`AttestationProvider`](../../gateway/governance/attestation_provider.py:36) — **three** concrete subclasses, one per axiom, plus [`WarrantSource`](../../gateway/governance/seams/warrant.py:43) |
| Integration style | Out-of-band attestation and live HTTP / seeded VEIP v0.2 institutional warrant verification |
| Classes | `Provider05BlueprintProvider`, `Provider05KeyProvider`, `Provider05PhysicsProvider`, plus `Provider05Client` and `Provider05WarrantSource` |
| Status | Warrant source: live HTTP (`GET /v0.2/warrants/{norm_id}` + `GET /.well-known/veip/key-manifest.json`) and seeded mode; Three-Axiom providers: seeded / synthetic |
| Conformance suite | Live Tier 1 over-the-wire conformance in [`tests/integrations/provider_05/test_provider_05_live.py`](../../../tests/integrations/provider_05/test_provider_05_live.py); vector suite in [`tests/integrations/provider_05/test_provider_05_veip_vectors.py`](../../../tests/integrations/provider_05/test_provider_05_veip_vectors.py) |

## The three axioms

| Provider | `provider_name` | `attestation_type` | Attests |
|---|---|---|---|
| [`Provider05BlueprintProvider`](blueprint_provider.py:41) | `provider_05-blueprint` | `BLUEPRINT` | Axiom 1 — Policy Legitimacy: a signed Authorizing Official risk-acceptance record backs the active threshold |
| [`Provider05KeyProvider`](key_provider.py) | `provider_05-key` | `KEY` | Axiom 2 — Identity Genesis: an admissibility grant exists for a SPIFFE ID at a consequence class |
| [`Provider05PhysicsProvider`](physics_provider.py) | `provider_05-physics` | `PHYSICS` | Axiom 3 — Substrate Integrity: vTPM status and eBPF anomaly count for the host node |

## Institutional warrants (Warrant Contract v0.1 & v0.2)

The warrant model, trust-anchor key-manifest verifier, standing verifier and
evidence binding are vendor-neutral kernel code in
[`src/gateway/governance/warrant/`](../../gateway/governance/warrant/__init__.py).
This package supplies warrants and the independently fetched key manifest:
[`Provider05WarrantSource`](warrant_source.py) implements the kernel
[`WarrantSource`](../../gateway/governance/seams/warrant.py:43) seam.
`fetch(norm_id)` returns the warrant as issued (`GET /v0.2/warrants/{norm_id}`
when `endpoint` or `PROVIDER_05_ATTESTATION_ENDPOINT` is configured, or the
seeded warrant in hermetic tests) or `None` (HTTP 404), which the kernel
verifier treats as `INELIGIBLE_MISSING`. `fetch_key_manifest()` fetches
`GET /.well-known/veip/key-manifest.json` (or the seeded manifest), which
[`WarrantCache`](../../gateway/governance/warrant/cache.py) verifies out-of-band
via [`VerifiedKeyManifest.verify()`](../../gateway/governance/warrant/trust_anchor.py)
against the pinned [`WarrantTrustAnchor`](../../gateway/governance/warrant/trust_anchor.py)
(`sha256:61ab867fc9ce773f2974081effbf0c9a4173caa23a4e18fa2c3bf65b249b8d85`).

`inject_fault()` takes the kernel `FaultMode` (`timeout`, `connection_error`,
`malformed_payload`, `unverified_source`) so every source-side fail-closed path
(`INELIGIBLE_UNRESOLVED`, `INELIGIBLE_STALE`) is exercised deterministically,
including end to end in
[`test_warrant_reliance_e2e.py`](../../../tests/governor/test_warrant_reliance_e2e.py).

A fourth `attestation_type`, `WARRANT`, is emitted by the kernel's
[`RelianceRecord.attestation()`](../../gateway/governance/warrant/reliance.py),
with `provider_name` taken from `Provider05WarrantSource.provider_name`
(`provider_05_warrant`). Its metadata is exactly the reliance record's
evidence form (below), so the envelope and the evidence chain cannot drift.
Under VEIP v0.2, its status is `VERIFIED` once the key manifest is verified
against the out-of-band root trust anchor, `warrant.kid` resolves to an active
issuer key in the manifest, the JCS `digest` matches, and the Ed25519
`signature` over `JCS(warrant_with_digest)` verifies; otherwise (including
`TAMPERED_SIGNATURE`, `UNKNOWN_KID`, or unsigned v0.1 warrants) it remains
`UNVERIFIED`. Reliance eligibility travels in `metadata["reliance_status"]`; an
ineligible warrant is never emitted as `DENIED`, because ineligibility is not
an institutional verdict.

Each evaluation becomes a kernel
[`RelianceRecord`](../../gateway/governance/warrant/reliance.py) naming this
source (`provider_name: provider_05_warrant`). It is written into the routing
seal's evidence record (covered by `record_hash`), the DEFER token and its
`GOVERNANCE_DEFERRAL` evidence event, or the refusal receipt, with the same
fields whether the warrant was eligible or not.

The record carries every Warrant Contract evidence field
(`WARRANT_CONTRACT_EVIDENCE_FIELDS` maps contract names to record keys):

| Contract field | Record key | Notes |
|---|---|---|
| `warrant_id` | `warrant_id` | |
| `norm_id` | `norm_id` | |
| `digest` | `warrant_digest` | issuer-declared, never computed by CAGE |
| `reliance_status` | `reliance_status` | |
| `governing_version` | `warrant_governing_version` | what the warrant declares |
| `residual_risk_ref` | `residual_risk_ref` | opaque (Q5): recorded verbatim, never resolved |
| `attested_at` | `attested_at` | when CAGE evaluated standing |

`required_governing_version` (what the deployment's binding requires) is
recorded apart from `warrant_governing_version`; they differ on
`INELIGIBLE_VERSION_MISMATCH` (VEC-005). The record also carries
`issuing_authority`, `authority_basis`, `revocation_ref`, and
`verification_status` (`VERIFIED` or `UNVERIFIED`). With no warrant
(`INELIGIBLE_MISSING`, or the source failed before answering) every
warrant-declared field is `""`; `attested_at` is always set.

### Freshness (60 s window & `state_as_of`)

The kernel never relies on a warrant state from this source for more than
`warrant.max_age_seconds` (60 s, the Warrant Contract Q2 window):
1. **Receipt freshness**: [`WarrantCache`](../../gateway/governance/warrant/cache.py)
   stamps `observed_at` (CAGE's receipt time) and re-fetches once the window
   has elapsed. A re-fetch that fails or exceeds `warrant.fetch_timeout_seconds`
   (2 s) makes the norm `INELIGIBLE_STALE` (DEFER).
2. **Issuer state freshness (v0.2 `state_as_of`)**:
   [`WarrantStandingVerifier`](../../gateway/governance/warrant/verifier.py)
   verifies that `now - state_as_of <= max_age_seconds` (60 s); a warrant whose
   issuer-signed `state_as_of` is older than the window resolves as
   `INELIGIBLE_STALE` (`STALE_STATE` conformance scenario).

## Verdict vocabulary

**No gate verdict.** These providers never return a `ValidationResult`. They
emit `ExternalAttestation` entries carrying a status from the shared
[`AttestationStatus`](../../gateway/governance/governance_envelope.py:113) enum.

| Status | Emitted when |
|---|---|
| `VERIFIED` | Warrant (v0.2): Ed25519 signature verified against `kid`-resolved key manifest · Blueprint: record found and no drift · Key: `grant.admitted` is true · Physics: `vtpm_status == "VERIFIED"` **and** `ebpf_anomaly_count == 0` |
| `UNVERIFIED` | Warrant: unsigned v0.1 warrant, `UNKNOWN_KID`, `TAMPERED_SIGNATURE`, or missing warrant |
| `DENIED` | Key: grant present but `admitted` false · Physics: vTPM not verified or any eBPF anomaly |
| `STALE` | Three-Axiom providers: the underlying record was not found |
| `DRIFT_DETECTED` | Blueprint only: the active runtime threshold differs from the signed value by more than `1e-6` |
| `ERROR` | Defined in the enum; not emitted by these providers |

### Warrant vocabularies

The kernel warrant model ([`model.py`](../../gateway/governance/warrant/model.py:52))
carries two further enums, distinct from `AttestationStatus`:

- `WarrantStatus` — `ACTIVE`, `SUSPENDED`, `REVOKED`
- `RelianceStatus` — `ELIGIBLE`, `INELIGIBLE_MISSING`, `INELIGIBLE_EXPIRED`,
  `INELIGIBLE_REVOKED`, `INELIGIBLE_SUSPENDED`, `INELIGIBLE_OUT_OF_SCOPE`,
  `INELIGIBLE_VERSION_MISMATCH`, `INELIGIBLE_AUTHENTICITY`,
  `INELIGIBLE_UNRESOLVED`, `INELIGIBLE_STALE`

## Configuration

- `PROVIDER_05_ATTESTATION_ENDPOINT`: Base URL for VEIP v0.2 warrant and key-manifest HTTP endpoints (sandbox: `https://veip-cage-sandbox.am-43b.workers.dev`).
- `PROVIDER_05_WARRANT_SCENARIO`: Optional scenario query parameter (`ACTIVE`, `REVOKED`, `SUSPENDED`, `EXPIRED`, `STALE_STATE`, `TAMPERED_SIGNATURE`, `UNKNOWN_KID`, `MISSING`).
- `PROVIDER_05_MANIFEST_ROOT_PUBLIC_KEY`, `PROVIDER_05_MANIFEST_ROOT_FINGERPRINT`, `PROVIDER_05_MANIFEST_ROOT_KID`: Out-of-band root trust anchor overrides (defaults to the pinned VEIP v0.2 sandbox root key `sha256:61ab867fc9ce773f2974081effbf0c9a4173caa23a4e18fa2c3bf65b249b8d85`).
- `PROVIDER_05_TIMEOUT_SECONDS`: HTTP request timeout (default `5.0`, bounded by kernel `warrant.fetch_timeout_seconds`).
