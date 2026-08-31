# Provider 04 — Envelope Mapper

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized. Adopters should treat
> this as an integration pattern to adapt.

| Property | Value |
|---|---|
| Protocols | Envelope-mapper surface |
| Integration style | Bidirectional envelope translation |
| Classes | `Provider04EnvelopeMapper` ([`envelope_mapper.py`](envelope_mapper.py:44)) |
| Conformance suite | Assessed in `test_provider_04_integration.py` |

## Verdict vocabulary

**None.** This provider does not participate in the active gate evaluation path. It provides structural translation for governance envelopes downstream.

## History

Previously, this package contained a misleading `Provider04AttestationProvider` stub. This was removed in the CAGE Layered Refactoring so that the reference code accurately reflects Archytan's true relationship with CAGE (i.e. as a downstream consumer of structured governance envelopes via the mapper, not an active attestation source).

## Envelope mapper

`Provider04EnvelopeMapper` is a plain class, not a subclass of any protocol
base — the "EnvelopeMapper" role is structural.

| Method | Direction | Behavior |
|---|---|---|
| `to_provider_04_format(envelope)` | CAGE → vendor | Wraps the signed `GovernanceEnvelope` dict under `cage_envelope`, adding `provider_04_version`, `digest`, and a `metadata` block |
| `from_provider_04_format(data)` | Vendor → CAGE | Reconstructs the `GovernanceEnvelope`; raises `ValueError` if `cage_envelope` is missing |

## Configuration

None required. The envelope mapper relies purely on structural data transformation.
