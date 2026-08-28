# Security Repair Design

## Status

Approved for implementation on 2026-08-02 following independent adversarial review of commit `8598b60`.

## Goal

Make every advertised integrity guarantee an enforced, adversarially tested invariant. A `PASS` must be impossible when response bytes are uncovered, sources or decisions are self-declared, policy input is malformed or untrusted, or a receipt is forged or replayed.

## Trust model

The application host is trusted. Model output is untrusted. Policies, source files, decision registries, envelopes, receipts, and CLI JSON are untrusted until validated or collected through a trusted host boundary.

The verifier remains deterministic and separate from model reasoning. It does not decide semantic truth. It verifies structural coverage, authenticated inputs, declared evidence relationships, active decision references, and receipt state.

## Protocol changes

- Every response section contains UTF-8 byte offsets and a digest of its exact bytes.
- Sections must cover the complete response exactly once, without gaps or overlap.
- Every non-empty response has at least one section. All sections require at least one claim in the alpha security profile.
- Evidence includes a byte range and digest anchored to a trusted collected source.
- Claims explicitly declare decision IDs; the verifier validates those references but does not infer omitted semantic dependencies.
- The policy is loaded and validated by the host, then identified by a digest; model-supplied policy objects are not authoritative.
- Source records are host-observed and recollected from allowed roots during verification and release.
- Decision events are loaded from the current configured trusted registry; envelope decision snapshots must match it. Cross-run history preservation remains a trusted storage responsibility until authenticated checkpoints exist.

These are breaking alpha changes and will use protocol version `2-alpha`.

## Runtime validation and canonicalization

All public entry points use one exact-key runtime schema. Unknown fields, accessors, class instances, dangerous object keys, oversized collections, excessive nesting, invalid enums, and non-finite values fail closed.

Canonicalization uses an RFC 8785-compatible JSON canonicalization implementation or an explicitly documented strict profile. Adversarial conformance covers `__proto__`, `constructor`, `prototype`, Unicode, number edge cases, and deep input limits.

## Verification flow

1. Parse and validate the trusted YAML policy.
2. Validate the untrusted envelope against the strict protocol schema and resource limits.
3. Verify complete response-byte coverage and section digests.
4. Recollect each source from allowed roots and compare path, size, and digest.
5. Verify evidence anchors against recollected source bytes.
6. Load the trusted decision registry and reduce its lifecycle.
7. Verify each claim's decision references resolve to active decisions.
8. Check claim/evidence structural rules and contradiction disclosure.
9. Produce `PASS`, `REVIEW`, or `BLOCKED` and bind the result to canonical digests of trusted inputs.

## Receipts

Receipts are producer-authenticated records, not self-digested trust artifacts. They bind protocol version, engine version, issuer, audience, purpose, policy digest, envelope digest, nonce, creation/expiry, outcome, and key ID. Ed25519 signs the canonical receipt body.

Release/recheck requires a trusted key set and an atomic persistent receipt registry. Single-use receipts transition from `issued` to `consumed` exactly once. Reuse, wrong audience/purpose, unknown/revoked key, future issuance beyond clock skew, excessive lifetime, mutation, expiry, or changed live inputs blocks.

## Failure behavior

Malformed or unverifiable input always fails closed. Checker exceptions never release content. `REVIEW` and `BLOCKED` release nothing. Receipt/store partial failures must be recoverable and must not orphan run IDs.

## Testing and release gate

Each adversarial finding becomes a regression test before its fix. Tests cover empty/partial/overlapping response coverage, fabricated sources, source mutation, policy bypass, omitted/stale decisions, canonical collisions, concurrent receipt consumption, copied receipts, future timestamps, resource exhaustion, and filesystem races where the platform permits.

Documentation is rewritten only after implementation invariants pass. A second independent read-only adversarial review is mandatory before public release.
