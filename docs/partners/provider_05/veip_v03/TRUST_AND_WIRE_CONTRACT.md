# VEIP v0.3 — proposed wire contract for Lars's review
Status: PROPOSED / NOT FROZEN / NOT DEPLOYED. All schemas in this package are candidate interfaces, not claims of compatibility with current CAGE provider models.

## Trust separation
Use existing out-of-band sandbox root `veip-sandbox-manifest-root-2026-10`, fingerprint `sha256:61ab867fc9ce773f2974081effbf0c9a4173caa23a4e18fa2c3bf65b249b8d85`.
Separate issuer keys and manifest-bound key purposes for WARRANT, BLUEPRINT, KEY, PHYSICS. Distinct `kid`, cryptographic keypair and `purpose` per class. No cross-class acceptance even when signatures verify. No private keys distributed.
Manifest extension proposed: add purpose binding per key; this is a BREAKING change relative to v0.2 key-manifest schema and requires Lars's approval of a v0.3 schema before deployment.

## Signing
Proposed digest = SHA-256 of RFC 8785 JCS serialization of payload excluding `digest` and `signature`; signature = Ed25519 over the canonical payload INCLUDING digest, excluding signature. Exact signing preimage requires agreement against the existing v0.2 implementation before freeze. Base64url unpadded signature. Validate canonical bytes, digest, signature, purpose, status, scope, clock and revocation.

## Currentness
UTC ISO 8601; valid_from <= evaluation_time <= valid_until; state_as_of not in future; propose maximum age 60 seconds matching v0.2 warrant precedent, subject to CAGE provider-specific review. Evaluation clock must be pinned in tests; live clock in runtime.

## Proposed routes (not deployed)
GET /v0.3/blueprint/{artifact_id}
GET /v0.3/key/{artifact_id}
GET /v0.3/physics/{artifact_id}
GET /v0.3/warrants/{warrant_id}?scenario=...
GET /.well-known/veip/key-manifest-v0.3.json
Return 404 on absent artifact; malformed / invalid signatures MUST NOT be treated as admissible. Gateway status mapping for three new classes awaits CAGE-side review.

## Open review questions
1. Confirm field-level compatibility with Provider05BlueprintProvider, Provider05KeyProvider, Provider05PhysicsProvider.
2. Confirm signing preimage and whether existing manifest schema should be versioned.
3. Confirm three evidence-class semantics, domain fields, time windows and CAGE failure mappings.
4. Confirm post-HITL retained transition expected state and context; proposed ELIGIBLE requires an unchanged valid warrant and renewed verification, not automatic retention.
5. Confirm whether UNRESOLVED means missing state-resolution evidence, distinct from SUSPENDED or authenticity failure.
