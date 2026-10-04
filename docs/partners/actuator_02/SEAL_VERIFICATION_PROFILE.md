# Seal Verification Profile `cage-seal/1` — NVIDIA OpenShell Supervisor (actuator_02)

> **Status: default and only profile for actuator_02.** actuator_02 has never
> been deployed against a live OpenShell Supervisor, so there is no earlier
> wire format to stay compatible with. Every actuation CAGE sends to the
> Supervisor follows this profile. The CAGE side (sending the seal) is
> implemented in
> [`adapter.py`](../../../src/integrations/actuator_02/adapter.py). The
> Supervisor side (verifying it, section 4) is the partner's to implement and
> **is not yet implemented upstream**.

## 1. Why the Supervisor verifies the seal

CAGE already authorises every actuation before dispatch: the domain tool
calls [`verify_and_consume_seal()`](../../../src/gateway/governance/routing_seal.py),
which verifies the seal and burns its single-use nonce, and only then
dispatches through `ActuatorRegistry`. The OpenShell assertion
(`X-CAGE-OpenShell-Assertion`) proves that the CAGE gateway sent the request.

The seal adds a second, independent proof: the **governor** authorised this
exact `(action, params)`, under a key the Supervisor resolves itself. A
Supervisor that verifies the seal refuses an actuation even if the transport
credential or the assertion signer were compromised.

## 2. What CAGE sends

`POST {ACTUATOR_02_ENDPOINT}/v1/supervisor/actuate`

| Item | Value |
|---|---|
| Body | RFC 8785 (JCS) bytes of the `ExecutionClearance` envelope. It includes `action` and `params`; the seal is **not** in the body. |
| `X-CAGE-Envelope-Digest` | Lowercase hex SHA-256 of the body |
| `X-CAGE-OpenShell-Assertion` | base64url signature over `CAGE_OPENSHELL_ASSERTION_V1:` + body |
| `X-CAGE-Routing-Seal` | The routing seal: a compact JWS (section 3) |
| `X-CAGE-Seal-Profile` | `cage-seal/1` |
| `X-CAGE-Correlation-ID` | The clearance correlation id |

The adapter refuses before the wire (outcome `REJECTED`, nothing brokered,
nothing sent) when:

- the clearance has no seal: finding `ROUTING_SEAL_MISSING`;
- the seal is not a compact JWS: finding `ROUTING_SEAL_NOT_JWS`. This covers
  HMAC (v2) seals, which use a symmetric key the Supervisor does not hold.

Brokered credential headers cannot set or shadow any `X-CAGE-*` header.

The seal travels on the dedicated
[`ExecutionClearance.routing_seal`](../../../src/gateway/governance/seams/actuation.py)
field. It is excluded from `to_dict()`, so it is never part of the envelope
body or its digest, and the `params` the Supervisor hashes are exactly the
`params` the governor sealed.

## 3. Seal format

JWS compact serialization, signed by the gateway's governance signer (KMS in
production).

**Header:** `alg` (`ES256`/`ES384`/`ES512` for EC keys, `EdDSA` for OKP keys),
`typ: "JWT"`, `kid`.

**Claims:**

| Claim | Meaning |
|---|---|
| `action_hash` | Lowercase hex `sha256(JCS({"action": <action>, "params": <params>}))` |
| `canon` | `"cage-action/1"`: identifies the `action_hash` recipe above |
| `record_hash` | Hash of the evidence record committed before issuance |
| `nonce` | Single-use identifier |
| `iat`, `exp` | Issued-at and expiry (Unix seconds); lifetime defaults to 30 s (`GOVERNANCE_SEAL_TTL_S`) |
| `iss` | `"cage-gateway"` |
| `aud` | `"cage-actuator:<action>"` unless issued for an explicit audience |

`params` are restricted to I-JSON values (RFC 7493): strings, booleans,
`null`, finite numbers, integers within ±(2⁵³−1), arrays and string-keyed
objects. CAGE refuses to mint a seal for anything else, so the hash never
depends on a language-specific rendering such as Python's `str()`.

## 4. Supervisor verification procedure

Fail closed: any failed step refuses the actuation with a definitive refusal
status (`401`/`403`/`409`/`422`), which CAGE records as `REJECTED`.

1. Require `X-CAGE-Seal-Profile: cage-seal/1`. Refuse unknown profiles.
2. Verify the body against `X-CAGE-Envelope-Digest` and the assertion, as today.
3. Parse `X-CAGE-Routing-Seal` as a compact JWS. Read `kid` from the header.
4. Resolve the public key **by `kid`** from the gateway JWK Set
   (`GET <gateway>/.well-known/jwks.json`). Fetch and cache it out of band;
   never use a key carried in the token. An unknown `kid` is a refusal. You
   may refetch once on an unknown `kid`, rate-limited.
5. Verify the signature with an algorithm allow-list chosen by key type
   (EC: `ES256`/`ES384`/`ES512`; OKP: `EdDSA`). Never take the algorithm
   from the token header alone, and never accept `none` or HMAC algorithms.
6. Check `exp` (allow at most a few seconds of clock skew),
   `iss == "cage-gateway"`, and `aud == "cage-actuator:" + envelope.action`.
7. Require `canon == "cage-action/1"`.
8. Recompute `sha256(JCS({"action": envelope.action, "params": envelope.params}))`
   from the received body and compare it with `action_hash` in constant time.
9. Require `record_hash` to be present and not one of `""`, `"none"`,
   `"null"`, `"no-evidence-binding"`.
10. Enforce single use: record `nonce` in a replay cache that holds each entry
    until at least `exp`, and refuse a nonce already present.

A reference for steps 4–8 in Python is the test
`TestSealProfile.test_supervisor_can_verify_seal_from_wire_bytes_alone` in
[`test_actuator_02.py`](../../../src/integrations/actuator_02/tests/test_actuator_02.py).
Any RFC 8785 implementation produces the same `action_hash`.

## 5. Revocation

CAGE can revoke an unconsumed seal before it expires
([`revoke_seal()`](../../../src/gateway/governance/routing_seal.py)). Revocation
is enforced at CAGE's own consume boundary: a revoked seal fails
`verify_and_consume_seal()`, so it is never dispatched to the Supervisor.

This profile defines **no revocation status endpoint** for the Supervisor to
query. A seal reaches the Supervisor only after CAGE has consumed it, and a
consumed seal can no longer be revoked. Seals expire after 30 seconds by
default, and the Supervisor's nonce cache (step 10) stops a consumed seal
being replayed within that window.

## 6. What this profile does not claim

- The Supervisor-side checks in section 4 are a specification. Upstream
  OpenShell does not implement them yet, and no live conformance test has
  run. Until a Supervisor verifies seals, the guarantee rests on CAGE's
  pre-dispatch consume, the mTLS channel and the assertion signature.
- HMAC (v2) seals are development-posture only and cannot be verified by a
  partner. actuator_02 therefore needs a JWT-issuing (KMS) signer.
- Per the over-the-wire conformance mandate in `AGENTS.md`, the hermetic
  tests in `test_actuator_02.py` cover CAGE-side behaviour only. Partner
  conformance must be shown against a live or sandbox Supervisor.
