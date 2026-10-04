# Actuator 01 — Downstream Execution Actuator

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Integrations are numbered and anonymized, and this integration
> has **no configured live endpoint**. Adopters should treat this as an
> integration pattern to adapt, not a hosted service.
>
> **Naming & Partner Note:** **Archytan** is the reference downstream
> execution actuator integration partner for CAGE. The package path
> `actuator_01` is retained for import stability across branches and test
> fixtures.


| Property | Value |
|---|---|
| Protocol | [`ExecutionActuator`](../../gateway/governance/execution_actuator.py:24) |
| Integration style | Synchronous execution clearance submission over mTLS |
| Class | `Actuator01Adapter` ([`adapter.py`](adapter.py:97)) |
| Status | `INTERFACE READY` — HTTP client fully implemented; no endpoint configured |
| Factory names | `actuator_01` |

## Protocol Implementation

This adapter implements the [`ExecutionActuator`](../../gateway/governance/execution_actuator.py:24)
protocol, orchestrating the full pipeline from `ExecutionClearance` to
`ActuationReceipt`:

```
ExecutionClearance
    → validate + build envelope (envelope_builder)
    → canonicalize per RFC 8785 (JCS)
    → enforce 4KB ceiling
    → compute digest
    → build 120-byte assertion (assertion)
    → sign for quorum (signatures)
    → submit over mTLS (client)
    → classify response (response_classifier)
    → ActuationReceipt
```

Fail-closed: any step that fails produces `accepted=False` with structured
findings. Network timeouts, HTTP errors, and parse failures never produce a
silent success.

## Declared Capabilities

The adapter declares four [`ActuatorCapability`](../../gateway/governance/execution_actuator.py:16) flags:

| Capability | Meaning |
|---|---|
| `MULTI_SIG_QUORUM` | Clearances are signed by multiple operators (quorum requirement) |
| `MTLS_REQUIRED` | Transport requires mutual TLS authentication |
| `DIGEST_ONLY_PAYLOAD` | The wire protocol transmits action digest only, not full payload |
| `REPLAY_PROTECTED` | Clearances carry nonces and timestamps to prevent replay attacks |

These capabilities are queried via `get_capabilities()` and inform the
governance harness about the security properties of the actuator.

## Wire Protocol

### Authentication

mTLS is mandatory. The adapter requires three PEM files configured via
environment variables:

- `ACTUATOR_01_CERT_PATH` — Client certificate
- `ACTUATOR_01_KEY_PATH` — Client private key
- `ACTUATOR_01_CA_PATH` — CA bundle for server verification

### Headers

| Header | Value | Purpose |
|---|---|---|
| `X-Tenant-ID` | From `ACTUATOR_01_TENANT_ID` | Secure tenant identifier |
| `X-Archytan-Signatures` | Quorum signature array | Per-operator signature over the 120-byte assertion |
| `Content-Type` | `application/json` | Envelope payload |

**Note:** The header name `X-Archytan-Signatures` and the domain tags
`ARCHYTAN_ASSERTION_V1:` (assertion signing) and `ARCHYTAN_QUORUM_V1:`
(quorum signing) embedded in wire signatures are load-bearing in the
wire protocol. This makes vendor anonymization unavailable for this partner
without a coordinated protocol change. See
[`docs/meetings/luis_actuator_01_response.md`](../../../docs/meetings/luis_actuator_01_response.md)
for wire-protocol collaboration history.

### Envelope Structure

The envelope is JCS-canonicalized (RFC 8785) and capped at 4KB. It carries:

- `clearance_id` — Unique clearance identifier
- `thread_id` — Governance thread identifier
- `action` — The governed action name
- `magnitude` — Action consequence magnitude
- `context` — Domain context (e.g., instrument symbol, patient ID)
- `operator_urns` — List of approving operator URNs
- `timestamp_utc` — ISO 8601 timestamp
- `nonce` — Replay protection nonce

The adapter computes a SHA-256 digest over the canonicalized envelope and
builds a 120-byte assertion for signing.

## Health Check

`health_check()` returns `False` (fail-closed) when:

- mTLS material is unreadable
- The endpoint is unreachable
- **KMS is not active** (checked via `self._signer.is_kms_active`)

This ensures that actuator health is coupled to the availability of the signing
infrastructure, preventing unsigned clearances from being submitted.

## Constructor (Post-C5 Abstraction)

The adapter constructor accepts an **injected signer abstraction** rather than
a concrete KMS implementation:

```python
def __init__(
    self,
    client: ActuatorHttpClient,
    signer: RawMessageSigner,
    signer_resolver: SignerResolver | None = None,
) -> None:
```

**Parameters:**

- `client` — Pre-configured `ActuatorHttpClient` with mTLS credentials
- `signer` — `RawMessageSigner` protocol instance for assertion and default quorum signing
- `signer_resolver` — Optional callable `(operator_urn: str) -> RawMessageSigner`
  for per-operator signing keys. If `None`, defaults to `signer` for all operators.

This design allows the adapter to remain vendor-neutral with respect to signing
infrastructure — it can use KMS, HSM, or any other implementation of the
`RawMessageSigner` protocol.

### Factory Method

For convenience, `from_env()` constructs the adapter from environment variables:

```python
actuator = Actuator01Adapter.from_env(
    signer=my_kms_signer,
    signer_resolver=my_resolver,  # Optional
)
```

## Configuration

All configuration is sourced from environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `ACTUATOR_01_ENDPOINT` | Yes | Base URL (e.g., `https://actuator.example.com`) |
| `ACTUATOR_01_CERT_PATH` | Yes | Client certificate PEM path |
| `ACTUATOR_01_KEY_PATH` | Yes | Client private key PEM path |
| `ACTUATOR_01_CA_PATH` | Yes | CA bundle PEM path |
| `ACTUATOR_01_TENANT_ID` | Yes | Secure tenant identifier |
| `ACTUATOR_01_RECEIPT_KEY_MANIFEST_URL` | No | `https://` (or `file://`) URL of the partner's Ed25519 receipt key manifest (JWKS) |
| `ACTUATOR_01_REQUIRE_SIGNED_RECEIPTS` | No | `1`/`true`/`yes`: treat unsigned or unverifiable receipts as `UNKNOWN` (requires the manifest URL) |

Missing any required variable causes `from_env()` to raise `RuntimeError` with
a list of missing keys.

## Signed Receipts (CAGE-proposed extension)

The partner contract does not yet define receipt signatures; this is a
CAGE-proposed wire extension pending partner adoption and over-the-wire
conformance testing. A response body MAY carry a detached Ed25519 signature:

```json
{"status": "accepted", "envelope_digest": "<sha256 hex>", "...": "...",
 "signature": {"alg": "EdDSA", "kid": "<key id>", "value": "<base64url>"}}
```

The signed message is `CAGE_ACTUATION_RECEIPT_V1:` followed by the RFC 8785
(JCS) canonical form of the body without `signature`
([`RECEIPT_SIGNATURE_DOMAIN_TAG`](constants.py)). [`verify_partner_receipt()`](receipt_verifier.py)
resolves the public key **only by `kid`** from the independently fetched
manifest, never from the receipt, and never raises:

| Condition | `verification` | Effect on outcome |
|---|---|---|
| Valid signature, signed `envelope_digest` matches ours | `VERIFIED` | Unchanged |
| No signature, or manifest unconfigured/unreachable | `UNVERIFIED` | Unchanged (strict mode: `UNKNOWN`, finding `RECEIPT_UNVERIFIED`) |
| Malformed signature, unknown `kid`, bad signature, digest mismatch | `INVALID` | Forced to `UNKNOWN` |

An unauthenticated accept or reject cannot settle the action, so it is treated
as indeterminate. When a manifest is configured the adapter advertises
`ActuatorCapability.SIGNED_RECEIPTS`.

## Fail-Closed Behavior

Every failure produces `ActuationReceipt(accepted=False)` with structured
findings and a three-valued `outcome`:

| Condition | Finding code | Outcome |
|---|---|---|
| Executor / route / credential gate failure | `EXECUTOR_ID_MISMATCH`, `TARGET_ROUTE_MISMATCH`, `CREDENTIAL_BROKER_FAILED` | `REJECTED` (never sent) |
| Invalid clearance, oversize envelope, assertion or quorum failure | `INVALID_CLEARANCE`, `ENVELOPE_TOO_LARGE`, `ASSERTION_BUILD_FAILED`, `QUORUM_SIGNING_FAILED` | `REJECTED` (never sent) |
| Transport error before the request left the client | network findings | `REJECTED` (retryable) |
| Transport error after send, unexpected error | network findings, `UNEXPECTED_ERROR` | `UNKNOWN` |
| Definitive refusal status from the partner | HTTP findings | `REJECTED` |
| Any other non-accepted response | HTTP / parse findings | `UNKNOWN` |
| Invalid receipt signature | `RECEIPT_*` | `UNKNOWN` |

The adapter never returns `accepted=True` on an ambiguous outcome, and it
never writes evidence itself: the kernel
`dispatch_actuation()` (`src/gateway/governance/execution_actuator.py`) records
each receipt exactly once.

## Vendor Isolation

This package lives in `src/integrations/` (Layer 3) and must not be imported by
the CAGE kernel. It is lazy-loaded by the governance harness through the
`ExecutionActuator` protocol seam.
