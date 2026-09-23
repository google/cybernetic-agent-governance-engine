# Provider 06 — Agent Integrity Verifier (Synchronous Gate, SPIKE)

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint**. Adopters should treat this as an integration
> pattern to adapt, not a hosted service.
>
> **Naming note:** The vendor name for this integration is **Guardian Cyber
> Agent Integrity**. The package path `provider_06` is retained for import
> stability across branches and test fixtures.

| Property | Value |
|---|---|
| Protocol | [`NormativeProvider`](../../gateway/governance/normative_provider.py:273) |
| Integration style | Synchronous verifier, remote HTTP ("sidecar CLI" pattern) with Ed25519 JCS signatures |
| Class | `Provider06AgentIntegrityAdapter` ([`adapter.py`](adapter.py:178)) |
| Status | **SPIKE** — the in-repo endpoint is a mock; the real upstream is vendored at [`third_party/agent-integrity/`](../../../third_party/agent-integrity) |
| Factory names | `provider_06`, aliases `p06`, `agent_integrity`, `agentintegrity` |
| Conformance suite | Registered in `NORMATIVE_PROVIDERS` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py:48)) |
| Protocol version | `1-alpha` (sent as `X-Protocol-Version`) |
| Receipt version | `2-alpha` (Phase 2: cryptographic signatures) |

## Endpoints

Base URL from `CAGE_AGENT_INTEGRITY_ENDPOINT` (no default — unset means every
verification fails closed).

| Method | Path | Protocol method | Returns |
|---|---|---|---|
| `POST` | `/verify` | `validate_fria()` | `ValidationResult` |
| `POST` | `/receipt` | `submit_evidence()` | `EvidenceSeal` (from `receiptDigest`) |
| — | *(none)* | `fetch_baseline()` | Synthesized locally — no network call |

`fetch_baseline()` does not call the vendor. Agent Integrity verifies responses
rather than supplying normative data, so the adapter returns a minimal
`NormativeBaseline` naming itself as the active verifier
([`adapter.py`](adapter.py:231)). Compose with another provider for real
baseline data.

## Verdict vocabulary

`PASS` / `REVIEW` / `BLOCKED` — the `IntegrityStatus` enum at
[`adapter.py:87`](adapter.py:87). Parsed strictly via `IntegrityStatus(...)`,
so matching is **case-sensitive** and an unknown value raises `ValueError`.

The field is **`status`**, inside a response shaped
`{"protocolVersion", "status", "findings"}`.

| `status` | `admitted` | Findings | Effect |
|---|---|---|---|
| `PASS` | `True` | Vendor findings passed through | Proceed |
| `BLOCKED` | `False` | Vendor findings passed through | Hard deny |
| `REVIEW` | `False` | `cage.review_pending` (severity `review`) prepended, then vendor findings | `needs_human_review: True` → parks in `DeferQueue` with `DeferReason.EXTERNAL_VALIDATION` |

The `REVIEW` marker also carries `integrity_status` and nested
`integrity_findings`, recoverable via
[`extract_integrity_status()`](adapter.py:463).

> **`REVIEW` belongs to this provider only.** Provider 01's vocabulary is
> `ALLOW`/`REFUSE`/`ESCALATE` and Provider 03's is
> `APPROVED`/`ESCALATE`/`REJECTED`; neither accepts `REVIEW`. Conflating the
> two tri-states is the most likely integration error here — the CAGE-side
> *effect* of `REVIEW` and `ESCALATE` is identical (`DeferQueue` parking), but
> the accepted wire tokens are not interchangeable.

Finding severities are constrained to `review` and `blocked`
([`FindingSeverity`](adapter.py:92)); an unrecognized severity string fails the
parse.

## Fail-closed behavior

| Condition | Finding code | Severity |
|---|---|---|
| `CAGE_AGENT_INTEGRITY_ENDPOINT` unset | `cage.endpoint_error` | `blocked` |
| Non-2xx status | `cage.endpoint_error` | `blocked` |
| Transport error / timeout | `cage.endpoint_error` | `blocked` |
| Malformed body, unknown `status`, bad severity, missing key | `cage.parse_error` | `blocked` |

`submit_evidence()` is more permissive: it catches broadly and returns an
`EvidenceSeal` with `error` populated.

## Mock endpoint

[`mock_endpoint.py`](mock_endpoint.py) is a FastAPI mock **for local testing
only, explicitly not for production**. Select a fixture with the
`X-Fixture-Name` header — `pass`, `review`, or `blocked` (default `pass`) — and
request bodies are validated against a vendored JSON schema when available.
Run it with:

```
uv run python -m src.integrations.provider_06.mock_endpoint
```

It binds `127.0.0.1:8090` by default. The module degrades gracefully to
`app = None` if FastAPI is not installed.

## Wire contract change in the backward-compatibility remediation

**No wire-contract change to this adapter.** Its tri-state mapping and response
shape are unchanged. Provider 01's mapping was described in its own source as
mirroring this adapter's pattern, but the two vocabularies were never the same
and the remediation did not alter this one.

## Phase 2 Architecture: Cryptographic Receipt Verification

Phase 2 introduces **cryptographic receipt verification** with Ed25519 JCS signatures:

### Trust Model

- **Out-of-band key resolution**: Public keys are resolved from an independent JWKS manifest (`CAGE_AGENT_INTEGRITY_KEY_MANIFEST`), never from the signed receipt payload itself.
- **Trust Anchor Invariant**: Never verify a signature against a public key supplied by the signed document.
- **Receipt structure**: `AlphaIntegrityReceipt` with `receiptDigest` (SHA-256 over JCS-canonicalized payload) and Ed25519 `signature` block.

### Verification Flow

When `submit_evidence()` is called:

1. **Fetch receipt**: Request signed receipt from `/receipt` endpoint
2. **Verify receipt digest**: Compute SHA-256 over JCS-canonicalized receipt (excluding `receiptDigest` and `signature` fields) and compare
3. **Resolve public key**: Fetch Ed25519 public key from JWKS manifest by `signature.keyId`
4. **Verify signature**: Ed25519 signature verification over canonical bytes
5. **Check expiration**: Ensure `now <= expiresAt`
6. **Return seal**: Store `receiptDigest` as seal hash

If any verification step fails, `submit_evidence()` returns an `EvidenceSeal` with `error` populated (fail-closed).

### JWKS Manifest

The key manifest (`CAGE_AGENT_INTEGRITY_KEY_MANIFEST`) supports:

- **HTTP/HTTPS**: Remote JWKS endpoint (e.g., `https://guardian.example.com/.well-known/jwks.json`)
- **file://**: Local manifest for testing (e.g., `file:///path/to/key_manifest.json`)

The manifest follows RFC 7517 JWK format:

```json
{
  "keys": [
    {
      "kid": "test-key-1",
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url-encoded-public-key>"
    }
  ]
}
```

Keys are cached in-memory with TTL (default: 3600s).

### Error Codes (Phase 2)

| Code | Severity | Meaning |
|---|---|---|
| `cage.unknown_key` | `blocked` | Public key not found in JWKS manifest |
| `cage.invalid_signature` | `blocked` | Ed25519 signature verification failed |
| `cage.invalid_digest` | `blocked` | Receipt digest does not match computed SHA-256 |
| `cage.envelope_digest_mismatch` | `blocked` | Envelope digest does not match evidence hash |
| `cage.receipt_expired` | `blocked` | Receipt expired (`now > expiresAt`) |

### Test Key Pair

Phase 2 includes a deterministic test key pair ([`tests/integrations/provider_06/fixtures/test_key_pair.py`](../../../tests/integrations/provider_06/fixtures/test_key_pair.py)):

- **Private key**: Used by [`mock_endpoint.py`](mock_endpoint.py) to sign test receipts
- **Public key**: Exported as JWK in [`key_manifest.json`](../../../tests/integrations/provider_06/fixtures/key_manifest.json)
- **Kid**: `test-key-1`

⚠️ **TEST-ONLY**: The private key is committed to source control and provides zero security. Never use in production.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `CAGE_AGENT_INTEGRITY_ENDPOINT` | Yes | *(none)* | Base URL of Agent Integrity verifier (e.g., `http://localhost:8090`) |
| `CAGE_AGENT_INTEGRITY_PROJECT_ROOT` | No | *(none)* | Trusted project root for source verification |
| `CAGE_AGENT_INTEGRITY_TIMEOUT` | No | `10` | HTTP request timeout in seconds |
| `CAGE_AGENT_INTEGRITY_KEY_MANIFEST` | **Phase 2** | *(none)* | JWKS manifest URL (`http://`, `https://`, or `file://`) for Ed25519 key resolution. If unset, signature verification is skipped. |

**Example (local dev with test key)**:
```bash
CAGE_AGENT_INTEGRITY_ENDPOINT=http://localhost:8090
CAGE_AGENT_INTEGRITY_KEY_MANIFEST=file:///home/user/cage/tests/integrations/provider_06/fixtures/key_manifest.json
CAGE_AGENT_INTEGRITY_TIMEOUT=10
```

## Upstream reference

Vendored protocol and architecture docs:
[`third_party/agent-integrity/docs/PROTOCOL.md`](../../../third_party/agent-integrity/docs/PROTOCOL.md),
[`ARCHITECTURE.md`](../../../third_party/agent-integrity/docs/ARCHITECTURE.md),
[`INTEGRATION_GUIDE.md`](../../../third_party/agent-integrity/docs/INTEGRATION_GUIDE.md).
