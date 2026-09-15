# Actuator 01 Golden Test Fixtures

This directory contains canonical test vectors for the Actuator 01 integration, used to validate wire protocol compliance, signature verification, and digest stability.

## Canonical Test Vectors

### Vector 1: DIRECT Path (No Approval)
- **File**: `vector1_direct.json`
- **Canonical Byte Length**: 958 bytes
- **SHA-256 Digest**: `83398b88482ae07f5ef11a95f7a695849a407da398feef48e4701d9f67c35e6e`
- **Decision Path**: `DIRECT`
- **Approval Block**: None (DIRECT path does not require human-in-the-loop approval)

**Root-Level Fields**:
- `action`, `parameters`, `target`, `operator_urn`, `authority_ref`
- `receipt_id`, `receipt_hash`, `policy_version`
- `thread_id`, `decision`, `decision_path`, `issued_at`, `correlation_id`
- `governance_decision_digest`, `opa_input_digest`, `nonce`
- **NO** `approval` key (DIRECT path)

### Vector 3: ESCALATE Path (With Approval)
- **File**: `vector3_escalate.json`
- **Canonical Byte Length**: 1523 bytes
- **SHA-256 Digest**: `aa10d1f8c0093808be0db3fba8c8787f755c8183ca8ab214fac42aaaadd6c080`
- **Decision Path**: `ESCALATE`
- **Approval Block**: Present (hardware-backed WebAuthn credential)

**Root-Level Fields**:
- All fields from Vector 1, PLUS:
- `approval` object containing:
  - `approver_urn`: URN of the approving operator
  - `approved_at`: Unix timestamp of approval
  - `credential_id`: Hardware credential identifier
  - `client_data_json`: Base64-encoded WebAuthn client data
  - `authenticator_data`: Base64-encoded authenticator assertion
  - `challenge_binding`: Deterministic policy seed binding
  - `signature`: ECDSA signature over the approval context

## Deterministic Policy Seed

**Canonical Seed**: `0707070707070707070707070707070707070707070707070707070707070707` (64 hex chars, 32 bytes)

This seed is used as the `challenge_binding` in Vector 3 and serves as a deterministic anchor for signature verification tests. In production, this would be a cryptographically random nonce; in tests, it's a fixed value to ensure reproducible digests.

## Public Key for Signature Verification

**Algorithm**: ECDSA over secp256r1 (P-256)  
**Public Key (PEM)**:
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE... (placeholder for actual key)
-----END PUBLIC KEY-----
```

**Note**: In the current phase, signature verification is mocked. The production key will be provisioned when hardware credential infrastructure is deployed.

## Usage in Tests

These fixtures are used by:
- `tests/test_actuator_01_adapter.py` — Wire protocol compliance
- `tests/test_actuator_01_signature.py` — Cryptographic verification (future)
- `tests/test_execution_clearance_mapping.py` — CAGE → Actuator 01 mapping

### Verifying Digest Stability

```bash
# Vector 1 digest
sha256sum tests/fixtures/actuator_01/vector1_direct.json
# Expected: 83398b88482ae07f5ef11a95f7a695849a407da398feef48e4701d9f67c35e6e

# Vector 3 digest
sha256sum tests/fixtures/actuator_01/vector3_escalate.json
# Expected: aa10d1f8c0093808be0db3fba8c8787f755c8183ca8ab214fac42aaaadd6c080
```

### JSON Validity

```bash
uv run python -c "import json; json.load(open('tests/fixtures/actuator_01/vector1_direct.json'))"
uv run python -c "import json; json.load(open('tests/fixtures/actuator_01/vector3_escalate.json'))"
```

## Changelog

- **2026-09-15**: Initial golden fixtures created (Phase 1: Archytan Wire Realignment)
