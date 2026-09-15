# Archytan ArbiterKernel Vector Alignment

**Status:** ✅ Complete  
**Date:** 2026-09-15  
**Golden Fixtures:** Byte-exact parity achieved

---

## Executive Summary

Successfully resolved byte-exact canonical JSON fixture discrepancies for Archytan Vector 1 (DIRECT path) and Vector 3 (ESCALATE path), achieving 100% passing tests across envelope builder, adapter, and full test suite.

## Golden Targets (Verified)

### Vector 1 (DIRECT Path)
- **Canonical Length:** 958 bytes
- **SHA-256:** `83398b88482ae07f5ef11a95f7a695849a407da398feef48e4701d9f67c35e6e`
- **Path:** `tests/fixtures/actuator_01/vector1_direct.json`
- **Characteristics:** DIRECT path with no `approval` key (omitted entirely, not null)

### Vector 3 (ESCALATE Path)
- **Canonical Length:** 1523 bytes
- **SHA-256:** `aa10d1f8c0093808be0db3fba8c8787f755c8183ca8ab214fac42aaaadd6c080`
- **Path:** `tests/fixtures/actuator_01/vector3_escalate.json`
- **Characteristics:** ESCALATE path with full WebAuthn attestation block

## Structural Changes

### Envelope Wire Format (Archytan ArbiterKernel Canonical Structure)

The envelope structure was aligned to match the Archytan ArbiterKernel specification:

```json
{
  "action": "payment.wire.execute",
  "authority_ref": {
    "graph_hash": "<64-char-hex>",
    "graph_version": "ag-2026-08-01T00:00:00Z"
  },
  "correlation_id": "<uuid>",
  "envelope_version": "archytan.envelope/v1",
  "governance": {
    "decision": "ALLOW",
    "decision_path": "DIRECT|ESCALATE",
    "decision_signature": "<128-char-hex>",
    "evaluated_at": 1785012000,
    "policy_version": "cage-policy-2.1.1",
    "receipt_hash": "<64-char-hex>",
    "receipt_id": "cage-seal-test-0001",
    "required_quorum": 2
  },
  "issued_at": 1785012000,
  "nonce": "<32-char-hex>",
  "operator_urn": "urn:archytan:op:...",
  "parameters": {
    "amount_minor": 12345,
    "currency": "USD"
  },
  "target": {
    "account_hash": "<64-char-hex>"
  },
  "ttl_seconds": 30
}
```

**ESCALATE path adds:**
```json
{
  "approval": {
    "approver_urn": "urn:archytan:op:...",
    "authenticator_data": "<base64url>",
    "challenge_binding": "<64-char-hex>",
    "client_data_json": "<base64url>",
    "credential_id": "<base64url>",
    "signature": "<base64url>"
  }
}
```

### Key Invariants

1. **DIRECT vs ESCALATE Differentiation:**
   - DIRECT path: `approval` key **omitted entirely** (not `null`)
   - ESCALATE path: `approval` key **present** with full WebAuthn structure

2. **Target Digest Computation:**
   - Target digest is SHA-256 of JCS-canonical target object
   - Used in policy decision signature binding payload

3. **Policy Decision Signature Binding (10-field payload with 0x1F separators):**
   ```
   action || 0x1F || target_digest || 0x1F || correlation_id || 0x1F ||
   decision || 0x1F || decision_path || 0x1F || required_quorum || 0x1F ||
   policy_version || 0x1F || evaluated_at || 0x1F || receipt_id || 0x1F || receipt_hash
   ```

4. **Fail-Closed Key Isolation:**
   - Operator quorum keys (`:op:`) cannot sign policy decisions
   - Policy authority keys (`:policy:`) cannot sign quorum payloads

## Code Changes

### [`src/integrations/actuator_01/envelope_builder.py`](../../src/integrations/actuator_01/envelope_builder.py)

**Updated Functions:**
- `build_envelope_dict()`: Added `receipt_id`, `receipt_hash`, `graph_hash`, `graph_version` parameters
- Root-level structure now matches Archytan wire format (`action`, `parameters`, `target` at root)
- Target object structure: `{"account_hash": "<sha256-of-clearance-target>"}`
- DIRECT path omits `approval` key entirely instead of setting to `null`

### [`tests/test_actuator_01_envelope.py`](../../tests/test_actuator_01_envelope.py)

**Updated Tests:**
- `test_archytan_vector_3_structure()`: Validates root-level keys (`action`, `parameters`, `target`, `authority_ref`)
- `test_governance_block_v3_structure()`: Validates `receipt_id`, `receipt_hash`, `evaluated_at` fields
- `test_approval_key_omitted_when_no_approvals()`: Verifies DIRECT path omits `approval` key
- `test_parameters_from_params_field()`: Validates `parameters` at root level
- Added `TestVector1Golden` class for Vector 1 golden fixture validation

### [`tests/fixtures/actuator_01/vector1_direct.json`](../../tests/fixtures/actuator_01/vector1_direct.json)

Extracted from `docs/partners/vector3_direct_json.pdf` (Archytan ArbiterKernel reference).

### [`tests/fixtures/actuator_01/vector3_escalate.json`](../../tests/fixtures/actuator_01/vector3_escalate.json)

Extracted from `docs/partners/vector3_escalate_json.pdf` (Archytan ArbiterKernel reference).

## Verification Gates (All Passing)

### 1. Golden Fixture Verification
```bash
uv run python3 -c "
import json, hashlib
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
v1 = json.load(open('tests/fixtures/actuator_01/vector1_direct.json'))
v3 = json.load(open('tests/fixtures/actuator_01/vector3_escalate.json'))
assert len(jcs_canonicalize_plan(v1)) == 958
assert hashlib.sha256(jcs_canonicalize_plan(v1)).hexdigest() == '83398b88482ae07f5ef11a95f7a695849a407da398feef48e4701d9f67c35e6e'
assert len(jcs_canonicalize_plan(v3)) == 1523
assert hashlib.sha256(jcs_canonicalize_plan(v3)).hexdigest() == 'aa10d1f8c0093808be0db3fba8c8787f755c8183ca8ab214fac42aaaadd6c080'
print('✓ All golden fixtures verified byte-exact.')
"
```
**Result:** ✅ PASS

### 2. Ruff Linting
```bash
uv run ruff check src/integrations/actuator_01/ tests/test_actuator_01_envelope.py tests/test_actuator_01_adapter.py
```
**Result:** ✅ All checks passed!

### 3. Import Boundary Check (Gate G3)
```bash
uv run python scripts/check_import_boundaries.py
```
**Result:** ✅ All import boundaries respected.

### 4. Actuator Test Suite
```bash
uv run pytest tests/test_actuator_01_envelope.py tests/test_actuator_01_adapter.py -v
```
**Result:** ✅ 75 passed in 27.78s

### 5. Full Test Suite (test-fast)
```bash
make test-fast
```
**Result:** ✅ 4222 passed, 93 skipped in 110.69s

## Source Documents

- **Vector 1 (DIRECT):** `docs/partners/vector3_direct_json.pdf`
- **Vector 3 (ESCALATE):** `docs/partners/vector3_escalate_json.pdf`

Both PDFs generated by `arbiter-kernel/cmd/gen-cage-vectors` from the Archytan ArbiterKernel reference implementation and self-verified through `ArbiterKernel.ServeHTTP`.

## Policy Decision Signature Mechanism

Per Archytan specification (`mechanism_notes.decision_signature`):

```
hex(Ed25519 over "ARCHYTAN_POLICY_DECISION_V1:" || binding)

binding = SHA-256(
  action 0x1f 
  target_digest 0x1f 
  correlation_id 0x1f 
  decision 0x1f 
  decision_path 0x1f 
  required_quorum 0x1f 
  policy_version 0x1f 
  evaluated_at 0x1f 
  receipt_id 0x1f 
  receipt_hash
)
```

- `target_digest` is hex SHA-256 over JCS-canonical target object
- Integers are decimal, unpadded
- Signed by policy authority (must NOT be an operator key)

## Archytan Wire Contract Compliance

| Requirement | Status | Evidence |
|-------------|--------|----------|
| RFC 8785 (JCS) canonicalization | ✅ | `jcs_canonicalize_plan()` produces byte-exact output |
| DIRECT path omits `approval` key | ✅ | Vector 1 has no `approval` key in canonical JSON |
| ESCALATE path includes `approval` | ✅ | Vector 3 includes full WebAuthn `approval` block |
| 10-field policy decision binding | ✅ | `signatures.py::sign_policy_decision()` implements binding |
| Operator/policy key isolation | ✅ | `ValueError` raised if `:op:` key signs policy decision |
| 4KB envelope ceiling | ✅ | `assert_within_ceiling()` enforces 4096-byte limit |
| Fail-closed validation | ✅ | All non-ALLOW decisions rejected before envelope construction |

## Remaining Work

None. All verification gates pass with byte-exact golden fixture parity.

---

**Signed-off:** Autonomous Systems & Integration Engineer  
**Verification Command:**
```bash
uv run python3 -c "import json, hashlib; from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan; v1 = json.load(open('tests/fixtures/actuator_01/vector1_direct.json')); v3 = json.load(open('tests/fixtures/actuator_01/vector3_escalate.json')); print(f'V1: {len(jcs_canonicalize_plan(v1))} bytes, {hashlib.sha256(jcs_canonicalize_plan(v1)).hexdigest()}'); print(f'V3: {len(jcs_canonicalize_plan(v3))} bytes, {hashlib.sha256(jcs_canonicalize_plan(v3)).hexdigest()}')"
```
