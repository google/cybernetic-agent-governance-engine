# TEST_INFRA.md — CAGE × KillSwitch Live Substrate Test Infrastructure Specification

**Document Version**: 1.0.0  
**Status**: APPROVED SPECIFICATION  
**Target Milestone**: M4 (Live Over-The-Wire Integration & Conformance Test Suite)  
**Security Classification**: High-Assurance Defense-Grade Reference Architecture  
**Target Repositories**:
- `d:\harfile\cybernetic-agent-governance-engine` (branch `feat/host-kernel-actuator`)
- `D:\harfile\killswitch` (branch `feat/cage-substrate-hardening`)

---

## 1. Architectural Philosophy & Core Invariants

The CAGE (Cybernetic AI Governance Engine) × KillSwitch integration enforces host OS kernel containment, hardware TPM 2.0 attestation, and conformal normative baselines across autonomous agent workloads. 

### 1.1 Over-The-Wire Conformance Mandate (Zero Mocks)
Per CAGE `AGENTS.md` and the approved A+ Integration Plan, **Tier 1 partner and external substrate integrations must run over physical loopback TCP/TLS wire against live running binaries. In-memory stubs, synthetic HTTP mocks, and monkeypatched client transports are strictly prohibited for integration verification.**
Every test in this suite interacts with real compiled `killswitch-server` instances executing in separate operating system processes, communicating over loopback TCP sockets (`127.0.0.1:<ephemeral_port>`).

### 1.2 Core Security & Protocol Invariants
1. **Out-of-Band Trust Anchors (`kid` Resolution)**: Never verify signatures against embedded public keys. The client fetches the server's Ed25519 public key via `GET /.well-known/jwks.json` and verifies detached signatures by resolving the key ID (`kid`). The server validates client directives against a pre-configured key manifest (`CAGE_TRUSTED_JWKS_JSON` / `CAGE_TRUSTED_JWKS_PATH`).
2. **Bit-Exact RFC 8785 JSON Canonicalization Scheme (JCS)**: Preimages for signatures are strictly constructed by prepending a domain separation prefix to the RFC 8785 JCS canonicalized JSON bytes. Keys are sorted lexicographically by UTF-16 code points, numbers format without whitespace or exponent if within safe range, and floating-point saturation at $2^{63}$ is handled via high-precision arithmetic.
3. **Single-Use Anti-Replay Nonce Cache**: All mutating directives (`quarantine`, `release`, and conformal `validate`) require a unique `nonce`. The server enforces a memory-bounded sliding-window replay cache (default TTL 300s); any duplicate nonce is rejected immediately with HTTP 409 Conflict (`REPLAY_DETECTED`).
4. **Monotonic Generation Epoch Autotomy (`Gen N -> Gen N+1`)**: Workloads carry a monotonic generation counter. Upon verified multi-operator release (`quorum_count >= 2`), the host kernel advances the epoch `N -> N+1`. Any agent handle, token, or warrant bearing an older epoch is rejected fail-closed across all gateway boundaries (`/governance/*`, `/mcp`, `/tools/execute`).
5. **Crash-Safe Sealed Journal Persistence**: Active quarantine leases, workload generation epochs, and sliding-window CBF dose states are atomically persisted to disk under `KILLSWITCH_STATE_DIR` and signed with an Ed25519 seal (`CAGE_JOURNAL_SEAL_V1:`). On process restart, unexpired leases are automatically restored and re-enforced at the kernel layer.
6. **Mathematical IP & SSRF Defense**: Clients strictly parse destination addresses mathematically into `IPv4Address` / `IPv6Address` structures, blocking link-local/cloud metadata (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), decimal, octal, hex, and IPv4-mapped IPv6 bypasses.

---

## 2. Substrate Endpoints Wire Contract Specification

The host substrate daemon (`killswitch-server`) exposes 6 dedicated CAGE endpoints mounted at both root `/` and `/api/` prefixes.

### Endpoint 1: `GET /.well-known/jwks.json`
- **Purpose**: Exposes the substrate's active Ed25519 signing key in RFC 8037 format.
- **Request Headers**: None.
- **Request Body**: None.
- **Response Headers**: `Content-Type: application/json`.
- **Response Status**: `200 OK`.
- **Response Schema**:
  ```json
  {
    "keys": [
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": "<64-hex SHA-256 of 32-byte public key>",
        "x": "<base64url unpadded 32-byte public key>",
        "use": "sig",
        "alg": "EdDSA"
      }
    ]
  }
  ```

### Endpoint 2: `POST /v1/cage/quarantine`
- **Purpose**: Engages host OS kernel network blackholing (Windows WFP / Linux Netlink / macOS PF) and suspends target process PID.
- **Request Headers**:
  - `Content-Type: application/json`
  - `X-CAGE-Quarantine-Assertion: <base64url unpadded Ed25519 signature>`
  - `X-CAGE-Signer-Kid: <key id registered in CAGE_TRUSTED_JWKS>`
  - `X-CAGE-Envelope-Digest: <64-hex sha256(JCS(body))>` (optional in transit, verified by client)
  - `X-CAGE-Correlation-ID: <uuid or string>`
- **Signature Preimage**: `CAGE_QUARANTINE_ASSERTION_V1:<RFC 8785 JCS(request_body)>`
- **Request Body**:
  ```json
  {
    "workload_id": "spiffe://cluster.local/ns/default/sa/agent-alpha",
    "target_pid": 12345,
    "source_rule_id": "RULE-SC-7-CBF-LETHAL",
    "trigger_reason": "CBF lethal barrier violation detected by CAGE kernel",
    "enforcement_plane": "HOST_OS_KERNEL",
    "refusal_proof_hash": "a1b2c3d4e5f6...",
    "nonce": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp_utc": "2026-11-03T05:00:00Z"
  }
  ```
- **Response Status**: `200 OK` (or `400`, `401`, `403`, `409`).
- **Response Preimage**: `CAGE_QUARANTINE_RECEIPT_V1:<RFC 8785 JCS(unsigned_response_body)>`
- **Response Schema**:
  ```json
  {
    "status": "QUARANTINED",
    "quarantined": true,
    "enforcement_plane": "HOST_OS_KERNEL",
    "rule_id": "RULE-SC-7-CBF-LETHAL",
    "quarantined_at": "2026-11-03T05:00:01Z",
    "target_pid": 12345,
    "envelope_digest": "<64-hex sha256(JCS(request_body))>",
    "kid": "<server_ed25519_kid>",
    "signature": "<base64url unpadded Ed25519 signature over receipt preimage>"
  }
  ```

### Endpoint 3: `GET /v1/cage/attest`
- **Purpose**: Gathers hardware TPM 2.0 PCR 0..7 quote and Ring-0 driver isolation posture.
- **Request Headers**: None.
- **Response Status**: `200 OK`.
- **Response Preimage**: `CAGE_ATTESTATION_RECEIPT_V1:<RFC 8785 JCS(unsigned_response_body)>`
- **Response Schema**:
  ```json
  {
    "attestation_type": "HOST_TPM_PCR",
    "ring0_posture": "ACTIVE_WFP_FILTERED",
    "tpm_pcr_quote": "<64-hex SHA-256 PCR quote>",
    "pcr_values": {
      "0": "<64-hex SHA-256 PCR 0>",
      "1": "<64-hex SHA-256 PCR 1>",
      "7": "<64-hex SHA-256 PCR 7>"
    },
    "timestamp_utc": "2026-11-03T05:00:00Z",
    "kid": "<server_ed25519_kid>",
    "signature": "<base64url unpadded Ed25519 signature over receipt preimage>"
  }
  ```

### Endpoint 4: `POST /v1/cage/release`
- **Purpose**: Verifies multi-operator quorum approval digest (`quorum_count >= 2`), advances workload epoch `Gen N -> Gen N+1`, lifts host kernel isolation, resumes suspended processes, and updates sealed journal.
- **Request Headers**:
  - `Content-Type: application/json`
  - `X-CAGE-Quarantine-Release: <base64url unpadded Ed25519 signature>`
  - `X-CAGE-Signer-Kid: <key id registered in CAGE_TRUSTED_JWKS>`
  - `X-CAGE-Envelope-Digest: <64-hex sha256(JCS(body))>`
- **Signature Preimage**: `CAGE_QUARANTINE_RELEASE_V1:<RFC 8785 JCS(request_body)>`
- **Request Body**:
  ```json
  {
    "workload_id": "spiffe://cluster.local/ns/default/sa/agent-alpha",
    "quorum_approval_digest": "<64-hex SHA-256 digest of operator signatures>",
    "quorum_count": 2,
    "nonce": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "timestamp_utc": "2026-11-03T05:10:00Z"
  }
  ```
- **Response Status**: `200 OK` (or `400`, `401`, `403`, `409`).
- **Response Preimage**: `CAGE_QUARANTINE_RELEASE_RECEIPT_V1:<RFC 8785 JCS(unsigned_response_body)>`
- **Response Schema**:
  ```json
  {
    "released": true,
    "enforcement_plane": "HOST_OS_KERNEL",
    "epoch_before": 1,
    "epoch_after": 2,
    "outcome": "RELEASED",
    "released_at": "2026-11-03T05:10:01Z",
    "envelope_digest": "<64-hex sha256(JCS(request_body))>",
    "kid": "<server_ed25519_kid>",
    "signature": "<base64url unpadded Ed25519 signature over release receipt preimage>"
  }
  ```

### Endpoint 5: `GET /v1/cage/normative-baseline/{region}`
- **Purpose**: Provides region-specific calibrated nonconformity baseline parameters.
- **Path Parameter**: `region` (e.g. `europe-west1`, `us-central1`, `asia-southeast1`).
- **Response Status**: `200 OK`.
- **Response Preimage**: `CAGE_CONFORMAL_BASELINE_V1:<RFC 8785 JCS(unsigned_response_body)>`
- **Response Schema**:
  ```json
  {
    "region": "europe-west1",
    "alpha": 0.05,
    "calibration_size": 500,
    "nonconformity_threshold": 4.25,
    "timestamp_utc": "2026-11-03T05:00:00Z",
    "kid": "<server_ed25519_kid>",
    "signature": "<base64url unpadded Ed25519 signature over baseline preimage>"
  }
  ```

### Endpoint 6: `POST /v1/cage/conformal/validate`
- **Purpose**: Computes calibrated Mahalanobis nonconformity $p$-value and multi-voter consensus for candidate actions.
- **Request Headers**: `Content-Type: application/json`.
- **Request Body**:
  ```json
  {
    "scores": [0.35, 0.42, 0.18, 0.29],
    "alpha": 0.05,
    "action": "execute_wire_transfer",
    "nonce": "7c9e6679-7425-40de-944b-e07fc1f90ae7"
  }
  ```
- **Response Status**: `200 OK` (or `400`, `409`).
- **Response Preimage**: `CAGE_CONFORMAL_VALIDATION_V1:<RFC 8785 JCS(unsigned_response_body)>`
- **Response Schema**:
  ```json
  {
    "admitted": true,
    "p_value": 0.3842,
    "alpha": 0.05,
    "voter_consensus": "CONSENSUS_ALLOW",
    "timestamp_utc": "2026-11-03T05:00:01Z",
    "kid": "<server_ed25519_kid>",
    "signature": "<base64url unpadded Ed25519 signature over validation preimage>"
  }
  ```

---

## 3. The 4-Tier Opaque-Box Test Plan Matrix

### Tier 1: Feature Coverage (>=5 Test Cases Per Endpoint)
*Goal: 100% happy-path verification of every substrate capability over live loopback HTTP wire.*

| Test ID | Endpoint | Description | Verification Criterion |
|---|---|---|---|
| **T1.1.1** | `GET /.well-known/jwks.json` | Live JWKS fetch over loopback | HTTP 200, `Content-Type: application/json`, non-empty `keys` array |
| **T1.1.2** | `GET /.well-known/jwks.json` | RFC 8037 schema conformance | `kty == "OKP"`, `crv == "Ed25519"`, `use == "sig"`, `alg == "EdDSA"` |
| **T1.1.3** | `GET /.well-known/jwks.json` | `kid` derivation integrity | `kid` is 64 lowercase hex chars == `sha256(base64url_decode(x))` |
| **T1.1.4** | `GET /.well-known/jwks.json` | Public key length & format | `x` decodes to exactly 32 raw bytes of valid Ed25519 public key |
| **T1.1.5** | `GET /.well-known/jwks.json` | Public key cryptographic verification | Signatures returned on subsequent endpoints verify against this key |
| **T1.2.1** | `POST /v1/cage/quarantine` | Workload-level quarantine directive | HTTP 200, `status == "QUARANTINED"`, `enforcement_plane == "HOST_OS_KERNEL"` |
| **T1.2.2** | `POST /v1/cage/quarantine` | Process PID targeted freeze | HTTP 200, receipt contains matching `target_pid`, process suspended |
| **T1.2.3** | `POST /v1/cage/quarantine` | Receipt detached Ed25519 signature | Preimage `CAGE_QUARANTINE_RECEIPT_V1:<JCS>` verifies with JWKS key |
| **T1.2.4** | `POST /v1/cage/quarantine` | Envelope digest binding | `receipt.envelope_digest == sha256(JCS(directive))` |
| **T1.2.5** | `POST /v1/cage/quarantine` | Rule ID & Reason propagation | Custom `rule_id` and `trigger_reason` accurately logged in journal & receipt |
| **T1.3.1** | `GET /v1/cage/attest` | Live hardware attestation probe | HTTP 200, `attestation_type == "HOST_TPM_PCR"` |
| **T1.3.2** | `GET /v1/cage/attest` | PCR measurement map integrity | `pcr_values` contains keys `"0"`, `"1"`, `"7"` as 64-character SHA-256 hex |
| **T1.3.3** | `GET /v1/cage/attest` | TPM quote binding | `tpm_pcr_quote == pcr_values["7"]` |
| **T1.3.4** | `GET /v1/cage/attest` | Ring-0 posture reporting | `ring0_posture` matches active state (`ACTIVE_WFP_FILTERED` or `ACTIVE_RING0_ENFORCED`) |
| **T1.3.5** | `GET /v1/cage/attest` | Attestation signature verification | Preimage `CAGE_ATTESTATION_RECEIPT_V1:<JCS>` verifies with JWKS key |
| **T1.4.1** | `POST /v1/cage/release` | Quorum release execution | HTTP 200, `released == true`, `outcome == "RELEASED"` |
| **T1.4.2** | `POST /v1/cage/release` | Monotonic epoch autotomy | `epoch_before == 1`, `epoch_after == 2` (`epoch_after > epoch_before`) |
| **T1.4.3** | `POST /v1/cage/release` | Multi-operator quorum scaling | Handles `quorum_count >= 2` (e.g. `quorum_count = 3, 5`) successfully |
| **T1.4.4** | `POST /v1/cage/release` | Release receipt signature verification | Preimage `CAGE_QUARANTINE_RELEASE_RECEIPT_V1:<JCS>` verifies with JWKS key |
| **T1.4.5** | `POST /v1/cage/release` | Host isolation lift | Active leases count reaches 0, kernel isolation disarms |
| **T1.5.1** | `GET /v1/cage/normative-baseline/{region}` | Primary baseline fetch (`europe-west1`) | HTTP 200, `region == "europe-west1"`, `alpha == 0.05`, `calibration_size == 500` |
| **T1.5.2** | `GET /v1/cage/normative-baseline/{region}` | Multi-region query (`us-central1`, `asia-southeast1`) | Dynamic region reflected in body, timestamps fresh (<30s UTC) |
| **T1.5.3** | `GET /v1/cage/normative-baseline/{region}` | Nonconformity threshold verification | `nonconformity_threshold == 4.25` |
| **T1.5.4** | `GET /v1/cage/normative-baseline/{region}` | Baseline signature verification | Preimage `CAGE_CONFORMAL_BASELINE_V1:<JCS>` verifies with JWKS key |
| **T1.5.5** | `GET /v1/cage/normative-baseline/{region}` | Region path routing resilience | Both `/v1/cage/normative-baseline/:region` and `/api/v1/...` resolve 200 |
| **T1.6.1** | `POST /v1/cage/conformal/validate` | High-conformity score admission | Single score `[0.1]` -> `admitted == true`, `p_value > 0.05`, `CONSENSUS_ALLOW` |
| **T1.6.2** | `POST /v1/cage/conformal/validate` | Non-conforming anomaly rejection | Single score `[25.0]` -> `admitted == false`, `p_value <= 0.05`, `CONSENSUS_DENY` |
| **T1.6.3** | `POST /v1/cage/conformal/validate` | Multi-dimensional feature vector | Vector `[0.1, 0.2, 0.15, 0.05]` projected into calibrated space -> valid p-value |
| **T1.6.4** | `POST /v1/cage/conformal/validate` | Custom action & alpha tuning | `action == "fund_transfer"`, `alpha == 0.01` evaluated by Zero-False-Positive Adjudicator |
| **T1.6.5** | `POST /v1/cage/conformal/validate` | Validation signature verification | Preimage `CAGE_CONFORMAL_VALIDATION_V1:<JCS>` verifies with JWKS key |

---

### Tier 2: Boundary, Edge & Corner Cases
*Goal: Prove the substrate fails closed under adversarial, malformed, or boundary conditions.*

| Test ID | Endpoint | Attack Vector / Edge Case | Expected HTTP Status & Error Code |
|---|---|---|---|
| **T2.1.1** | `POST /v1/cage/quarantine` | Missing `X-CAGE-Quarantine-Assertion` header | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.1.2** | `POST /v1/cage/quarantine` | Missing `X-CAGE-Signer-Kid` header | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.1.3** | `POST /v1/cage/release` | Missing `X-CAGE-Quarantine-Release` header | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.1.4** | `POST /v1/cage/release` | Missing `X-CAGE-Signer-Kid` header | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.2.1** | `POST /v1/cage/quarantine` | Cryptographically forged signature (64 random bytes) | HTTP 401 (`SIGNATURE_INVALID`) |
| **T2.2.2** | `POST /v1/cage/quarantine` | Truncated signature (<64 bytes, e.g. 32 bytes) | HTTP 401 (`SIGNATURE_INVALID`) |
| **T2.2.3** | `POST /v1/cage/quarantine` | Inflated signature (>64 bytes, e.g. 96 bytes) | HTTP 401 (`SIGNATURE_INVALID`) |
| **T2.2.4** | `POST /v1/cage/quarantine` | Corrupted base64url encoding (invalid symbols, invalid padding) | HTTP 401 (`SIGNATURE_INVALID`) |
| **T2.2.5** | `POST /v1/cage/quarantine` | Tampered body after signature generation (`workload_id` mutation) | HTTP 401 (`SIGNATURE_INVALID`) |
| **T2.3.1** | `POST /v1/cage/quarantine` | Signer `kid` not registered in key manifest | HTTP 403 (`UNKNOWN_SIGNER_KID`) |
| **T2.3.2** | `POST /v1/cage/quarantine` | Empty string `kid` | HTTP 403 (`UNKNOWN_SIGNER_KID`) |
| **T2.3.3** | `POST /v1/cage/quarantine` | Signer `kid` case-sensitivity mutation | HTTP 403 (`UNKNOWN_SIGNER_KID`) |
| **T2.4.1** | `POST /v1/cage/quarantine` | Immediate duplicate nonce replay | HTTP 409 (`REPLAY_DETECTED`) |
| **T2.4.2** | `POST /v1/cage/release` | Immediate duplicate nonce replay | HTTP 409 (`REPLAY_DETECTED`) |
| **T2.4.3** | `POST /v1/cage/conformal/validate` | Immediate duplicate nonce replay | HTTP 409 (`REPLAY_DETECTED`) |
| **T2.5.1** | `POST /v1/cage/quarantine` | Keys in unsorted, random order | HTTP 200 (JCS canonicalizes identically on client and server) |
| **T2.5.2** | `POST /v1/cage/quarantine` | Malformed JSON syntax (missing braces, trailing commas) | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.5.3** | `POST /v1/cage/quarantine` | Payload exceeding `max_body_bytes` (> 2 MB) | HTTP 413 (`PAYLOAD_TOO_LARGE`) |
| **T2.6.1** | `POST /v1/cage/release` | Quorum count insufficient: `quorum_count == 1` | HTTP 400 (`VALIDATION_ERROR`: "quorum_count >= 2") |
| **T2.6.2** | `POST /v1/cage/release` | Quorum count zero or negative: `quorum_count == 0` | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.6.3** | `POST /v1/cage/release` | Digest length invalid: 63 hex characters | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.6.4** | `POST /v1/cage/release` | Digest characters invalid: non-hex characters (`0x...zz`) | HTTP 400 (`VALIDATION_ERROR`) |
| **T2.7.1** | `POST /v1/cage/conformal/validate` | Extreme float saturation: $2^{63}-1$ ($9.223372036854775807 \times 10^{18}$) | HTTP 200 (JCS bit-exact representation without overflow) |
| **T2.7.2** | `POST /v1/cage/conformal/validate` | Extreme negative float: $-2^{63}$ | HTTP 200 (Bit-exact parsing) |
| **T2.7.3** | `POST /v1/cage/conformal/validate` | Scientific notation boundary: $10^{20}$ vs $10^{21}$ | HTTP 200 (ECMAScript notation conformance) |
| **T2.7.4** | `POST /v1/cage/conformal/validate` | Sub-normal float boundary: $10^{-6}$ vs $10^{-7}$ | HTTP 200 (ECMAScript small float conformance) |
| **T2.7.5** | `POST /v1/cage/conformal/validate` | Unrepresentable float values: `NaN`, `Infinity`, `-Infinity` | HTTP 400 (`VALIDATION_ERROR` / Invalid JSON) |

---

### Tier 3: Cross-Feature State Workflows
*Goal: Prove multi-endpoint sequential integration, state machine consistency, and journal durability.*

| Workflow ID | Workflow Name | Step-by-Step Sequence | Verification Checkpoints |
|---|---|---|---|
| **T3.1** | **Full Containment Lifecycle & Epoch Autotomy** | 1. Query baseline state (`is_workload_quarantined("agent-alpha") == False`, epoch = 1).<br>2. Send signed `POST /v1/cage/quarantine`.<br>3. Verify live CAGE gateway calls (`/governance/validate-action`, `/mcp`) return 403.<br>4. Issue multi-operator release (`quorum_count=2`, valid digest) to `POST /v1/cage/release`.<br>5. Verify release receipt: `epoch_before=1`, `epoch_after=2`.<br>6. Verify CAGE gateway unblocks agent under Gen 2 credentials.<br>7. Query `GET /v1/cage/attest` to verify clean hardware state. | - Quarantine receipt verified.<br>- Immediate gateway 403 block.<br>- Monotonic epoch autotomy verified.<br>- Unblock verified.<br>- Journal lease cleared. |
| **T3.2** | **Conformal Anomaly Trigger to Lethal Barrier Quarantine** | 1. Fetch baseline parameters from `GET /v1/cage/normative-baseline/europe-west1`.<br>2. Submit extreme observation vector (`scores=[50.0]`) to `POST /v1/cage/conformal/validate`.<br>3. Server returns `admitted=false`, `CONSENSUS_DENY`.<br>4. CAGE kernel triggers CBF lethal barrier and automatically issues `POST /v1/cage/quarantine`.<br>5. Target PID suspended and network blackholed. | - Conformal rejection receipt verified.<br>- Automatic transition to quarantine.<br>- Substrate process freeze confirmed. |
| **T3.3** | **Crash-Safe Sealed Journal Survival Across Process Restart** | 1. Start server instance $S_1$ with state dir $D$.<br>2. Issue quarantine directive for `workload-gamma` (PID 9999).<br>3. Kill server process $S_1$.<br>4. Start new server instance $S_2$ pointing to the same state dir $D$.<br>5. Query $S_2$: verify active lease for `workload-gamma` is still enforced.<br>6. Issue release directive to $S_2$; verify release advances epoch cleanly. | - Journal Ed25519 seal verifies.<br>- Lease survives process death.<br>- Epoch advances correctly on revived server. |
| **T3.4** | **Multi-Workload Lease Coexistence & Independent Release** | 1. Quarantine `workload-1` (PID 1001) and `workload-2` (PID 1002) in sequence.<br>2. Verify journal holds 2 unexpired leases.<br>3. Release `workload-1` only.<br>4. Verify `workload-1` epoch advances (`1 -> 2`), while `workload-2` remains quarantined at epoch 1.<br>5. Host kernel isolation remains active (because `workload-2` is still leased).<br>6. Release `workload-2`; host isolation lifts. | - Workload epoch isolation.<br>- Zero cross-workload interference.<br>- Kernel disarms only when lease count == 0. |

---

### Tier 4: Real-World Workload Scenarios
*Goal: Stress testing, concurrency safety, and continuous agent loopback execution.*

| Scenario ID | Scenario Name | Load / Stress Profile | Success Criteria |
|---|---|---|---|
| **T4.1** | **Continuous Agent Loop Under Asynchronous Quarantine Injection** | Background async client executing gateway tool calls every 50ms. Mid-stream, a signed quarantine directive is injected asynchronously. | Ingress requests block with 403 in <10ms from receipt timestamp. Zero execution leak during quarantine. Seamless recovery on release. |
| **T4.2** | **Concurrent Quarantine Storm (20 Workloads)** | 20 parallel coroutines issuing signed quarantine directives simultaneously via `asyncio.gather`. | 100% of directives return HTTP 200 with unique signed receipts. Journal records all 20 leases without deadlocks or race conditions. |
| **T4.3** | **Rapid Ephemeral Port Recycling & Cold-Boot Performance** | Spawning 5 sequential `killswitch-server` processes on dynamic loopback ports, executing health probe, and shutting down. | Each process boots to ready state (`GET /.well-known/jwks.json` returns 200) in <500ms. All sockets cleanly released without `WSAEADDRINUSE`. |

---

## 4. Pytest Fixture & Execution Architecture

To execute the 4-Tier test matrix against real binaries with zero manual setup, pytest fixtures manage process lifetime, port discovery, key generation, and fail-safe cleanup.

### 4.1 Ephemeral Port Discovery & Binary Resolution
```python
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
import base64

def get_free_port() -> int:
    """Acquire an ephemeral port safely from the OS kernel."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(s.getsockname()[1])

def resolve_killswitch_binary() -> Path:
    """Locate the compiled release binary for killswitch."""
    candidates = [
        Path(r"D:\harfile\killswitch\target\release\killswitch.exe"),
        Path(r"D:\harfile\killswitch\killswitch.exe"),
        Path(r"D:\harfile\killswitch\target\release\start.exe"),
        Path(r"D:\harfile\killswitch\start.exe"),
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    raise FileNotFoundError(
        "Could not find compiled killswitch binary. Run `cargo build --release --workspace` first!"
    )
```

### 4.2 Dynamic Key Manifest & Process Supervisor Fixture
```python
import httpx
import json
import hashlib

@pytest.fixture(scope="module")
def killswitch_server_harness(tmp_path_factory):
    """Spawn real killswitch-server child process on ephemeral port with test trust anchors."""
    port = get_free_port()
    state_dir = tmp_path_factory.mktemp("ks_state")
    binary_path = resolve_killswitch_binary()

    # Generate run-local CAGE test signer keypair
    cage_priv = ed25519.Ed25519PrivateKey.generate()
    cage_pub_bytes = cage_priv.public_key().public_bytes_raw()
    cage_kid = hashlib.sha256(cage_pub_bytes).hexdigest()
    cage_x_b64 = base64.urlsafe_b64encode(cage_pub_bytes).decode("ascii").rstrip("=")

    jwks_json = json.dumps({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": cage_kid,
            "x": cage_x_b64,
            "use": "sig",
            "alg": "EdDSA"
        }]
    })

    env = os.environ.copy()
    env["KILLSWITCH_PORT"] = str(port)
    env["KILLSWITCH_HOST"] = "127.0.0.1"
    env["KILLSWITCH_STATE_DIR"] = str(state_dir)
    env["CAGE_TRUSTED_JWKS_JSON"] = jwks_json
    env["KILLSWITCH_MASTER_TOKEN"] = "test_token_live_wire_000000000000"

    cmd = [str(binary_path), "-p", str(port), "-H", "127.0.0.1", "-m", "autonomous"]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    base_url = f"http://127.0.0.1:{port}"

    # Poll readiness probe (GET /.well-known/jwks.json)
    ready = False
    start_time = time.time()
    while time.time() - start_time < 8.0:
        if proc.poll() is not None:
            _, err = proc.communicate()
            raise RuntimeError(f"Server exited prematurely with code {proc.returncode}: {err.decode(errors='replace')}")
        try:
            with httpx.Client(timeout=0.5) as client:
                r = client.get(f"{base_url}/.well-known/jwks.json")
                if r.status_code == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.1)

    if not ready:
        proc.kill()
        raise TimeoutError(f"Server at {base_url} failed readiness probe within 8s")

    harness = {
        "proc": proc,
        "port": port,
        "base_url": base_url,
        "cage_priv": cage_priv,
        "cage_kid": cage_kid,
        "state_dir": state_dir,
    }

    yield harness

    # Fail-safe teardown: terminate process tree
    try:
        proc.terminate()
        proc.wait(timeout=2.0)
    except Exception:
        proc.kill()
```

---

## 5. Critical Protocol Discrepancies & Implementer Remediation Guide

During deep opaque-box exploration of the Rust substrate (`D:\harfile\killswitch`) and CAGE Layer 3 client (`src/integrations/actuator_04/`), **4 critical protocol discrepancies** were uncovered that would cause live over-the-wire tests to fail closed. Implementers must apply the following remediations:

### Remediation KS-SUB-01: Add `envelope_digest` to Substrate Receipts in `cage_substrate.rs`
- **Location**: `D:\harfile\killswitch\crates\killswitch-server\src\cage_substrate.rs` (lines 165-172 and 324-332)
- **Problem**: `Actuator04Adapter` verifies `envelope_digest == sha256(JCS(directive))` inside `verify_substrate_receipt_signature()` (lines 164-173 of `adapter.py`). If `envelope_digest` is missing from the receipt body, CAGE rejects the receipt with `RECEIPT_ENVELOPE_MISMATCH`.
- **Fix**: Calculate `envelope_digest = hex::encode(sha2::Sha256::digest(&canonical_body))` from the canonical request bytes and include it in `unsigned_receipt` for both `/v1/cage/quarantine` and `/v1/cage/release`.

### Remediation KS-SUB-02: Add `X-CAGE-Signer-Kid` to `release_workload()` Headers in `adapter.py`
- **Location**: `d:\harfile\cybernetic-agent-governance-engine\src\integrations\actuator_04\adapter.py` (lines 403-408)
- **Problem**: `handle_cage_release()` in `cage_substrate.rs` (line 220) explicitly requires `X-CAGE-Signer-Kid` to resolve the trusted key. `adapter.py` included `HEADER_SIGNER_KID` in `quarantine_workload()` (line 281) but omitted it in `release_workload()`, causing HTTP 400 `Missing X-CAGE-Signer-Kid header`.
- **Fix**: Add `HEADER_SIGNER_KID: getattr(self._signer, "key_id", "")` to the request headers dictionary in `release_workload()`.

### Remediation KS-SUB-03: Align Conformal Validation Domain Tags
- **Location**: `src/integrations/actuator_04/constants.py` and `normative.py`
- **Problem**: `cage_substrate.rs` (line 548) signs validation receipts using domain tag `b"CAGE_CONFORMAL_VALIDATION_V1:"`. `constants.py` (line 33) and `normative.py` (line 124) verify with `b"CAGE_NORMATIVE_VALIDATION_V1:"`, causing Ed25519 signature verification failure.
- **Fix**: Update `constants.py` and `normative.py` to use `CONFORMAL_VALIDATION_DOMAIN_TAG = b"CAGE_CONFORMAL_VALIDATION_V1:"` matching the substrate server.

### Remediation KS-SUB-04: Expose `envelope_digest` in `handle_conformal_validate`
- **Location**: `D:\harfile\killswitch\crates\killswitch-server\src\cage_substrate.rs` (line 537)
- **Problem**: `validate_fria()` in `normative.py` calls `verify_substrate_receipt_signature(..., expected_envelope_digest=digest)`. If the response body does not include `envelope_digest`, it fails verification.
- **Fix**: Compute sha256 of incoming canonical validate request bytes and include `"envelope_digest": digest` in `unsigned_resp`.

---

## 6. Test Suite File Structure & Test Execution Commands

### 6.1 Deliverable Test File Layout
```
tests/integrations/actuator_04/
├── __init__.py
├── conftest.py                             # Live killswitch-server loopback fixtures
├── test_live_wire_conformance.py          # Tier 1 (30 tests) & Tier 2 (27 tests)
└── test_formal_quarantine_invariants.py    # Tier 3 (4 workflows) & Tier 4 (3 scenarios)
```

### 6.2 Test Marker Compliance
In accordance with `pytest.ini` and CAGE CI marker contract:
```python
pytestmark = [pytest.mark.integration, pytest.mark.local]
```

### 6.3 Test Invocation Command
```bash
# Run the entire live over-the-wire integration suite
uv run pytest tests/integrations/actuator_04/ -m "integration or local" -v --timeout=120
```
