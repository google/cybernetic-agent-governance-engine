# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
assertion.py — 120-Byte Execution Assertion Builder (Phase 3, Stream C / C.3)

Constructs the compact, fixed-size binary assertion submitted via the
X-Execution-Assertion header.  The assertion binds the envelope digest,
nonce, timestamp, and a domain-tagged KMS signature into exactly 120 bytes:

    Offset    Length   Content
    ──────    ──────   ──────────────────────────────────────────
     0..31      32     SHA-256 digest of canonical envelope bytes
    32..47      16     Nonce (16 raw bytes, decoded from 32 hex chars)
    48..55       8     Timestamp — ``issued_at`` as unsigned 64-bit big-endian
    56..119     64     Domain-tagged KMS signature over bytes [0..55]

Domain tag:  ``ARCHYTAN_ASSERTION_V1:``
    Isolates assertion signatures from quorum signatures (which use
    ``ARCHYTAN_QUORUM_V1:``), preventing cross-context replay.

Wire encoding: base64url (RFC 4648 §5, no padding) per wire contract §7.3.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import struct

from src.gateway.governance.kms_signer import KMSGovernanceSigner
from src.gateway.governance.raw_signer_protocol import RawMessageSigner

logger = logging.getLogger(__name__)

# Exactly 120 bytes.
ASSERTION_TOTAL_BYTES = 120

# Layout offsets and sizes.
_DIGEST_OFFSET = 0
_DIGEST_SIZE = 32
_NONCE_OFFSET = 32
_NONCE_SIZE = 16
_TIMESTAMP_OFFSET = 48
_TIMESTAMP_SIZE = 8
_SIGNATURE_OFFSET = 56
_SIGNATURE_SIZE = 64

# Domain tag — distinct from ARCHYTAN_QUORUM_V1: (quorum tag) used in signatures.py.
# NOTE: This is the wire-load-bearing value required by Archytan kernel verification.
# The constant name is anonymized; the runtime value must match the kernel contract.
ACTUATOR_01_DOMAIN_TAG_ASSERTION = b"ARCHYTAN_ASSERTION_V1:"


class AssertionBuildError(Exception):
    """Raised when assertion construction fails pre-flight validation."""

    pass


def _validate_inputs(
    envelope_digest_hex: str,
    nonce_hex: str,
    issued_at: int,
) -> None:
    """Validate assertion inputs before assembly.

    Raises:
        AssertionBuildError: If any input is malformed.
    """
    # Digest must be a 64-char lowercase hex SHA-256.
    if len(envelope_digest_hex) != 64:
        raise AssertionBuildError(
            f"envelope_digest_hex must be 64 hex chars, got {len(envelope_digest_hex)}"
        )
    try:
        bytes.fromhex(envelope_digest_hex)
    except ValueError as exc:
        raise AssertionBuildError(
            f"envelope_digest_hex is not valid hex: {exc}"
        ) from exc

    # Nonce must be 32 hex chars (16 bytes).
    if len(nonce_hex) != 32:
        raise AssertionBuildError(
            f"nonce_hex must be 32 hex chars, got {len(nonce_hex)}"
        )
    try:
        bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise AssertionBuildError(f"nonce_hex is not valid hex: {exc}") from exc

    # issued_at must be a positive Unix timestamp.
    if issued_at <= 0:
        raise AssertionBuildError(
            f"issued_at must be a positive Unix timestamp, got {issued_at}"
        )


def build_assertion(
    envelope_digest_hex: str,
    nonce_hex: str,
    issued_at: int,
    signer: RawMessageSigner,
) -> str:
    """Build the 120-byte execution assertion and return base64url encoding.

    Steps:
        1. Validate inputs.
        2. Pack digest (32B) + nonce (16B) + timestamp (8B) = 56 bytes.
        3. KMS-sign the 56-byte payload with domain tag isolation.
        4. Append 64-byte signature → 120 bytes total.
        5. Encode as base64url (no padding).

    Args:
        envelope_digest_hex: 64-char lowercase hex SHA-256 of canonical
            envelope bytes (from ``envelope_builder.body_digest``).
        nonce_hex: 32-char lowercase hex nonce (from ``ExecutionClearance.nonce``).
        issued_at: Unix timestamp in seconds (from ``ExecutionClearance.issued_at``).
        signer: ``RawMessageSigner`` protocol instance for assertion signing.

    Returns:
        Base64url-encoded (no padding) string of exactly 120 raw bytes.

    Raises:
        AssertionBuildError: Pre-flight validation failure.
        RuntimeError: KMS not active or signing failure.
    """
    _validate_inputs(envelope_digest_hex, nonce_hex, issued_at)

    if not signer.is_kms_active:
        raise RuntimeError(
            "[actuator_01/assertion] build_assertion() called but KMS is not "
            "active. Ensure KMS_GOVERNANCE_KEY is set and signer initialized."
        )

    # ── Step 1: Pack the signable payload (56 bytes) ───────────────────────
    digest_bytes = bytes.fromhex(envelope_digest_hex)  # 32B
    nonce_bytes = bytes.fromhex(nonce_hex)  # 16B
    timestamp_bytes = struct.pack(">Q", issued_at)  # 8B big-endian uint64

    signable_payload = digest_bytes + nonce_bytes + timestamp_bytes
    assert len(signable_payload) == _SIGNATURE_OFFSET  # 56 bytes

    # ── Step 2: Domain-tagged KMS signature ────────────────────────────────
    tagged_message = ACTUATOR_01_DOMAIN_TAG_ASSERTION + signable_payload
    signature_bytes = signer.sign_raw(tagged_message)

    # Truncate or verify signature is exactly 64 bytes.
    # Ed25519 signatures are always 64 bytes.  ECDSA P-256 raw signatures are
    # also 64 bytes (32-byte r + 32-byte s).  If we get a different length, the
    # KMS key type is incompatible with the wire contract.
    if len(signature_bytes) != _SIGNATURE_SIZE:
        raise AssertionBuildError(
            f"KMS signature is {len(signature_bytes)} bytes, expected "
            f"{_SIGNATURE_SIZE}. The KMS key type may be incompatible with "
            "the actuator_01 wire contract (Ed25519 or ECDSA P-256 required)."
        )

    # ── Step 3: Assemble the 120-byte assertion ───────────────────────────
    assertion_bytes = signable_payload + signature_bytes
    assert len(assertion_bytes) == ASSERTION_TOTAL_BYTES  # 120 bytes

    # ── Step 4: Encode as base64url (no padding) ──────────────────────────
    assertion_b64 = (
        base64.urlsafe_b64encode(assertion_bytes).rstrip(b"=").decode("ascii")
    )

    logger.info(
        "[actuator_01/assertion] Assertion built: digest=%s... nonce=%s... "
        "timestamp=%d sig=%s... total_bytes=%d",
        envelope_digest_hex[:16],
        nonce_hex[:8],
        issued_at,
        signature_bytes[:8].hex(),
        ASSERTION_TOTAL_BYTES,
    )

    return assertion_b64


def decode_assertion(assertion_b64: str) -> dict[str, bytes | int]:
    """Decode a base64url assertion into its component fields.

    Useful for testing, verification, and the mock actuator kernel.

    Returns:
        dict with keys: ``digest`` (32B), ``nonce`` (16B),
        ``timestamp`` (int), ``signature`` (64B), ``signable_payload`` (56B).

    Raises:
        AssertionBuildError: If assertion is malformed or wrong length.
    """
    # Re-add padding for base64 decoding.
    padded = assertion_b64 + "=" * (-len(assertion_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise AssertionBuildError(f"Invalid base64url: {exc}") from exc

    if len(raw) != ASSERTION_TOTAL_BYTES:
        raise AssertionBuildError(
            f"Assertion is {len(raw)} bytes, expected {ASSERTION_TOTAL_BYTES}"
        )

    digest = raw[_DIGEST_OFFSET : _DIGEST_OFFSET + _DIGEST_SIZE]
    nonce = raw[_NONCE_OFFSET : _NONCE_OFFSET + _NONCE_SIZE]
    (timestamp,) = struct.unpack(
        ">Q", raw[_TIMESTAMP_OFFSET : _TIMESTAMP_OFFSET + _TIMESTAMP_SIZE]
    )
    signature = raw[_SIGNATURE_OFFSET : _SIGNATURE_OFFSET + _SIGNATURE_SIZE]

    return {
        "digest": digest,
        "nonce": nonce,
        "timestamp": timestamp,
        "signature": signature,
        "signable_payload": raw[:_SIGNATURE_OFFSET],
    }
