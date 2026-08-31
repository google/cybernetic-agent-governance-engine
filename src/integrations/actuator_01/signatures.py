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
signatures.py — Ed25519 Quorum Signature Construction (Phase 2, Stream C)

Implements multi-operator quorum signing for execution authorization envelopes.
Quorum signatures use a domain-tagged construction to prevent cross-context replay.
"""

from __future__ import annotations

import hashlib
import logging

from src.gateway.governance.kms_signer import KMSGovernanceSigner

logger = logging.getLogger(__name__)

# Domain tag for quorum signatures (prevents replay as assertion signatures)
ACTUATOR_01_DOMAIN_TAG_QUORUM = b"ACTUATOR_01_QUORUM_V1:"


def sign_for_quorum(
    signer: KMSGovernanceSigner,
    raw_body: bytes,
) -> str:
    """Sign a canonical envelope body for quorum verification.

    Per wire contract §7.2, quorum signatures sign the SHA-256 digest of the
    raw canonical body bytes (NOT the envelope dict, NOT a re-hash). The
    domain tag isolates quorum signatures from assertion signatures so neither
    can be replayed in the other's context.

    Format:
        Ed25519(operator_key, ACTUATOR_01_DOMAIN_TAG_QUORUM || SHA-256(raw_body))

    Args:
        signer: KMS signer instance for this operator.
        raw_body: The exact canonical envelope bytes (from JCS serialization).

    Returns:
        Lowercase hex-encoded signature string.

    Raises:
        RuntimeError: If KMS is not active or signing fails.

    Example:
        >>> from src.gateway.governance.kms_signer import get_governance_signer
        >>> from src.integrations.actuator_01.signatures import sign_for_quorum
        >>> signer = get_governance_signer()
        >>> canonical_bytes = b'{"action":"execute_trade",...}'
        >>> sig_hex = sign_for_quorum(signer, canonical_bytes)
        >>> len(sig_hex)
        128  # Ed25519 signature is 64 bytes = 128 hex chars
    """
    if not signer.is_kms_active:
        raise RuntimeError(
            "[actuator_01/signatures] sign_for_quorum() called but KMS is not active. "
            "Ensure KMS_GOVERNANCE_KEY is set and signer initialized successfully."
        )

    # Compute SHA-256 of the raw body
    body_digest = hashlib.sha256(raw_body).digest()

    # Prepend domain tag to isolate quorum signatures
    message = ACTUATOR_01_DOMAIN_TAG_QUORUM + body_digest

    # Sign the tagged message
    # KMSSigner.sign_raw() handles Ed25519 vs ECDSA/RSA logic internally
    signature_bytes = signer.sign_raw(message)

    # Return lowercase hex (wire contract requirement)
    signature_hex = signature_bytes.hex().lower()

    logger.info(
        "[actuator_01/signatures] Quorum signature generated: %s... (len=%d)",
        signature_hex[:16],
        len(signature_hex),
    )

    return signature_hex
