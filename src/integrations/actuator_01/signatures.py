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

from src.gateway.governance.raw_signer_protocol import RawMessageSigner

logger = logging.getLogger(__name__)

# Domain tag for quorum signatures (prevents replay as assertion signatures)
# NOTE: This is the wire-load-bearing value required by Archytan kernel verification.
# The constant name is anonymized; the runtime value must match the kernel contract.
ACTUATOR_01_DOMAIN_TAG_QUORUM = b"ARCHYTAN_QUORUM_V1:"

# Domain tag for policy decision signatures (dual-authority model)
# Isolates institutional policy authority signatures from operator quorum signatures
ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION = b"ARCHYTAN_POLICY_DECISION_V1:"


def sign_for_quorum(
    signer: RawMessageSigner,
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
        >>> signer = get_governance_signer()  # Returns RawMessageSigner protocol
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


def sign_policy_decision(
    signer: RawMessageSigner,
    action: str,
    target_digest: str,
    correlation_id: str,
    decision: str,
    decision_path: str,
    required_quorum: int,
    policy_version: str,
    evaluated_at: int,
    receipt_id: str | None = None,
    receipt_hash: str | None = None,
) -> str:
    """Sign a policy decision for dual-authority verification.

    Implements the canonical decision binding payload per Archytan Vector 3:
    action || 0x1F || target_digest || 0x1F || correlation_id || 0x1F ||
    decision || 0x1F || decision_path || 0x1F || required_quorum || 0x1F ||
    policy_version || 0x1F || evaluated_at || 0x1F || receipt_id || 0x1F || receipt_hash

    The 0x1F unit separator ensures unambiguous field boundaries and prevents
    cross-field substitution attacks.

    Format:
        Ed25519(policy_key, ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION || SHA-256(binding_payload))

    Args:
        signer: KMS signer instance for the institutional policy authority.
        action: Action being authorized (e.g., "payment.wire.execute").
        target_digest: SHA-256 digest of the target parameters.
        correlation_id: Request correlation UUID.
        decision: Governance decision ("ALLOW", "DENY", "HOLD").
        decision_path: Decision path ("DIRECT", "ESCALATE").
        required_quorum: Number of operator approvals required.
        policy_version: Policy version identifier (e.g., "v1").
        evaluated_at: Unix timestamp when decision was evaluated.
        receipt_id: Optional partner receipt ID (if available).
        receipt_hash: Optional receipt hash (if available).

    Returns:
        Lowercase hex-encoded signature string.

    Raises:
        RuntimeError: If KMS is not active or signing fails.
        ValueError: If signer URN indicates operator quorum key (prohibited).

    Example:
        >>> from src.gateway.governance.kms_signer import get_governance_signer
        >>> signer = get_governance_signer()
        >>> sig = sign_policy_decision(
        ...     signer=signer,
        ...     action="payment.wire.execute",
        ...     target_digest="a" * 64,
        ...     correlation_id="550e8400-e29b-41d4-a716-446655440000",
        ...     decision="ALLOW",
        ...     decision_path="DIRECT",
        ...     required_quorum=2,
        ...     policy_version="v1",
        ...     evaluated_at=1785012000,
        ... )
    """
    if not signer.is_kms_active:
        raise RuntimeError(
            "[actuator_01/signatures] sign_policy_decision() called but KMS is not active. "
            "Ensure KMS_GOVERNANCE_KEY is set and signer initialized successfully."
        )

    # Guardrail: Ensure operator quorum keys cannot be used for policy decision signatures
    # Policy authority signers should have distinct URNs (e.g., "urn:actuator_01:policy:*")
    # vs operator quorum keys (e.g., "urn:actuator_01:op:*")
    signer_urn = getattr(signer, "signer_urn", "")
    if signer_urn and ":op:" in signer_urn:
        raise ValueError(
            f"[actuator_01/signatures] Policy decision signature attempted with "
            f"operator quorum key (URN: {signer_urn}). Policy authority keys must be isolated."
        )

    # Construct decision binding payload with 0x1F unit separators
    unit_sep = b"\x1f"
    binding_payload = unit_sep.join(
        [
            action.encode("utf-8"),
            target_digest.encode("utf-8"),
            correlation_id.encode("utf-8"),
            decision.encode("utf-8"),
            decision_path.encode("utf-8"),
            str(required_quorum).encode("utf-8"),
            policy_version.encode("utf-8"),
            str(evaluated_at).encode("utf-8"),
            (receipt_id or "").encode("utf-8"),
            (receipt_hash or "").encode("utf-8"),
        ]
    )

    # Compute SHA-256 digest of the binding payload
    decision_binding_sha256 = hashlib.sha256(binding_payload).digest()

    # Sign domain-tagged decision binding
    message = ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION + decision_binding_sha256
    signature_bytes = signer.sign_raw(message)

    # Return lowercase hex (wire contract requirement)
    signature_hex = signature_bytes.hex().lower()

    logger.info(
        "[actuator_01/signatures] Policy decision signature generated: %s... (len=%d)",
        signature_hex[:16],
        len(signature_hex),
    )

    return signature_hex
