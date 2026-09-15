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
Envelope builder for actuator_01 with RFC 8785 (JCS) canonicalization and 4KB ceiling.

The four-step discipline (Implementation Plan v2 §7.1):
1. Build the envelope object
2. Serialize with RFC 8785 (JCS) - sorted keys, canonical number form, UTF-8
3. Compute SHA-256 over those exact bytes
4. Sign and transmit those exact bytes - never re-serialize afterwards

Engineering rule: This module returns bytes. Every downstream consumer accepts
only those bytes. No function may accept a dict and re-serialize it.
"""

import hashlib
import secrets
import uuid
from typing import Any

from src.gateway.governance.execution_actuator import ExecutionClearance
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.raw_signer_protocol import RawMessageSigner
from src.integrations.actuator_01.constants import (
    ENVELOPE_MAX_BYTES,
    MAX_TTL_SECONDS,
    NONCE_HEX_LENGTH,
)


class EnvelopeTooLargeError(Exception):
    """Raised when canonical envelope exceeds 4096 bytes."""

    def __init__(self, actual_bytes: int):
        self.actual_bytes = actual_bytes
        super().__init__(
            f"Canonical envelope is {actual_bytes} bytes, exceeds 4096-byte ceiling"
        )


class InvalidClearanceError(Exception):
    """Raised when clearance fails pre-flight validation."""

    pass


def validate_clearance(clearance: ExecutionClearance) -> None:
    """
    Pre-flight validation before envelope construction.

    Per Implementation Plan v2 §2.4 invariant: An envelope is evidence that
    ALLOW was reached. HOLD, DENY, pending-escalation never produce one.

    Raises:
        InvalidClearanceError: If clearance is invalid
    """
    # Only ALLOW decisions produce envelopes
    if clearance.decision != "ALLOW":
        raise InvalidClearanceError(
            f"Clearance decision must be ALLOW, got {clearance.decision}. "
            "An envelope is evidence that ALLOW was reached."
        )

    # Quorum threshold must be met
    if len(clearance.approvals) < clearance.required_quorum:
        raise InvalidClearanceError(
            f"Clearance has {len(clearance.approvals)} approvals but requires "
            f"{clearance.required_quorum}. Envelope construction refused."
        )

    # correlation_id must be a valid UUID (enforced locally, per §2.5)
    try:
        uuid.UUID(clearance.correlation_id)
    except ValueError as e:
        raise InvalidClearanceError(
            f"Clearance correlation_id must be a valid UUID, got {clearance.correlation_id!r}: {e}"
        )

    # TTL must not exceed partner Micro-TTL
    if clearance.ttl_seconds > MAX_TTL_SECONDS:
        raise InvalidClearanceError(
            f"Clearance ttl_seconds={clearance.ttl_seconds} exceeds {MAX_TTL_SECONDS}s Micro-TTL"
        )

    # Nonce must be 32 hex chars (16 bytes)
    if len(clearance.nonce) != NONCE_HEX_LENGTH or not all(
        c in "0123456789abcdef" for c in clearance.nonce
    ):
        raise InvalidClearanceError(
            f"Clearance nonce must be {NONCE_HEX_LENGTH} lowercase hex chars, "
            f"got {clearance.nonce!r}"
        )


def build_envelope_dict(
    clearance: ExecutionClearance,
    policy_signer: RawMessageSigner | None = None,
    receipt_id: str | None = None,
    receipt_hash: str | None = None,
    graph_hash: str | None = None,
    graph_version: str | None = None,
) -> dict[str, Any]:
    """
    Build the envelope dictionary from ExecutionClearance.

    This is a CAGE-to-vendor mapping. The envelope schema is vendor-specific,
    but the clearance is CAGE-native and vendor-neutral.

    Returns a dict ready for JCS canonicalization. Does not canonicalize here;
    canonicalization happens in canonicalize_envelope().

    Phase 3: Emits canonical Archytan ArbiterKernel wire structure per Vector 1/3.

    Args:
        clearance: ExecutionClearance from governance decision.
        policy_signer: Optional policy authority signer for decision_signature.
                      If provided, generates dual-authority policy signature.
        receipt_id: Optional partner receipt ID for governance block.
        receipt_hash: Optional receipt hash for governance block.
        graph_hash: Optional authority graph hash for authority_ref.
        graph_version: Optional authority graph version for authority_ref.
    """
    validate_clearance(clearance)

    # Compute target digest for policy decision signature
    # Per Archytan spec: target_digest is SHA-256 of JCS-canonical target object
    target_obj = {
        "account_hash": hashlib.sha256(clearance.target.encode("utf-8")).hexdigest()
    }
    from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

    target_canonical = jcs_canonicalize_plan(target_obj)
    target_digest = hashlib.sha256(target_canonical).hexdigest()

    # Compute policy decision signature if policy signer provided
    decision_signature = None
    if policy_signer is not None and policy_signer.is_kms_active:
        from src.integrations.actuator_01.signatures import sign_policy_decision

        try:
            decision_signature = sign_policy_decision(
                signer=policy_signer,
                action=clearance.action,
                target_digest=target_digest,
                correlation_id=clearance.correlation_id,
                decision=clearance.decision,
                decision_path=clearance.decision_path,
                required_quorum=clearance.required_quorum,
                policy_version=clearance.policy_version
                if hasattr(clearance, "policy_version")
                else "cage-policy-2.1.1",
                evaluated_at=clearance.issued_at,
                receipt_id=receipt_id,
                receipt_hash=receipt_hash,
            )
        except (RuntimeError, ValueError) as e:
            # Log but don't fail envelope construction if policy signature fails
            # The envelope can still proceed with operator quorum signatures only
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(
                "[envelope_builder] Policy decision signature generation failed: %s. "
                "Proceeding with operator quorum signatures only.",
                e,
            )

    # Archytan canonical wire structure (per Vector 1 & 3)
    envelope: dict[str, Any] = {
        "action": clearance.action,
        "authority_ref": {
            "graph_hash": graph_hash or ("f" * 64),
            "graph_version": graph_version or "ag-2026-08-01T00:00:00Z",
        },
        "correlation_id": clearance.correlation_id,
        "envelope_version": "archytan.envelope/v1",
        "governance": {
            "decision": clearance.decision,
            "decision_path": clearance.decision_path,
            "decision_signature": decision_signature,
            "evaluated_at": clearance.issued_at,
            "policy_version": clearance.policy_version
            if hasattr(clearance, "policy_version")
            else "cage-policy-2.1.1",
            "receipt_hash": receipt_hash or ("0" * 64),
            "receipt_id": receipt_id or "cage-generated-receipt",
            "required_quorum": clearance.required_quorum,
        },
        "issued_at": clearance.issued_at,
        "nonce": clearance.nonce,
        "operator_urn": clearance.operator_urn,
        "parameters": clearance.params if isinstance(clearance.params, dict) else {},
        "target": target_obj,
        "ttl_seconds": clearance.ttl_seconds,
    }

    # Approval block - construct ONLY if clearance.approvals is non-empty (ESCALATE path)
    # Per Vector 1: DIRECT path omits the "approval" key entirely (not null)
    if clearance.approvals:
        # Extract from first approval (primary operator)
        approval = clearance.approvals[0]
        envelope["approval"] = {
            "approver_urn": approval.get("approver_urn", clearance.operator_urn),
            "authenticator_data": approval.get("authenticator_data"),
            "challenge_binding": approval.get("challenge_binding"),
            "client_data_json": approval.get("client_data_json"),
            "credential_id": approval.get("credential_id"),
            "signature": approval.get("signature"),
        }

    return envelope


def canonicalize_envelope(envelope: dict[str, Any]) -> bytes:
    """
    Canonicalize envelope per RFC 8785 (JCS).

    Delegates to jcs_canonicalize_plan() - never vendor a second JCS implementation.

    Returns:
        Canonical bytes (sorted keys, canonical number form, UTF-8, no insignificant whitespace)
    """
    return jcs_canonicalize_plan(envelope)


def assert_within_ceiling(canonical_bytes: bytes) -> None:
    """
    Enforce 4096-byte ceiling on canonical envelope body.

    Per Implementation Plan v2 §7.1: The ceiling is on the canonical body only,
    headers are measured separately. Enforced before any JSON unmarshaling at
    the partner side.

    Raises:
        EnvelopeTooLargeError: If canonical_bytes exceeds ENVELOPE_MAX_BYTES
    """
    if len(canonical_bytes) > ENVELOPE_MAX_BYTES:
        raise EnvelopeTooLargeError(len(canonical_bytes))


def body_digest(canonical_bytes: bytes) -> str:
    """
    Compute SHA-256 digest of canonical envelope bytes.

    Returns:
        64-character lowercase hex digest
    """
    return hashlib.sha256(canonical_bytes).hexdigest()


def generate_nonce() -> str:
    """
    Generate a 32-character hex nonce (16 random bytes).

    This is the execution/session UUID in hex form.
    """
    return secrets.token_hex(16)


def build_and_canonicalize(
    clearance: ExecutionClearance,
    policy_signer: RawMessageSigner | None = None,
    receipt_id: str | None = None,
    receipt_hash: str | None = None,
    graph_hash: str | None = None,
    graph_version: str | None = None,
) -> tuple[bytes, str]:
    """
    Complete envelope construction pipeline.

    1. Validate clearance
    2. Build envelope dict (with optional policy decision signature)
    3. Canonicalize per RFC 8785
    4. Assert within 4KB ceiling
    5. Compute body digest

    Args:
        clearance: ExecutionClearance from governance decision.
        policy_signer: Optional policy authority signer for dual-authority model.
        receipt_id: Optional partner receipt ID for governance block.
        receipt_hash: Optional receipt hash for governance block.
        graph_hash: Optional authority graph hash for authority_ref.
        graph_version: Optional authority graph version for authority_ref.

    Returns:
        (canonical_bytes, digest) - The frozen bytes and their SHA-256 hex digest

    Raises:
        InvalidClearanceError: Pre-flight validation failure
        EnvelopeTooLargeError: Envelope exceeds 4096 bytes
    """
    envelope = build_envelope_dict(
        clearance,
        policy_signer=policy_signer,
        receipt_id=receipt_id,
        receipt_hash=receipt_hash,
        graph_hash=graph_hash,
        graph_version=graph_version,
    )
    canonical_bytes = canonicalize_envelope(envelope)
    assert_within_ceiling(canonical_bytes)
    digest = body_digest(canonical_bytes)

    return canonical_bytes, digest
