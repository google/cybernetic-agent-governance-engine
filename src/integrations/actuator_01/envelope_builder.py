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


def build_envelope_dict(clearance: ExecutionClearance) -> dict[str, Any]:
    """
    Build the envelope dictionary from ExecutionClearance.

    This is a CAGE-to-vendor mapping. The envelope schema is vendor-specific,
    but the clearance is CAGE-native and vendor-neutral.

    Returns a dict ready for JCS canonicalization. Does not canonicalize here;
    canonicalization happens in canonicalize_envelope().
    """
    validate_clearance(clearance)

    # Core envelope structure (simplified for Phase 1)
    # Full schema implementation will follow in Phase 3/Stream C
    envelope = {
        "version": "actuator_01.envelope/v1",
        "correlation_id": clearance.correlation_id,
        "issued_at": clearance.issued_at,
        "ttl_seconds": clearance.ttl_seconds,
        "nonce": clearance.nonce,
        "operator_urn": clearance.operator_urn,
        "action": clearance.action,
        "target": clearance.target,
        "decision": clearance.decision,
        "decision_path": clearance.decision_path,
        "governance": {
            "decision_digest": clearance.governance_decision_digest,
            "opa_input_digest": clearance.opa_input_digest,
            "required_quorum": clearance.required_quorum,
        },
        "parameters": {
            # Digest-only, never full content
            "semantic_distance": clearance.semantic_distance,
            "confidence_score": clearance.confidence_score,
        },
    }

    # Authority reference block (placeholder - will be configured at runtime)
    envelope["authority_ref"] = {
        "graph_version": "v1",  # Supplied by partner at onboarding
        "graph_hash": "placeholder",  # Configured, not computed
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


def build_and_canonicalize(clearance: ExecutionClearance) -> tuple[bytes, str]:
    """
    Complete envelope construction pipeline.

    1. Validate clearance
    2. Build envelope dict
    3. Canonicalize per RFC 8785
    4. Assert within 4KB ceiling
    5. Compute body digest

    Returns:
        (canonical_bytes, digest) - The frozen bytes and their SHA-256 hex digest

    Raises:
        InvalidClearanceError: Pre-flight validation failure
        EnvelopeTooLargeError: Envelope exceeds 4096 bytes
    """
    envelope = build_envelope_dict(clearance)
    canonical_bytes = canonicalize_envelope(envelope)
    assert_within_ceiling(canonical_bytes)
    digest = body_digest(canonical_bytes)

    return canonical_bytes, digest
