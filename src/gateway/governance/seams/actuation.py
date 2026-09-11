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
Execution Actuator Seam — Downstream Clearance Transmission.

This module defines the contract between CAGE's governance kernel and downstream
execution actuators (actuator_01, etc.). Unlike normative/attestation providers
(where CAGE calls in for truth), the actuator receives an authorization token
from CAGE and hands it off for physical execution at an external system.

CAGE is the ISSUER, not the consumer. This is a fundamentally different trust
boundary from the upstream NormativeProvider/AttestationProvider seams.

Architectural Invariant:
    This module must NEVER import from src.gateway.governance or any other kernel
    module. It defines pure data contracts and protocols only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class ActuatorCapability(str, Enum):
    """Capabilities an execution actuator may declare."""

    MULTI_SIG_QUORUM = "multi_sig_quorum"
    HARDWARE_APPROVAL_PROOF = "hardware_approval_proof"
    MTLS_REQUIRED = "mtls_required"
    DIGEST_ONLY_PAYLOAD = "digest_only_payload"
    REPLAY_PROTECTED = "replay_protected"


@dataclass
class ExecutionClearance:
    """
    CAGE-native, vendor-neutral clearance to actuate.

    This is what CAGE produces. The actuator adapter maps it to vendor-specific
    wire formats. No vendor types ever cross this boundary.

    Per Implementation Plan v2 §2.5, `issued_at` and `correlation_id` are
    externally-supplied with provenance flags to keep both Q6 branches open.
    """

    # Core decision context
    thread_id: str
    decision: str  # "ALLOW" - only ALLOW produces a clearance
    decision_path: str  # "DIRECT" or "ESCALATE"
    action: str
    target: str
    operator_urn: str  # Primary operator

    # Temporal and correlation
    issued_at: int  # Unix seconds - externally supplied
    issued_at_provenance: str  # "CHALLENGE_TIME" | "CONSTRUCTION_TIME"
    correlation_id: str  # UUID - minted at ingress, before governance decision
    correlation_id_source: str  # "INGRESS_MINTED" | "THREAD_DERIVED"

    # Governance context (digest-only, never full content)
    governance_decision_digest: str  # SHA-256 hex of the governance decision
    opa_input_digest: str  # SHA-256 hex of OPA input snapshot

    # Execution context
    nonce: str  # 32 hex chars (16 bytes) - execution/session UUID

    # Fields with defaults (must come after fields without defaults)
    semantic_distance: float | None = None
    confidence_score: float | None = None

    # Quorum and approval (populated by dual-control mechanism)
    approvals: list[dict] = field(default_factory=list)  # ApprovalRecord dicts
    required_quorum: int = 2  # 2-5, per partner contract

    ttl_seconds: int = 30  # ≤30 per partner Micro-TTL


@dataclass
class ActuationReceipt:
    """
    Outcome of an actuation attempt.

    Returned by ExecutionActuator.actuate(). Follows the fail-closed pattern:
    network timeouts, HTTP errors, and parse failures produce accepted=False
    with structured findings.
    """

    accepted: bool  # True only on a verified 200 with a valid receipt
    receipt_id: str | None  # Partner-issued receipt ID (if accepted)
    session_uuid: str | None  # Partner-issued session UUID (if accepted)
    raw_receipt: dict | None  # Full partner receipt (if accepted)
    findings: list[dict] = field(default_factory=list)  # Error/rejection details
    retryable: bool = False  # True only for transient failures (429, 503, load shed)

    # Evidence chain fields
    envelope_digest: str | None = None  # SHA-256 of canonical envelope bytes
    timestamp_utc: str | None = None  # ISO-8601 UTC when actuation was attempted


@runtime_checkable
class ExecutionActuator(Protocol):
    """
    Downstream execution boundary. CAGE is the issuer, not the consumer.

    Unlike NormativeProvider (where CAGE calls in for truth), the actuator
    receives an authorization token from CAGE and hands it off for physical
    execution at an external system.

    Position: downstream of the governance decision, out-of-band from the hot path.
    Failure mode: fail-closed - do not actuate; the governance decision is already recorded.

    Per Secure Plugin & Adapter Architecture Specification:
    - Vendor packages live exclusively under src/integrations/{provider_name}/
    - No vendor imports in the core CAGE kernel (src/gateway/)
    - Seam implementations return CAGE dataclasses, never vendor types
    - Fail-closed semantics: timeouts/errors → accepted=False with findings
    """

    @property
    def actuator_id(self) -> str:
        """Unique identifier for this actuator (e.g., 'actuator_01')."""
        ...

    async def health_check(self) -> bool:
        """
        Check if the actuator is ready to accept clearances.

        Returns False (fail-closed) when mTLS material is unreadable, the
        partner endpoint is unreachable, or configuration is invalid.
        """
        ...

    def get_capabilities(self) -> set[ActuatorCapability]:
        """Declare what capabilities this actuator supports."""
        ...

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        """
        Actuate an authorized action at the downstream execution boundary.

        This is the core seam method. The adapter:
        1. Validates the clearance (quorum threshold, ALLOW-only, correlation_id is UUID)
        2. Maps ExecutionClearance → vendor envelope format
        3. Canonicalizes per RFC 8785 (JCS)
        4. Enforces 4KB ceiling on canonical bytes
        5. Computes digests and signatures
        6. Transmits over mTLS
        7. Classifies the response
        8. Returns ActuationReceipt with fail-closed semantics

        Pre-conditions enforced locally (before wire transmission):
        - clearance.decision == "ALLOW" (no envelope for DENY/HOLD/DEFER)
        - len(clearance.approvals) >= clearance.required_quorum
        - clearance.correlation_id is a valid UUID
        - Canonical envelope ≤ 4096 bytes

        Invariant: An envelope is evidence that ALLOW was reached.
        """
        ...
