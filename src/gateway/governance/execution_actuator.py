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
ExecutionActuator protocol and supporting types for downstream execution boundary.

CAGE is the ISSUER, not the consumer. This is a fundamentally different trust
boundary from the upstream NormativeProvider/AttestationProvider seams.
"""

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


class ActuatorRegistry:
    """
    Registry of ExecutionActuator instances.

    Unlike NormativeProvider's singleton, this supports N registered actuators
    dispatched by claim (which actions each actuator handles).

    The registry shape is fixed now so a second actuator does not force a refactor.
    """

    def __init__(self) -> None:
        self._actuators: dict[str, ExecutionActuator] = {}
        self._claims: dict[str, set[str]] = {}  # actuator_id -> set of action patterns

    def register(
        self,
        actuator: ExecutionActuator,
        claims: set[str] | None = None,
    ) -> None:
        """
        Register an actuator.

        Args:
            actuator: The ExecutionActuator instance
            claims: Set of action patterns this actuator handles (e.g., {"trade.*", "transfer.*"})
                   If None, the actuator handles all actions (default for the first actuator)
        """
        actuator_id = actuator.actuator_id
        if actuator_id in self._actuators:
            raise ValueError(f"Actuator {actuator_id} already registered")

        if not isinstance(actuator, ExecutionActuator):
            raise TypeError(
                f"Actuator must implement ExecutionActuator protocol, got {type(actuator)}"
            )

        self._actuators[actuator_id] = actuator
        self._claims[actuator_id] = claims if claims is not None else {"*"}

    def get_actuator(self, action: str) -> ExecutionActuator | None:
        """
        Retrieve the actuator that handles the given action.

        Returns the first matching actuator, or None if no actuator claims it.
        """
        for actuator_id, patterns in self._claims.items():
            if "*" in patterns:
                return self._actuators[actuator_id]
            # Simple prefix matching for now
            for pattern in patterns:
                if pattern.endswith("*") and action.startswith(pattern[:-1]):
                    return self._actuators[actuator_id]
                elif action == pattern:
                    return self._actuators[actuator_id]
        return None

    def list_actuators(self) -> list[str]:
        """Return list of registered actuator IDs."""
        return list(self._actuators.keys())
