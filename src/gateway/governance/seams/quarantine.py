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

"""Out-of-Band Workload Quarantine Seam — Layer 1 Pure Protocol Contract.

Defines the vendor-neutral contract for severing a compromised agent workload's
inference or network path upon critical Control Barrier Function (CBF) or
FTRA breaches.

Architectural Invariant:
    This module must NEVER import from ``src.gateway.governance`` (other than
    sibling seam contracts) or any Layer 2/3/vendor module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ReceiptVerification,
)

EnforcementPlane = Literal[
    "IN_SILICON_DPU",
    "CAGE_INFERENCE_PROXY_SVID",
    "SIMULATED",
]


class QuarantineTriggerReason(StrEnum):
    """Root causes triggering immediate out-of-band workload quarantine."""

    CRITICAL_CBF_BREACH = "CRITICAL_CBF_BREACH"
    FTRA_UNCONTAINABLE_TERMINAL = "FTRA_UNCONTAINABLE_TERMINAL"
    RECONCILIATION_STATE_DRIFT = "RECONCILIATION_STATE_DRIFT"
    SANDBOX_ESCAPE_ATTEMPT = "SANDBOX_ESCAPE_ATTEMPT"


@dataclass(frozen=True)
class QuarantineDirective:
    """CAGE-issued directive to isolate an agent workload or thread."""

    thread_id: str
    agent_svid: str
    sandbox_id: str
    reason: QuarantineTriggerReason
    violation_codes: tuple[str, ...]
    issued_at: int
    correlation_id: str
    governance_decision_digest: str
    nonce: str
    ttl_seconds: int = 3600

    def to_dict(self) -> dict[str, Any]:
        return {
            "thread_id": self.thread_id,
            "agent_svid": self.agent_svid,
            "sandbox_id": self.sandbox_id,
            "reason": str(self.reason.value),
            "violation_codes": list(self.violation_codes),
            "issued_at": self.issued_at,
            "correlation_id": self.correlation_id,
            "governance_decision_digest": self.governance_decision_digest,
            "nonce": self.nonce,
            "ttl_seconds": self.ttl_seconds,
        }


@dataclass(frozen=True)
class QuarantineReceipt:
    """Outcome receipt of an out-of-band quarantine directive."""

    quarantined: bool
    enforcement_plane: EnforcementPlane
    rule_id: str | None
    latency_us: float | None
    outcome: ActuationOutcome
    verification: ReceiptVerification = ReceiptVerification.UNVERIFIED
    findings: list[dict[str, Any]] = field(default_factory=list)
    envelope_digest: str | None = None
    timestamp_utc: str | None = None

    def __post_init__(self) -> None:
        if self.quarantined != (self.outcome is ActuationOutcome.ACCEPTED):
            raise ValueError(
                f"quarantined={self.quarantined} contradicts outcome={self.outcome.value}"
            )
        if (
            self.verification is ReceiptVerification.INVALID
            and self.outcome is not ActuationOutcome.UNKNOWN
        ):
            raise ValueError(
                "an INVALID receipt signature leaves the quarantine outcome UNKNOWN"
            )


@runtime_checkable
class QuarantineActuator(Protocol):
    """Protocol for out-of-band workload quarantine actuators."""

    @property
    def actuator_id(self) -> str: ...

    async def quarantine_workload(
        self, directive: QuarantineDirective
    ) -> QuarantineReceipt: ...

    async def health_check(self) -> bool: ...
