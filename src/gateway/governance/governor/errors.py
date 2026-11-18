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

from typing import Any

from src.gateway.governance.contracts import RefusalReceipt


class GovernanceError(Exception):
    """Raised when a symbolic rule is violated.

    Args:
        message: Human-readable violation description.  Begins with the stable
                 ``[CTRL_*]`` control ID so log aggregators can key on it.
        payload: Optional structured dict emitted to OTel / SIEM consumers.
                 Contains ``control_id``, ``primary_framework``,
                 ``legacy_citation``, etc. sourced from control_mappings.json.
        receipt: Optional immutable RefusalReceipt proof object.
        violations: Every violation behind the refusal, deciding one first.
                    Defaults to ``[message]``.
    """

    def __init__(
        self,
        message: str,
        payload: dict[str, Any] | None = None,
        receipt: RefusalReceipt | None = None,
        violations: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.payload: dict[str, Any] = payload or {}
        self.receipt: RefusalReceipt | None = receipt
        self.violations: list[str] = list(violations) if violations else [message]


class GovernanceDeferred(GovernanceError):
    """Raised when a committing run defers instead of refusing.

    A deferral seals nothing and commits nothing, so it is a
    :class:`GovernanceError` to every caller that only needs to stop.  It is
    distinct from a refusal in what it leaves behind: the post-approval
    committing run raises it on a warrant-ineligible finding, and the human
    approval it was given stays unspent and redeemable (POAM-2026-104).

    Args:
        message: Human-readable description of why the run deferred.
        defer_reason: The ``DeferReason`` value (e.g. ``WARRANT_INELIGIBLE``).
        deferred_id: The id of the parked record that stays resolvable (for a
            post-approval run, the approval token itself).
        reliance: The evidence form of the reliance records behind the
            deferral (``reliance_evidence()``).
        violations: Every finding behind the deferral.
    """

    def __init__(
        self,
        message: str,
        *,
        defer_reason: str,
        deferred_id: str,
        reliance: list[dict[str, Any]] | None = None,
        violations: list[str] | None = None,
    ) -> None:
        super().__init__(message, violations=violations)
        self.defer_reason: str = defer_reason
        self.deferred_id: str = deferred_id
        self.reliance: list[dict[str, Any]] = list(reliance or [])


class DeferQueueUnavailableError(GovernanceError):
    """Raised when a committing deferral cannot be persisted to DeferQueue (F-05).

    Subclasses :class:`GovernanceError` so direct ``govern()`` callers fail
    closed uniformly, while ``enforce_governance()`` catches it ahead of
    generic ``GovernanceError`` to avoid emitting a contradictory
    ``GOVERNANCE_REFUSAL_RECEIPT`` after ``GOVERNANCE_DEFERRAL (persisted=False)``
    has already been chained.
    """

    def __init__(
        self,
        message: str,
        *,
        defer_reason: str,
        violations: list[str] | None = None,
    ) -> None:
        super().__init__(message, violations=violations)
        self.defer_reason: str = defer_reason


class GovernanceInfrastructureError(GovernanceError):
    """Raised when governance blocks fail-closed due to dependency unavailability.

    Subclasses :class:`GovernanceError` (always with ``receipt=None``) so direct
    ``govern()`` callers block fail-closed without minting a seal, while gateway
    HTTP and middleware surfaces catch it ahead of :class:`GovernanceError` to
    emit ``GOVERNANCE_INFRASTRUCTURE_BLOCK`` and HTTP 503 rather than signing a
    false policy refusal receipt (POAM-2026-233).
    """

    def __init__(
        self,
        message: str,
        *,
        dependency: str,
        failure_code: str,
        error_code: str = "governance_dependency_unavailable",
        payload: dict[str, Any] | None = None,
        violations: list[str] | None = None,
    ) -> None:
        super().__init__(message, payload=payload, receipt=None, violations=violations)
        self.dependency: str = dependency
        self.failure_code: str = failure_code
        self.error_code: str = error_code


class ApprovalSpendUnavailableError(RuntimeError):
    """Raised when PostHitlApproval.spend() cannot reach DeferQueue storage (F-03, POAM-2026-233).

    Distinct from returning ``False``, which means DeferQueue answered and proved
    the approval was already spent, expired, or non-covering.
    """

    def __init__(self, message: str, *, pipeline_result: Any = None) -> None:
        super().__init__(message)
        self.pipeline_result: Any = pipeline_result
