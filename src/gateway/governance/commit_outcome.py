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

"""Typed outcomes of a governed committing run and of an approval redemption.

A committing run (a governed tool that commits, seals and actuates) ends in
one of a few outcomes that demand different client responses. They used to
reach clients as free text (``"BLOCKED: ..."``, ``"DEFERRED: ..."``), and an
approval that could not be redeemed was one generic sentence whatever the
reason (POAM-2026-245). A client that must decide whether to wait for the
same approval or give up therefore had nothing to decide on but prose.

This module is the kernel's single definition of those outcomes:

* :class:`ApprovalRedemptionRefusal` names every reason an approval
  (``deferred_id``) is not redeemable, one member per distinct queue state;
* :data:`RETRYABLE_REDEMPTION_REFUSALS` says which of them can still turn
  into a redeemable approval *on the same ticket* (the approval has simply
  not been recorded yet). Clients read retryability from here; they never
  re-derive it;
* :class:`CommitStatus` / :class:`CommitOutcome` are the committing run's
  structured result, with the human ``message`` kept separate and never
  load-bearing. :meth:`CommitOutcome.to_wire` / :meth:`CommitOutcome.from_wire`
  are the wire form carried in an MCP ``CallToolResult.structuredContent``.

The wire form is **not signed**: the advisor trusts it on the same mesh-mTLS
channel it already trusts for committing results. A forged refusal code can
only choose between two fail-closed outcomes (wait on the same ticket, or
stop); it can never cause an execution. The tamper-evident record of every
refusal is the refusal receipt in the evidence chain.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from mcp.types import CallToolResult


class ApprovalRedemptionRefusal(str, Enum):
    """Why an approval (``deferred_id``) could not be redeemed.

    One member per distinct state the approval can be in; none is a
    catch-all hiding a distinction the client must act on.

    PENDING:                   Parked, no approval recorded yet.
    QUORUM_INCOMPLETE:         Some, but not enough, approvals recorded yet.
    UNKNOWN_OR_EXPIRED:        No such ticket: never parked, or its key expired
                               (the two cannot be told apart).
    NOT_AN_APPROVAL:           The ticket is not a human-approval deferral.
    CONSUMED:                  Already redeemed (spent exactly once).
    EXPIRED:                   Resolved by the expiry sweep, never approved.
    RESOLVED_WITHOUT_APPROVAL: Resolved by automated context injection, not by
                               an approval quorum.
    QUORUM_NOT_DISTINCT:       Resolved, but its approvals collapse to fewer
                               distinct approvers than the quorum. A resolved
                               ticket is immutable, so this never recovers.
    UNRECOGNIZED_STATE:        The ticket's status or resolution is not one the
                               kernel knows.
    ACTION_MISMATCH:           Parked for another action.
    STALE_BARRIER_PREVIEW:     Approvals were given against a barrier preview
                               other than the ticket's current one.
    NO_APPROVED_PARAMS:        The ticket carries no approved params.
    PARAMS_NOT_COVERED:        The approved params do not cover the params the
                               committing run evaluated.
    """

    PENDING = "PENDING"
    QUORUM_INCOMPLETE = "QUORUM_INCOMPLETE"
    UNKNOWN_OR_EXPIRED = "UNKNOWN_OR_EXPIRED"
    NOT_AN_APPROVAL = "NOT_AN_APPROVAL"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    RESOLVED_WITHOUT_APPROVAL = "RESOLVED_WITHOUT_APPROVAL"
    QUORUM_NOT_DISTINCT = "QUORUM_NOT_DISTINCT"
    UNRECOGNIZED_STATE = "UNRECOGNIZED_STATE"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    STALE_BARRIER_PREVIEW = "STALE_BARRIER_PREVIEW"
    NO_APPROVED_PARAMS = "NO_APPROVED_PARAMS"
    PARAMS_NOT_COVERED = "PARAMS_NOT_COVERED"


#: Refusals after which the *same* ticket can still become redeemable: the
#: approval has not been recorded (or not fully) yet. Every other refusal is
#: terminal for that ticket.
RETRYABLE_REDEMPTION_REFUSALS: Final[frozenset[ApprovalRedemptionRefusal]] = frozenset(
    {
        ApprovalRedemptionRefusal.PENDING,
        ApprovalRedemptionRefusal.QUORUM_INCOMPLETE,
    }
)


def is_retryable_refusal(refusal: ApprovalRedemptionRefusal | None) -> bool:
    """Whether ``refusal`` leaves the same ticket redeemable later.

    ``None`` (no refusal reason, or one that could not be decoded) is
    terminal: an unknown reason never earns a retry.
    """
    return refusal in RETRYABLE_REDEMPTION_REFUSALS


def decode_redemption_refusal(raw: object) -> ApprovalRedemptionRefusal | None:
    """The member whose value is exactly ``raw``; ``None`` for anything else."""
    if not isinstance(raw, str):
        return None
    try:
        return ApprovalRedemptionRefusal(raw)
    except ValueError:
        return None


class CommitStatus(str, Enum):
    """How a committing run ended.

    EXECUTED:            The action was sealed and actuated.
    DRY_RUN:             The action was sealed; a dry run actuates nothing.
    REFUSED:             Nothing was executed; the run was refused.
    DEFERRED:            Nothing was sealed, committed or refused; the run deferred.
    INDETERMINATE:       Post-wire outcome is UNKNOWN; reservations remain held.
    UNSETTLED_DUPLICATE: Duplicate idempotency key whose prior attempt is IN_FLIGHT/UNKNOWN.
    """

    EXECUTED = "EXECUTED"
    DRY_RUN = "DRY_RUN"
    REFUSED = "REFUSED"
    DEFERRED = "DEFERRED"
    INDETERMINATE = "INDETERMINATE"
    UNSETTLED_DUPLICATE = "UNSETTLED_DUPLICATE"


#: Statuses after which nothing was guaranteed executed.
NOT_EXECUTED_STATUSES: Final[frozenset[CommitStatus]] = frozenset(
    {
        CommitStatus.REFUSED,
        CommitStatus.DEFERRED,
        CommitStatus.INDETERMINATE,
        CommitStatus.UNSETTLED_DUPLICATE,
    }
)

#: Statuses indicating outcome is indeterminate or awaiting settlement, not a policy refusal.
INDETERMINATE_STATUSES: Final[frozenset[CommitStatus]] = frozenset(
    {CommitStatus.INDETERMINATE, CommitStatus.UNSETTLED_DUPLICATE}
)
NON_REFUSAL_STATUSES: Final[frozenset[CommitStatus]] = INDETERMINATE_STATUSES

#: Version tag of :meth:`CommitOutcome.to_wire`. A payload without exactly
#: this tag is not a commit outcome.
COMMIT_OUTCOME_SCHEMA: Final[str] = "cage.commit_outcome/1"


class CommitOutcomeDecodeError(ValueError):
    """A payload is not a :class:`CommitOutcome` this kernel understands."""


@dataclass(frozen=True)
class CommitOutcome:
    """The structured result of one committing run.

    Attributes:
        status: How the run ended.
        message: Human-readable account. Never load-bearing: no decision may
            be taken on it.
        redemption_refusal: Why the approval named by the request could not
            be redeemed, when that is why the run was ``REFUSED``; otherwise
            ``None``.
        deferred_id: For ``DEFERRED``: the ticket that stays resolvable (the
            retained approval itself when ``approval_retained``).
        approval_retained: For ``DEFERRED`` after an approval: the approval was
            not spent and stays redeemable (POAM-2026-104).
    """

    status: CommitStatus
    message: str
    redemption_refusal: ApprovalRedemptionRefusal | None = None
    deferred_id: str | None = None
    approval_retained: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, CommitStatus):
            raise TypeError(f"status must be a CommitStatus, not {self.status!r}")
        if self.redemption_refusal is not None and (
            self.status is not CommitStatus.REFUSED
            or not isinstance(self.redemption_refusal, ApprovalRedemptionRefusal)
        ):
            raise ValueError("redemption_refusal is only set on a REFUSED outcome")
        if self.approval_retained and self.status is not CommitStatus.DEFERRED:
            raise ValueError("approval_retained is only set on a DEFERRED outcome")

    @property
    def executed(self) -> bool:
        """Whether the action was actuated."""
        return self.status is CommitStatus.EXECUTED

    def to_wire(self) -> dict[str, Any]:
        """JSON-safe wire form (MCP ``structuredContent``)."""
        return {
            "schema": COMMIT_OUTCOME_SCHEMA,
            "status": self.status.value,
            "message": self.message,
            "redemption_refusal": (
                self.redemption_refusal.value
                if self.redemption_refusal is not None
                else None
            ),
            "deferred_id": self.deferred_id,
            "approval_retained": self.approval_retained,
        }

    @classmethod
    def from_wire(cls, payload: object) -> CommitOutcome:
        """Decode :meth:`to_wire` output, failing closed.

        Raises:
            CommitOutcomeDecodeError: ``payload`` is not a mapping, lacks the
                exact schema tag, or carries an unknown or missing status.

        A ``REFUSED`` payload whose ``redemption_refusal`` is absent or not a
        known member decodes with ``redemption_refusal=None``, which is
        terminal (:func:`is_retryable_refusal`). ``approval_retained`` counts
        only when it is exactly ``True`` on a ``DEFERRED`` payload.
        """
        if not isinstance(payload, Mapping):
            raise CommitOutcomeDecodeError("commit outcome is not a mapping")
        if payload.get("schema") != COMMIT_OUTCOME_SCHEMA:
            raise CommitOutcomeDecodeError(
                f"commit outcome schema is not {COMMIT_OUTCOME_SCHEMA!r}"
            )
        raw_status = payload.get("status")
        if not isinstance(raw_status, str):
            raise CommitOutcomeDecodeError("commit outcome carries no status")
        try:
            status = CommitStatus(raw_status)
        except ValueError as exc:
            raise CommitOutcomeDecodeError(
                f"unknown commit outcome status {raw_status[:32]!r}"
            ) from exc
        message = payload.get("message")
        deferred_id = payload.get("deferred_id")
        return cls(
            status=status,
            message=message if isinstance(message, str) else "",
            redemption_refusal=(
                decode_redemption_refusal(payload.get("redemption_refusal"))
                if status is CommitStatus.REFUSED
                else None
            ),
            deferred_id=(
                deferred_id
                if status is CommitStatus.DEFERRED
                and isinstance(deferred_id, str)
                and deferred_id
                else None
            ),
            approval_retained=(
                status is CommitStatus.DEFERRED
                and payload.get("approval_retained") is True
            ),
        )


def commit_tool_result(outcome: CommitOutcome) -> CallToolResult:
    """Build the MCP ``CallToolResult`` for a committing run's :class:`CommitOutcome`.

    The typed outcome rides in ``structuredContent`` (:meth:`CommitOutcome.to_wire`);
    ``content`` carries only its prose. ``isError`` is set whenever nothing was
    guaranteed executed (:data:`NOT_EXECUTED_STATUSES`), so a caller that reads
    only ``isError`` or text still fails closed (POAM-2026-245 / POAM-2026-255).
    """
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(
        content=[TextContent(type="text", text=outcome.message)],
        structuredContent=outcome.to_wire(),
        isError=outcome.status in NOT_EXECUTED_STATUSES,
    )
