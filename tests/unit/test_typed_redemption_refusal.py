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

"""Typed approval-redemption refusals and the structured commit outcome (POAM-2026-245).

The gateway used to collapse every reason an approval could not be redeemed
into one sentence, and the committing run reported its result as free text.
These tests pin the typed contract end to end on the gateway side:

* every :class:`ApprovalRedemptionRefusal` member is produced by exactly the
  defer-queue state it names, and the check never mutates the ticket;
* retryability is the kernel's frozen set, not a client heuristic;
* ``enforce_approved_governance`` raises :class:`ApprovalRedemptionRefused`
  carrying the member (including ``PARAMS_NOT_COVERED`` and a lost spend);
* the finance committing run returns a :class:`CommitOutcome` whose MCP
  ``structuredContent`` carries it, and ``GatewayMCPClient`` decodes it and
  fails closed on an absent or unknown outcome.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest

from src.gateway.governance.commit_outcome import (
    COMMIT_OUTCOME_SCHEMA,
    RETRYABLE_REDEMPTION_REFUSALS,
    ApprovalRedemptionRefusal,
    CommitOutcome,
    CommitOutcomeDecodeError,
    CommitStatus,
    decode_redemption_refusal,
    is_retryable_refusal,
)
from src.gateway.governance.defer_queue import (
    _KEY_PREFIX,
    ApprovalRecord,
    DeferQueue,
    DeferReason,
    DeferToken,
)
from src.gateway.governance.governor.errors import GovernanceError

pytestmark = [pytest.mark.unit, pytest.mark.local]

R = ApprovalRedemptionRefusal
_ACTION = "execute_trade"
_PARAMS = {"symbol": "AAPL", "amount": 10.0}


def _record(who: str, preview: str | None = None) -> ApprovalRecord:
    return ApprovalRecord(
        approver_urn=f"urn:operator:{who}",
        approved_at_utc="2026-11-23T12:00:00Z",
        auth_method="OIDC",
        auth_principal_hash=f"hash-{who}",
        approved_barrier_preview=preview,
    )


def _token(**fields: Any) -> DeferToken:
    attrs: dict[str, Any] = {
        "thread_id": "thread-typed",
        "defer_reason": DeferReason.HITL_REQUIRED,
        "ttl_seconds": 300,
        "opa_input_snapshot": {"action": _ACTION, "params": dict(_PARAMS)},
        "approvals": [_record("alice"), _record("bob")],
        "resolution": "ESCALATED",
    }
    attrs.update(fields)
    return DeferToken(**attrs)


async def _store(queue: DeferQueue, token: DeferToken, status: str) -> str:
    await queue._redis.hset(
        f"{_KEY_PREFIX}{token.defer_id}",
        mapping={"token": token.model_dump_json(), "status": status, "rev": 1},
    )
    return token.defer_id


async def _snapshot(queue: DeferQueue, defer_id: str) -> dict[str, str]:
    return await queue._redis.hgetall(f"{_KEY_PREFIX}{defer_id}")


@pytest.fixture
def queue() -> DeferQueue:
    return DeferQueue(fakeredis.aioredis.FakeRedis(decode_responses=True))


#: One queue state per refusal member that ``check_redemption`` decides.
_STATES: dict[ApprovalRedemptionRefusal, tuple[dict[str, Any], str]] = {
    R.PENDING: ({"approvals": [], "resolution": None}, "PARKED"),
    R.QUORUM_INCOMPLETE: (
        {"approvals": [_record("alice")], "resolution": None},
        "PARTIALLY_APPROVED",
    ),
    R.NOT_AN_APPROVAL: (
        {"defer_reason": DeferReason.CONFIDENCE_BELOW_THRESHOLD},
        "RESOLVED",
    ),
    R.CONSUMED: ({}, "CONSUMED"),
    R.EXPIRED: ({"resolution": "EXPIRED"}, "RESOLVED"),
    R.RESOLVED_WITHOUT_APPROVAL: ({"resolution": "INJECTED"}, "RESOLVED"),
    R.QUORUM_NOT_DISTINCT: (
        # Two records, one approver: they collapse below the quorum of two.
        {"approvals": [_record("alice"), _record("alice")]},
        "RESOLVED",
    ),
    R.UNRECOGNIZED_STATE: ({}, "SOMETHING_ELSE"),
    R.ACTION_MISMATCH: (
        {"opa_input_snapshot": {"action": "other_action", "params": dict(_PARAMS)}},
        "RESOLVED",
    ),
    R.STALE_BARRIER_PREVIEW: (
        {
            "opa_input_snapshot": {
                "action": _ACTION,
                "params": dict(_PARAMS),
                "barrier_preview": "FAIL",
            },
            "approvals": [_record("alice", "PASS"), _record("bob", "PASS")],
        },
        "RESOLVED",
    ),
    R.NO_APPROVED_PARAMS: (
        {"opa_input_snapshot": {"action": _ACTION, "params": "not-a-dict"}},
        "RESOLVED",
    ),
}


@pytest.mark.parametrize("member", list(_STATES), ids=lambda m: m.value)
async def test_each_queue_state_maps_to_exactly_its_refusal(
    queue: DeferQueue, member: ApprovalRedemptionRefusal
) -> None:
    fields, status = _STATES[member]
    defer_id = await _store(queue, _token(**fields), status)
    before = await _snapshot(queue, defer_id)

    checked = await queue.check_redemption(defer_id, action=_ACTION)

    assert checked.token is None
    assert checked.refusal is member
    assert await queue.redeemable_token(defer_id, action=_ACTION) is None
    # Read-only: a refused check never touches the ticket.
    assert await _snapshot(queue, defer_id) == before


async def test_a_missing_key_is_unknown_or_expired(queue: DeferQueue) -> None:
    checked = await queue.check_redemption("never-parked", action=_ACTION)
    assert checked == (None, R.UNKNOWN_OR_EXPIRED)


async def test_a_quorum_approved_ticket_is_redeemable(queue: DeferQueue) -> None:
    defer_id = await _store(queue, _token(), "RESOLVED")
    checked = await queue.check_redemption(defer_id, action=_ACTION)
    assert checked.refusal is None
    assert checked.token is not None and checked.token.defer_id == defer_id


async def test_parked_then_approved_through_the_queue_turns_redeemable(
    queue: DeferQueue,
) -> None:
    """PENDING and QUORUM_INCOMPLETE are retryable on the same ticket."""
    token = DeferToken(
        thread_id="thread-real",
        defer_reason=DeferReason.HITL_REQUIRED,
        ttl_seconds=300,
        opa_input_snapshot={"action": _ACTION, "params": dict(_PARAMS)},
    )
    await queue.park(token)
    assert (await queue.check_redemption(token.defer_id, action=_ACTION)).refusal is (
        R.PENDING
    )
    await queue.approve(token.defer_id, _record("alice"))
    assert (await queue.check_redemption(token.defer_id, action=_ACTION)).refusal is (
        R.QUORUM_INCOMPLETE
    )
    await queue.approve(token.defer_id, _record("bob"))
    redeemed = await queue.check_redemption(token.defer_id, action=_ACTION)
    assert redeemed.refusal is None and redeemed.token is not None


async def test_consume_redemption_names_uncovered_and_consumed(
    queue: DeferQueue,
) -> None:
    defer_id = await _store(queue, _token(), "RESOLVED")

    uncovered = await queue.consume_redemption(
        defer_id, action=_ACTION, covers=lambda _p: False
    )
    assert uncovered == (None, R.PARAMS_NOT_COVERED)
    assert (await _snapshot(queue, defer_id))["status"] == "RESOLVED"  # not burnt

    spent = await queue.consume_redemption(
        defer_id, action=_ACTION, covers=lambda _p: True
    )
    assert spent.refusal is None and spent.token is not None
    replay = await queue.consume_redemption(
        defer_id, action=_ACTION, covers=lambda _p: True
    )
    assert replay == (None, R.CONSUMED)


async def test_a_lost_compare_and_swap_reports_the_state_it_left(
    queue: DeferQueue,
) -> None:
    defer_id = await _store(queue, _token(), "RESOLVED")
    # Another caller wins between the check and the swap.
    with patch.object(queue, "_atomic_resolve", new=AsyncMock(return_value=False)):
        await queue._redis.hset(f"{_KEY_PREFIX}{defer_id}", "status", "CONSUMED")
        lost = await queue.consume_redemption(
            defer_id, action=_ACTION, covers=lambda _p: True
        )
    assert lost == (None, R.CONSUMED)


def test_every_member_is_produced_by_some_queue_path() -> None:
    produced = set(_STATES) | {R.UNKNOWN_OR_EXPIRED, R.PARAMS_NOT_COVERED}
    assert produced == set(ApprovalRedemptionRefusal)


def test_retryable_refusals_are_exactly_the_not_yet_approved_ones() -> None:
    assert RETRYABLE_REDEMPTION_REFUSALS == {R.PENDING, R.QUORUM_INCOMPLETE}
    for member in ApprovalRedemptionRefusal:
        assert is_retryable_refusal(member) is (
            member in (R.PENDING, R.QUORUM_INCOMPLETE)
        )
    assert is_retryable_refusal(None) is False


def test_decode_refusal_is_exact() -> None:
    assert decode_redemption_refusal("PENDING") is R.PENDING
    for raw in ("pending", " PENDING", "PENDING_X", None, 1, R):
        assert decode_redemption_refusal(raw) is None


# ── CommitOutcome wire form ──────────────────────────────────────────────────


def test_outcome_round_trips_through_the_wire() -> None:
    outcomes = [
        CommitOutcome(CommitStatus.EXECUTED, "EXECUTED: x"),
        CommitOutcome(CommitStatus.DRY_RUN, "DRY_RUN: x"),
        CommitOutcome(CommitStatus.REFUSED, "no", redemption_refusal=R.CONSUMED),
        CommitOutcome(CommitStatus.REFUSED, "no"),
        CommitOutcome(
            CommitStatus.DEFERRED, "wait", deferred_id="d-1", approval_retained=True
        ),
    ]
    for outcome in outcomes:
        assert CommitOutcome.from_wire(outcome.to_wire()) == outcome


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "REFUSED",
        {},
        {"status": "EXECUTED"},  # no schema tag
        {"schema": "cage.commit_outcome/2", "status": "EXECUTED"},
        {"schema": COMMIT_OUTCOME_SCHEMA},
        {"schema": COMMIT_OUTCOME_SCHEMA, "status": "MAYBE"},
        {"schema": COMMIT_OUTCOME_SCHEMA, "status": "executed"},
    ],
)
def test_an_unrecognised_outcome_never_decodes(payload: Any) -> None:
    with pytest.raises(CommitOutcomeDecodeError):
        CommitOutcome.from_wire(payload)


def test_unknown_refusal_and_loose_retention_decode_terminal() -> None:
    refused = CommitOutcome.from_wire(
        {
            "schema": COMMIT_OUTCOME_SCHEMA,
            "status": "REFUSED",
            "redemption_refusal": "NOT_A_MEMBER",
        }
    )
    assert refused.redemption_refusal is None
    assert not is_retryable_refusal(refused.redemption_refusal)
    deferred = CommitOutcome.from_wire(
        {
            "schema": COMMIT_OUTCOME_SCHEMA,
            "status": "DEFERRED",
            "approval_retained": "true",
        }
    )
    assert deferred.approval_retained is False
    executed = CommitOutcome.from_wire(
        {
            "schema": COMMIT_OUTCOME_SCHEMA,
            "status": "EXECUTED",
            "redemption_refusal": "PENDING",
            "approval_retained": True,
        }
    )
    assert executed.redemption_refusal is None and not executed.approval_retained


def test_an_outcome_cannot_carry_a_refusal_unless_refused() -> None:
    with pytest.raises(ValueError):
        CommitOutcome(CommitStatus.EXECUTED, "x", redemption_refusal=R.PENDING)
    with pytest.raises(ValueError):
        CommitOutcome(CommitStatus.REFUSED, "x", approval_retained=True)


# ── GatewayMCPClient decodes structuredContent, failing closed ───────────────


async def _client_outcome(result: Any) -> CommitOutcome:
    from src.gateway.infrastructure.mcp_client import GatewayMCPClient

    client = GatewayMCPClient.__new__(GatewayMCPClient)
    with patch.object(
        GatewayMCPClient,
        "_call_tool_at_most_once",
        new=AsyncMock(return_value=result),
    ):
        return await client.call_commit_tool("execute_trade_action", {})


async def test_client_decodes_a_refusal_even_when_is_error_is_set() -> None:
    wire = CommitOutcome(
        CommitStatus.REFUSED, "prose", redemption_refusal=R.PENDING
    ).to_wire()
    result = SimpleNamespace(
        structuredContent=wire, content=[SimpleNamespace(text="prose")], isError=True
    )
    outcome = await _client_outcome(result)
    assert outcome.status is CommitStatus.REFUSED
    assert outcome.redemption_refusal is R.PENDING


@pytest.mark.parametrize(
    "structured",
    [None, {}, {"schema": COMMIT_OUTCOME_SCHEMA, "status": "UNKNOWN"}],
)
async def test_client_fails_closed_without_a_decodable_outcome(
    structured: Any,
) -> None:
    from src.gateway.infrastructure.mcp_client import (
        MCPCommitOutcomeUnrecognizedError,
    )

    # Prose that looks like success is never read.
    result = SimpleNamespace(
        structuredContent=structured,
        content=[SimpleNamespace(text="EXECUTED: AAPL")],
        isError=False,
    )
    with pytest.raises(MCPCommitOutcomeUnrecognizedError):
        await _client_outcome(result)


# ── enforce_approved_governance raises the typed refusal ────────────────────


def _open(queue: DeferQueue):
    @asynccontextmanager
    async def _ctx():
        yield queue

    return _ctx


async def _enforce(queue: DeferQueue, defer_id: str, governor: Any) -> Any:
    from src.gateway.server import governance_middleware as gm

    with (
        patch("src.gateway.governance.defer_queue.open_defer_queue", new=_open(queue)),
        patch.object(gm, "_emit_refusal_receipt", new=AsyncMock(return_value="")),
    ):
        return await gm.enforce_approved_governance(
            governor,
            _ACTION,
            dict(_PARAMS),
            deferred_id=defer_id,
            approval_covers=lambda approved, evaluated: True,
        )


@pytest.mark.parametrize("member", list(_STATES), ids=lambda m: m.value)
async def test_premature_or_dead_approval_raises_its_member_and_spends_nothing(
    queue: DeferQueue, member: ApprovalRedemptionRefusal
) -> None:
    from src.gateway.server.governance_middleware import ApprovalRedemptionRefused

    fields, status = _STATES[member]
    defer_id = await _store(queue, _token(**fields), status)
    before = await _snapshot(queue, defer_id)
    governor = MagicMock()
    governor.revalidate_post_hitl = AsyncMock()

    with pytest.raises(ApprovalRedemptionRefused) as exc:
        await _enforce(queue, defer_id, governor)

    assert exc.value.refusal is member
    governor.revalidate_post_hitl.assert_not_awaited()
    assert await _snapshot(queue, defer_id) == before  # the ticket is untouched


async def test_uncovered_params_inside_the_run_raise_params_not_covered(
    queue: DeferQueue,
) -> None:
    from src.gateway.server.governance_middleware import ApprovalRedemptionRefused

    defer_id = await _store(queue, _token(), "RESOLVED")

    async def _revalidate(action: str, params: dict[str, Any], *, approval: Any):
        if not approval.covers({"symbol": "MSFT", "amount": 99.0}):
            raise GovernanceError("[APPROVAL_NOT_REDEEMABLE] does not cover")
        raise AssertionError("covers should have refused")

    from src.gateway.server import governance_middleware as gm

    governor = MagicMock()
    governor.revalidate_post_hitl = _revalidate
    with (
        patch("src.gateway.governance.defer_queue.open_defer_queue", new=_open(queue)),
        patch.object(gm, "_emit_refusal_receipt", new=AsyncMock(return_value="")),
        pytest.raises(ApprovalRedemptionRefused) as exc,
    ):
        await gm.enforce_approved_governance(
            governor,
            _ACTION,
            dict(_PARAMS),
            deferred_id=defer_id,
            approval_covers=lambda approved, evaluated: approved == evaluated,
        )
    assert exc.value.refusal is R.PARAMS_NOT_COVERED
    assert (await _snapshot(queue, defer_id))["status"] == "RESOLVED"


async def test_a_lost_spend_inside_the_run_raises_consumed(queue: DeferQueue) -> None:
    from src.gateway.server import governance_middleware as gm
    from src.gateway.server.governance_middleware import ApprovalRedemptionRefused

    defer_id = await _store(queue, _token(), "RESOLVED")

    async def _revalidate(action: str, params: dict[str, Any], *, approval: Any):
        # A concurrent redemption consumed the approval first.
        await queue._redis.hset(f"{_KEY_PREFIX}{defer_id}", "status", "CONSUMED")
        if not await approval.spend(dict(_PARAMS)):
            raise GovernanceError("[APPROVAL_NOT_REDEEMABLE] already spent")
        raise AssertionError("spend should have failed")

    governor = MagicMock()
    governor.revalidate_post_hitl = _revalidate
    with (
        patch("src.gateway.governance.defer_queue.open_defer_queue", new=_open(queue)),
        patch.object(gm, "_emit_refusal_receipt", new=AsyncMock(return_value="")),
        pytest.raises(ApprovalRedemptionRefused) as exc,
    ):
        await gm.enforce_approved_governance(
            governor,
            _ACTION,
            dict(_PARAMS),
            deferred_id=defer_id,
            approval_covers=lambda approved, evaluated: True,
        )
    assert exc.value.refusal is R.CONSUMED


async def test_a_stage_refusal_after_approval_carries_no_redemption_refusal(
    queue: DeferQueue,
) -> None:
    from src.gateway.server import governance_middleware as gm

    defer_id = await _store(queue, _token(), "RESOLVED")
    governor = MagicMock()
    governor.revalidate_post_hitl = AsyncMock(
        side_effect=GovernanceError("[OPA] refused")
    )
    with pytest.raises(gm.GovernanceBlockedError) as exc:
        await _enforce(queue, defer_id, governor)
    assert not isinstance(exc.value, gm.ApprovalRedemptionRefused)


# ── The finance committing run returns the typed outcome ─────────────────────


async def _govern(side_effect: BaseException | None, *, deferred_id: str | None):
    from src.cage_finance.tools import tool_provider as tp

    with (
        patch.object(
            tp, "enforce_approved_governance", new=AsyncMock(side_effect=side_effect)
        ),
        patch.object(tp, "enforce_governance", new=AsyncMock(side_effect=side_effect)),
    ):
        return await tp._govern_and_actuate(
            dict(_PARAMS),
            deferred_id=deferred_id,
            dry_run=False,
            governor=MagicMock(),
        )


async def test_committing_run_reports_the_redemption_refusal() -> None:
    from src.gateway.server.governance_middleware import ApprovalRedemptionRefused

    outcome = await _govern(
        ApprovalRedemptionRefused("Governance Blocked: x", refusal=R.PENDING),
        deferred_id="d-1",
    )
    assert outcome.status is CommitStatus.REFUSED
    assert outcome.redemption_refusal is R.PENDING


async def test_committing_run_reports_a_plain_refusal_without_a_member() -> None:
    from src.gateway.server.governance_middleware import GovernanceBlockedError

    outcome = await _govern(GovernanceBlockedError("blocked"), deferred_id=None)
    assert outcome.status is CommitStatus.REFUSED
    assert outcome.redemption_refusal is None


async def test_committing_run_reports_a_retained_deferral() -> None:
    from src.gateway.governance.governor.errors import GovernanceDeferred
    from src.gateway.server.governance_middleware import ActionDeferred

    cause = MagicMock(spec=GovernanceDeferred)
    cause.deferred_id = "d-1"
    cause.defer_reason = "WARRANT_INELIGIBLE"
    cause.reliance = []
    outcome = await _govern(
        ActionDeferred(cause, approval_retained=True), deferred_id="d-1"
    )
    assert outcome.status is CommitStatus.DEFERRED
    assert outcome.approval_retained is True
    assert outcome.deferred_id == "d-1"


def test_mcp_result_carries_the_outcome_and_marks_unexecuted_as_error() -> None:
    from src.cage_finance.tools.tool_provider import _call_tool_result

    refused = CommitOutcome(CommitStatus.REFUSED, "no", redemption_refusal=R.CONSUMED)
    result = _call_tool_result(refused)
    assert result.isError is True
    assert CommitOutcome.from_wire(result.structuredContent) == refused
    assert [c.text for c in result.content] == ["no"]
    executed = _call_tool_result(CommitOutcome(CommitStatus.EXECUTED, "ok"))
    assert executed.isError is False
