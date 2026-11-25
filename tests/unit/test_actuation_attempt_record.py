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

"""The kernel's attempt record: one answer to "may this attempt have executed?".

POAM-2026-252. ``dispatch_actuation()`` is the record's only writer: it marks
a dispatch before ``actuate()`` is awaited and settles it from the receipt
once the receipt is ingested. These tests pin the record itself, its scopes
(fresh per scope, merged into the enclosing scope on exit, shared through
``asyncio.to_thread`` and task creation), the transitions ``dispatch_actuation()``
makes, and ``ExecutionLedger.release_unexecuted()`` refusing a dispatched
attempt.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest

from src.gateway.governance import execution_actuator as exec_act
from src.gateway.governance.commit_outcome import CommitStatus
from src.gateway.governance.execution_actuator import dispatch_actuation
from src.gateway.governance.execution_idempotency import (
    ActuationAttemptScopeError,
    Claim,
    Duplicate,
    ExecutionLedger,
    ExecutionStatus,
    actuation_attempt_scope,
    current_actuation_attempt,
    exceptions_after_dispatch,
    outcome_after_dispatch,
)
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ExecutionClearance,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ACCEPTED = ActuationOutcome.ACCEPTED
_REJECTED = ActuationOutcome.REJECTED
_UNKNOWN = ActuationOutcome.UNKNOWN


def _clearance() -> ExecutionClearance:
    return ExecutionClearance(
        thread_id="t-attempt",
        decision="ALLOW",
        decision_path="DIRECT",
        action="governed_action",
        target="target-1",
        operator_urn="urn:op",
        issued_at=0,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        required_quorum=0,
    )


def _receipt(outcome: ActuationOutcome) -> ActuationReceipt:
    return ActuationReceipt(
        accepted=outcome is _ACCEPTED,
        receipt_id="r-1" if outcome is _ACCEPTED else None,
        session_uuid=None,
        raw_receipt=None,
        findings=[] if outcome is _ACCEPTED else [{"code": outcome.value}],
        outcome=outcome,
    )


class _Actuator:
    """Answers with a fixed outcome and notes the attempt record it was called under."""

    actuator_id = "attempt_test_actuator"

    def __init__(self, outcome: ActuationOutcome) -> None:
        self.outcome = outcome
        self.seen: list[tuple[bool, ExecutionStatus]] = []

    async def actuate(self, _clearance: ExecutionClearance) -> ActuationReceipt:
        attempt = current_actuation_attempt()
        assert attempt is not None
        self.seen.append((attempt.dispatched, attempt.status))
        return _receipt(self.outcome)


@pytest.fixture
def ingest(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    stub = AsyncMock(return_value="msg-1")
    monkeypatch.setattr(exec_act, "ingest_actuation_receipt", stub)
    return stub


# ── The record and its scopes ───────────────────────────────────────────────


def test_outside_every_scope_there_is_no_record_and_no_after_dispatch_answer() -> None:
    assert current_actuation_attempt() is None
    assert exceptions_after_dispatch() == ()
    assert outcome_after_dispatch("boom") is None


def test_a_fresh_scope_says_nothing_was_dispatched() -> None:
    with actuation_attempt_scope() as attempt:
        assert current_actuation_attempt() is attempt
        assert attempt.dispatched is False
        assert attempt.status is ExecutionStatus.BLOCKED
        assert attempt.may_have_executed is False
        assert exceptions_after_dispatch() == ()
        assert outcome_after_dispatch("boom") is None
    assert current_actuation_attempt() is None


@pytest.mark.asyncio
async def test_a_nested_scope_is_fresh_and_folds_into_the_enclosing_one_on_exit(
    ingest: AsyncMock,
) -> None:
    with actuation_attempt_scope() as outer:
        with actuation_attempt_scope() as inner:
            assert inner is not outer
            await dispatch_actuation(_Actuator(_ACCEPTED), _clearance())
            assert inner.status is ExecutionStatus.EXECUTED
            # The enclosing record learns of the dispatch only on exit.
            assert outer.dispatched is False
        assert current_actuation_attempt() is outer
        assert outer.dispatched is True
        assert outer.status is ExecutionStatus.EXECUTED


@pytest.mark.asyncio
async def test_the_enclosing_record_knows_before_an_escaping_error_reaches_it(
    ingest: AsyncMock,
) -> None:
    seen: tuple[bool, ExecutionStatus] | None = None
    with actuation_attempt_scope() as outer:
        try:
            with actuation_attempt_scope():
                await dispatch_actuation(_Actuator(_UNKNOWN), _clearance())
                raise RuntimeError("raised after dispatch")
        except RuntimeError:
            seen = (outer.dispatched, outer.status)
    assert seen == (True, ExecutionStatus.UNKNOWN)


@pytest.mark.asyncio
async def test_a_scope_closed_with_a_dispatch_in_flight_leaves_the_enclosing_record_unknown(
    ingest: AsyncMock,
) -> None:
    release = asyncio.Event()

    class _Waiting(_Actuator):
        async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
            await release.wait()
            return await super().actuate(clearance)

    with actuation_attempt_scope() as outer:
        with actuation_attempt_scope():
            in_flight = asyncio.create_task(
                dispatch_actuation(_Waiting(_REJECTED), _clearance())
            )
            await asyncio.sleep(0)
        assert outer.status is ExecutionStatus.UNKNOWN
        release.set()
        await in_flight
        # The late REJECTED receipt settles the closed scope, never this one.
        assert outer.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_the_record_reaches_a_sync_tool_run_by_to_thread(
    ingest: AsyncMock,
) -> None:
    actuator = _Actuator(_UNKNOWN)

    def _sync_tool() -> None:
        # A sync tool can only dispatch on its own loop; its task copies the
        # thread's context, which asyncio.to_thread copied from the caller.
        asyncio.run(dispatch_actuation(actuator, _clearance()))

    with actuation_attempt_scope() as attempt:
        await asyncio.to_thread(_sync_tool)
        assert actuator.seen == [(True, ExecutionStatus.UNKNOWN)]
        assert attempt.dispatched is True
        assert attempt.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_the_record_reaches_a_dispatch_in_a_created_task(
    ingest: AsyncMock,
) -> None:
    with actuation_attempt_scope() as attempt:
        await asyncio.create_task(
            dispatch_actuation(_Actuator(_ACCEPTED), _clearance())
        )
        assert attempt.status is ExecutionStatus.EXECUTED


@pytest.mark.asyncio
async def test_concurrent_requests_keep_separate_records(ingest: AsyncMock) -> None:
    both_inside = asyncio.Barrier(2)

    async def _request(
        outcome: ActuationOutcome | None,
    ) -> tuple[bool, ExecutionStatus]:
        with actuation_attempt_scope() as attempt:
            if outcome is not None:
                await dispatch_actuation(_Actuator(outcome), _clearance())
            await both_inside.wait()
            return attempt.dispatched, attempt.status

    dispatched, idle = await asyncio.gather(_request(_ACCEPTED), _request(None))
    assert dispatched == (True, ExecutionStatus.EXECUTED)
    assert idle == (False, ExecutionStatus.BLOCKED)
    assert current_actuation_attempt() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first", "second", "final"),
    [
        (_ACCEPTED, _REJECTED, ExecutionStatus.EXECUTED),
        (_REJECTED, _ACCEPTED, ExecutionStatus.EXECUTED),
        (_UNKNOWN, _REJECTED, ExecutionStatus.UNKNOWN),
        (_ACCEPTED, _UNKNOWN, ExecutionStatus.UNKNOWN),
        (_REJECTED, _REJECTED, ExecutionStatus.BLOCKED),
    ],
)
async def test_a_later_rejected_receipt_never_hides_an_earlier_dispatch(
    ingest: AsyncMock,
    first: ActuationOutcome,
    second: ActuationOutcome,
    final: ExecutionStatus,
) -> None:
    with actuation_attempt_scope() as attempt:
        await dispatch_actuation(_Actuator(first), _clearance())
        await dispatch_actuation(_Actuator(second), _clearance())
        assert attempt.dispatched is True
        assert attempt.status is final


@pytest.mark.asyncio
async def test_the_record_stays_unknown_while_any_dispatch_is_in_flight(
    ingest: AsyncMock,
) -> None:
    release = asyncio.Event()

    class _Waiting(_Actuator):
        async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
            await release.wait()
            return await super().actuate(clearance)

    with actuation_attempt_scope() as attempt:
        waiting = asyncio.create_task(
            dispatch_actuation(_Waiting(_ACCEPTED), _clearance())
        )
        await asyncio.sleep(0)
        await dispatch_actuation(_Actuator(_REJECTED), _clearance())
        assert attempt.status is ExecutionStatus.UNKNOWN
        release.set()
        await waiting
        assert attempt.status is ExecutionStatus.EXECUTED


# ── What dispatch_actuation() writes, and when ──────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_marks_the_record_before_actuate_runs(ingest: AsyncMock) -> None:
    actuator = _Actuator(_REJECTED)
    with actuation_attempt_scope():
        await dispatch_actuation(actuator, _clearance())
    assert actuator.seen == [(True, ExecutionStatus.UNKNOWN)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status", "may_have_executed"),
    [
        (_ACCEPTED, ExecutionStatus.EXECUTED, True),
        (_UNKNOWN, ExecutionStatus.UNKNOWN, True),
        (_REJECTED, ExecutionStatus.BLOCKED, False),
    ],
)
async def test_the_receipt_settles_the_record(
    ingest: AsyncMock,
    outcome: ActuationOutcome,
    status: ExecutionStatus,
    may_have_executed: bool,
) -> None:
    with actuation_attempt_scope() as attempt:
        receipt = await dispatch_actuation(_Actuator(outcome), _clearance())
        assert receipt.outcome is outcome
        assert attempt.dispatched is True
        assert attempt.status is status
        assert attempt.may_have_executed is may_have_executed


@pytest.mark.asyncio
async def test_the_record_is_settled_only_after_the_receipt_is_ingested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    during_ingest: list[ExecutionStatus] = []

    async def _ingest(*_args: Any, **_kwargs: Any) -> str:
        attempt = current_actuation_attempt()
        assert attempt is not None
        during_ingest.append(attempt.status)
        return "msg-1"

    monkeypatch.setattr(exec_act, "ingest_actuation_receipt", _ingest)
    with actuation_attempt_scope() as attempt:
        await dispatch_actuation(_Actuator(_REJECTED), _clearance())
    assert during_ingest == [ExecutionStatus.UNKNOWN]
    assert attempt.status is ExecutionStatus.BLOCKED


@pytest.mark.asyncio
async def test_an_actuator_that_raises_leaves_the_record_unknown(
    ingest: AsyncMock,
) -> None:
    class _Raising(_Actuator):
        async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
            raise TimeoutError("raised before or after the request left")

    with actuation_attempt_scope() as attempt:
        receipt = await dispatch_actuation(_Raising(_ACCEPTED), _clearance())
    assert receipt.outcome is _UNKNOWN
    assert attempt.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_cancellation_mid_actuate_leaves_the_record_unknown(
    ingest: AsyncMock,
) -> None:
    class _Cancelled(_Actuator):
        async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
            raise asyncio.CancelledError("caller went away mid-dispatch")

    with actuation_attempt_scope() as attempt:
        with pytest.raises(asyncio.CancelledError):
            await dispatch_actuation(_Cancelled(_REJECTED), _clearance())
    assert attempt.dispatched is True
    assert attempt.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [_ACCEPTED, _REJECTED])
async def test_cancellation_while_ingesting_leaves_the_record_unknown(
    monkeypatch: pytest.MonkeyPatch, outcome: ActuationOutcome
) -> None:
    monkeypatch.setattr(
        exec_act,
        "ingest_actuation_receipt",
        AsyncMock(side_effect=asyncio.CancelledError("cancelled while recording")),
    )
    with actuation_attempt_scope() as attempt:
        with pytest.raises(asyncio.CancelledError):
            await dispatch_actuation(_Actuator(outcome), _clearance())
    assert attempt.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_dispatch_outside_a_scope_is_refused_before_actuate(
    ingest: AsyncMock,
) -> None:
    actuator = _Actuator(_ACCEPTED)
    actuator.actuate = AsyncMock(side_effect=AssertionError("must not be awaited"))  # type: ignore[method-assign]
    with pytest.raises(ActuationAttemptScopeError):
        await dispatch_actuation(actuator, _clearance())
    actuator.actuate.assert_not_awaited()
    ingest.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (_UNKNOWN, CommitStatus.INDETERMINATE),
        (_ACCEPTED, CommitStatus.EXECUTED),
    ],
)
async def test_after_dispatch_every_error_is_answered_from_the_record(
    ingest: AsyncMock, outcome: ActuationOutcome, expected: CommitStatus
) -> None:
    with actuation_attempt_scope():
        await dispatch_actuation(_Actuator(outcome), _clearance())
        assert exceptions_after_dispatch() == (Exception,)
        after = outcome_after_dispatch("raised after dispatch")
    assert after is not None
    assert after.status is expected
    assert after.message == "raised after dispatch"


@pytest.mark.asyncio
async def test_after_a_rejected_receipt_errors_keep_their_type_mapping(
    ingest: AsyncMock,
) -> None:
    with actuation_attempt_scope() as attempt:
        await dispatch_actuation(_Actuator(_REJECTED), _clearance())
        assert attempt.dispatched is True
        assert exceptions_after_dispatch() == ()
        assert outcome_after_dispatch("raised after a rejection") is None


# ── ExecutionLedger.release_unexecuted() refuses a dispatched attempt ───────


def _ledgers() -> list[Any]:
    return [
        pytest.param(
            lambda: ExecutionLedger(fakeredis.aioredis.FakeRedis()), id="redis"
        ),
        pytest.param(lambda: ExecutionLedger(None), id="local"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("make_ledger", _ledgers())
@pytest.mark.parametrize(
    ("outcome", "recorded"),
    [
        (_UNKNOWN, ExecutionStatus.UNKNOWN),
        (_ACCEPTED, ExecutionStatus.EXECUTED),
        (_REJECTED, ExecutionStatus.BLOCKED),
    ],
)
async def test_release_after_dispatch_keeps_the_key_and_records_the_attempt(
    ingest: AsyncMock,
    make_ledger: Any,
    outcome: ActuationOutcome,
    recorded: ExecutionStatus,
) -> None:
    ledger = make_ledger()
    claim = await ledger.claim("governed_action", "caller", "k-1")
    assert isinstance(claim, Claim)
    with actuation_attempt_scope():
        await dispatch_actuation(_Actuator(outcome), _clearance())
        assert await ledger.release_unexecuted(claim) is False
    duplicate = await ledger.claim("governed_action", "caller", "k-1")
    assert isinstance(duplicate, Duplicate)
    assert duplicate.status is recorded
    assert duplicate.outcome is not None
    assert duplicate.outcome.startswith(f"{recorded.value}: ")


@pytest.mark.asyncio
@pytest.mark.parametrize("make_ledger", _ledgers())
async def test_release_before_dispatch_frees_the_key(make_ledger: Any) -> None:
    ledger = make_ledger()
    claim = await ledger.claim("governed_action", "caller", "k-2")
    assert isinstance(claim, Claim)
    with actuation_attempt_scope():
        assert await ledger.release_unexecuted(claim) is True
    assert isinstance(await ledger.claim("governed_action", "caller", "k-2"), Claim)


@pytest.mark.asyncio
@pytest.mark.parametrize("make_ledger", _ledgers())
async def test_release_outside_a_scope_frees_the_key(make_ledger: Any) -> None:
    ledger = make_ledger()
    claim = await ledger.claim("governed_action", "caller", "k-3")
    assert isinstance(claim, Claim)
    assert await ledger.release_unexecuted(claim) is True
    assert isinstance(await ledger.claim("governed_action", "caller", "k-3"), Claim)
