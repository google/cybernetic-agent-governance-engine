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

"""``execute_trade_action`` executes a ``idempotency_key`` at most once (#514).

The governor, seal check and broker are stand-ins; the execution ledger is
real, over fakeredis, so these tests observe what reaches the broker.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest

from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    ExecutionLedger,
    ExecutionStatus,
    UnsettledDuplicate,
)
from src.gateway.governance.governor.errors import GovernanceInfrastructureError
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import ActuationOutcome, ActuationReceipt
from tests.fixtures.trade_inputs import sealed_governance, trade_governor

pytestmark = [
    pytest.mark.unit,
    pytest.mark.local,
    pytest.mark.usefixtures("connected_evidence_sink"),
]

_TXN = "0b6c7f4e-2a51-4f7e-9c3d-8e1f2a3b4c5d"
_KEY = ExecutionLedger.key_for("execute_trade", SHARED_CALLER, _TXN)


def _accepted() -> ActuationReceipt:
    return ActuationReceipt(
        accepted=True,
        receipt_id="r-1",
        session_uuid="s-1",
        raw_receipt={"execution_result": "EXECUTED"},
        outcome=ActuationOutcome.ACCEPTED,
    )


def _not_accepted(outcome: ActuationOutcome) -> ActuationReceipt:
    return ActuationReceipt(
        accepted=False,
        receipt_id=None,
        session_uuid=None,
        raw_receipt=None,
        findings=[{"code": "BROKER", "detail": outcome.value.lower()}],
        outcome=outcome,
    )


@pytest.fixture
def redis() -> fakeredis.aioredis.FakeRedis:
    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def governor(redis: fakeredis.aioredis.FakeRedis) -> MagicMock:
    gov = trade_governor()
    gov.components.execution_ledger = ExecutionLedger(redis)
    return gov


@contextmanager
def _pipeline(
    actuate: AsyncMock, governance: AsyncMock | None = None
) -> Iterator[tuple[AsyncMock, AsyncMock]]:
    """Seal-issuing governance, a no-op seal check and a scripted broker."""
    governance = governance or AsyncMock(side_effect=sealed_governance("seal-1"))
    with (
        patch("src.cage_finance.tools.tool_provider.enforce_governance", governance),
        patch(
            "src.gateway.governance.routing_seal.verify_and_consume_seal",
            new_callable=AsyncMock,
        ),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
        patch("src.gateway.infrastructure.redis_client.redis_client", None),
        patch(
            "src.gateway.server.governance_middleware.record_refusal",
            new_callable=AsyncMock,
        ) as refusals,
    ):
        yield governance, refusals


async def _trade(governor: Any, **overrides: Any) -> CommitOutcome:
    kwargs: dict[str, Any] = {
        "symbol": "AAPL",
        "amount": 10.0,
        "currency": "USD",
        "confidence": 0.99,
        "idempotency_key": _TXN,
        "governor": governor,
    }
    kwargs.update(overrides)
    return await execute_trade_action(**kwargs)


@pytest.mark.asyncio
async def test_duplicate_returns_the_original_outcome_and_dispatches_once(
    governor: MagicMock,
) -> None:
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate) as (governance, refusals):
        first = await _trade(governor)
        second = await _trade(governor)

    assert first.status is CommitStatus.EXECUTED
    assert first.message.startswith("EXECUTED: AAPL x 10.0")
    assert second == first
    assert actuate.await_count == 1
    assert governance.await_count == 1  # the duplicate is not governed again
    refusals.assert_awaited_once()
    action, reason = refusals.await_args.args
    assert action == "execute_trade"
    assert "duplicate submission" in reason and "EXECUTED" in reason
    assert refusals.await_args.kwargs["oscal_control_ref"] == "AC-3"


@pytest.mark.asyncio
async def test_concurrent_duplicates_dispatch_exactly_once(governor: MagicMock) -> None:
    async def slow_broker(*_: Any, **__: Any) -> ActuationReceipt:
        await asyncio.sleep(0.05)
        return _accepted()

    actuate = AsyncMock(side_effect=slow_broker)
    with _pipeline(actuate):
        results = await asyncio.gather(
            *(_trade(governor) for _ in range(10)), return_exceptions=True
        )

    assert actuate.await_count == 1
    executed = [r for r in results if isinstance(r, CommitOutcome)]
    in_flight = [
        r
        for r in results
        if isinstance(r, UnsettledDuplicate) and str(r).startswith("IN_FLIGHT:")
    ]
    assert len(executed) >= 1
    assert all(
        r.status is CommitStatus.EXECUTED and r.message.startswith("EXECUTED: AAPL")
        for r in executed
    )
    assert len(executed) + len(in_flight) == len(results)


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.governance.execution_idempotency:ExecutionLedger.claim#no Redis is configured for the execution ledger",
    'src.gateway.governance.execution_idempotency:execution_claim_scope#infra_dependency="execution_ledger"',
)
async def test_enforcing_posture_without_redis_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_ENV", "production")
    gov = trade_governor()
    object.__setattr__(gov.components, "execution_ledger", ExecutionLedger(None))
    actuate = AsyncMock(return_value=_accepted())

    with _pipeline(actuate) as (governance, refusals):
        with pytest.raises(GovernanceInfrastructureError) as exc_info:
            await _trade(gov)

    assert exc_info.value.error_code == "execution_ledger_unavailable"
    assert exc_info.value.dependency == "execution_ledger"
    assert exc_info.value.failure_code == "EXECUTION_LEDGER_UNAVAILABLE"
    assert exc_info.value.receipt is None
    governance.assert_not_awaited()
    actuate.assert_not_awaited()
    refusals.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_outcome_keeps_the_claim(
    governor: MagicMock, redis: fakeredis.aioredis.FakeRedis
) -> None:
    from src.gateway.governance.seams.actuation import ActuationIndeterminateError

    actuate = AsyncMock(return_value=_not_accepted(ActuationOutcome.UNKNOWN))
    with _pipeline(actuate) as (governance, _):
        with pytest.raises(
            ActuationIndeterminateError, match="indeterminate"
        ) as exc_info:
            await _trade(governor)
        assert not isinstance(exc_info.value, SymbolicGovernorViolation)
        # Never read as settled: the duplicate raises, as the first attempt did.
        with pytest.raises(UnsettledDuplicate, match="^UNKNOWN: .*pending"):
            await _trade(governor)
        with pytest.raises(UnsettledDuplicate, match="^UNKNOWN: "):
            await _trade(governor, deferred_id="d-1")  # nor re-claimed

    assert actuate.await_count == 1
    assert governance.await_count == 1
    duplicate = await governor.components.execution_ledger.claim(
        "execute_trade", SHARED_CALLER, _TXN
    )
    assert duplicate.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.cage_finance.tools.tool_provider:_govern_and_actuate#Actuation rejected:",
    "src.gateway.governance.execution_idempotency:_settle_claim_on_error#attempt.status.value",
    "src.gateway.governance.execution_idempotency:execution_claim_scope#duplicate=claimed",
)
async def test_rejected_actuation_is_recorded_as_blocked(governor: MagicMock) -> None:
    from src.gateway.governance.seams.actuation import ActuationRejectedError

    actuate = AsyncMock(return_value=_not_accepted(ActuationOutcome.REJECTED))
    with _pipeline(actuate):
        with pytest.raises(
            ActuationRejectedError, match="Actuation rejected"
        ) as exc_info:
            await _trade(governor)
        assert not isinstance(exc_info.value, SymbolicGovernorViolation)
        replay = await _trade(governor)

    assert replay.status is CommitStatus.REFUSED
    assert replay.message.startswith("BLOCKED: ")
    assert actuate.await_count == 1


@pytest.mark.asyncio
async def test_governance_refusal_is_replayed_without_governing_again(
    governor: MagicMock,
) -> None:
    governance = AsyncMock(side_effect=PermissionError("Governance Blocked: DENY"))
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate, governance):
        first = await _trade(governor)
        second = await _trade(governor)

    assert first == CommitOutcome(
        CommitStatus.REFUSED, "BLOCKED: Governance Blocked: DENY"
    )
    assert second == first
    assert governance.await_count == 1
    actuate.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.governance.execution_idempotency:ExecutionLedger.claim#if int(reclaimed) == 1:",
    "src.cage_finance.tools.tool_provider:_govern_and_actuate#enforce_approved_governance(",
)
async def test_an_approval_reclaims_a_blocked_key_and_executes_once(
    governor: MagicMock,
) -> None:
    refused = AsyncMock(side_effect=PermissionError("Governance Blocked: HITL"))
    approved = AsyncMock(side_effect=sealed_governance("seal-1"))
    actuate = AsyncMock(return_value=_accepted())
    with (
        _pipeline(actuate, refused),
        patch(
            "src.cage_finance.tools.tool_provider.enforce_approved_governance",
            approved,
        ),
    ):
        blocked = await _trade(governor)
        assert await _trade(governor) == blocked  # a plain resubmission replays
        executed = await _trade(governor, deferred_id="d-1")
        # Once the trade executed, nothing re-claims the key, an approval included.
        assert await _trade(governor, deferred_id="d-2") == executed
        assert await _trade(governor) == executed

    assert blocked == CommitOutcome(
        CommitStatus.REFUSED, "BLOCKED: Governance Blocked: HITL"
    )
    assert executed.status is CommitStatus.EXECUTED
    assert executed.message.startswith("EXECUTED: AAPL")
    assert refused.await_count == 1
    assert approved.await_count == 1
    assert actuate.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("idempotency_key", "expected"),
    [
        (None, "BLOCKED: idempotency_key is required"),
        ("", "BLOCKED: idempotency_key is required"),
        (str(uuid.uuid1()), "BLOCKED: invalid idempotency_key"),
        ("not-a-uuid", "BLOCKED: invalid idempotency_key"),
    ],
    ids=["missing", "empty", "uuid1", "garbage"],
)
async def test_missing_or_invalid_idempotency_key_is_refused(
    governor: MagicMock, idempotency_key: str | None, expected: str
) -> None:
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate) as (governance, _):
        result = await _trade(governor, idempotency_key=idempotency_key)

    assert result.status is CommitStatus.REFUSED
    assert result.message.startswith(expected)
    governance.assert_not_awaited()
    actuate.assert_not_awaited()


@pytest.mark.asyncio
async def test_idempotency_key_case_does_not_create_a_second_key(
    governor: MagicMock,
) -> None:
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate):
        first = await _trade(governor, idempotency_key=_TXN.upper())
        second = await _trade(governor, idempotency_key=_TXN)

    assert second == first
    assert actuate.await_count == 1


@pytest.mark.asyncio
async def test_dry_run_claims_nothing(
    governor: MagicMock, redis: fakeredis.aioredis.FakeRedis
) -> None:
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate):
        dry = await _trade(governor, dry_run=True)
        assert dry.status is CommitStatus.DRY_RUN
        assert dry.message.startswith("DRY_RUN:")
        assert await redis.exists(_KEY) == 0
        executed = await _trade(governor)

    assert executed.status is CommitStatus.EXECUTED
    assert executed.message.startswith("EXECUTED: AAPL")
    assert actuate.await_count == 1


def _infrastructure_error_after_dispatch(kind: str) -> Exception:
    """An infrastructure failure of ``kind``, raised once the broker was called.

    Nothing after dispatch raises one today: the settle step stands in for
    the first step that does. Both types the ledger may free a key on are
    covered.
    """
    if kind == "governance":
        return GovernanceInfrastructureError(
            "settlement store unreachable after dispatch",
            dependency="settlement_store",
            failure_code="SETTLEMENT_STORE_UNAVAILABLE",
            error_code="settlement_store_unavailable",
        )
    from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError

    return EvidenceChainUnavailableError("evidence chain unreachable after dispatch")


def _first_attempt_errors() -> tuple[type[BaseException], ...]:
    """What the first attempt may raise; only the ledger's answer is asserted."""
    from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError
    from src.gateway.governance.seams.actuation import ActuationIndeterminateError

    return (
        GovernanceInfrastructureError,
        EvidenceChainUnavailableError,
        ActuationIndeterminateError,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["governance", "evidence_chain"])
async def test_infrastructure_error_after_accepted_dispatch_keeps_the_claim(
    governor: MagicMock, kind: str
) -> None:
    """The broker accepted, so the key stays EXECUTED whatever fails afterwards.

    The ledger frees a key on an infrastructure error only while nothing has
    been dispatched (``release_unexecuted``). After dispatch it records what
    the broker said, and a resubmission replays that reply instead of
    trading again.
    """
    actuate = AsyncMock(return_value=_accepted())
    settle = AsyncMock(side_effect=_infrastructure_error_after_dispatch(kind))
    with _pipeline(actuate) as (governance, _):
        with patch("src.cage_finance.tools.tool_provider._settle", settle):
            with pytest.raises(_first_attempt_errors()):
                await _trade(governor)
        replay = await _trade(governor)  # same idempotency_key, healthy settle

    assert replay.status is CommitStatus.EXECUTED
    assert actuate.await_count == 1
    assert governance.await_count == 1
    duplicate = await governor.components.execution_ledger.claim(
        "execute_trade", SHARED_CALLER, _TXN
    )
    assert duplicate.status is ExecutionStatus.EXECUTED


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["governance", "evidence_chain"])
async def test_infrastructure_error_after_unknown_dispatch_keeps_the_claim(
    governor: MagicMock, kind: str
) -> None:
    """The broker answered UNKNOWN, so the key stays UNKNOWN whatever fails afterwards.

    A resubmission raises ``UnsettledDuplicate``, as for any first attempt
    that may have executed, and an approval cannot re-claim the key either.
    """
    actuate = AsyncMock(return_value=_not_accepted(ActuationOutcome.UNKNOWN))
    settle = AsyncMock(side_effect=_infrastructure_error_after_dispatch(kind))
    with _pipeline(actuate) as (governance, _):
        with patch("src.cage_finance.tools.tool_provider._settle", settle):
            with pytest.raises(_first_attempt_errors()):
                await _trade(governor)
        with pytest.raises(UnsettledDuplicate, match="^UNKNOWN: "):
            await _trade(governor)
        with pytest.raises(UnsettledDuplicate, match="^UNKNOWN: "):
            await _trade(governor, deferred_id="d-1")

    assert actuate.await_count == 1
    assert governance.await_count == 1
    duplicate = await governor.components.execution_ledger.claim(
        "execute_trade", SHARED_CALLER, _TXN
    )
    assert duplicate.status is ExecutionStatus.UNKNOWN
