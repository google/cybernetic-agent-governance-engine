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

"""``execute_trade_action`` executes a ``transaction_id`` at most once (#514).

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
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    ExecutionLedger,
    ExecutionStatus,
    UnsettledDuplicate,
)
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import ActuationOutcome, ActuationReceipt
from tests.fixtures.trade_inputs import trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_TXN = "0b6c7f4e-2a51-4f7e-9c3d-8e1f2a3b4c5d"
_KEY = ExecutionLedger.key_for("execute_trade", SHARED_CALLER, _TXN)


def _accepted() -> ActuationReceipt:
    return ActuationReceipt(
        accepted=True,
        receipt_id="r-1",
        session_uuid="s-1",
        raw_receipt={"execution_result": "EXECUTED"},
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
    governance = governance or AsyncMock(return_value="seal-1")
    with (
        patch("src.cage_finance.tools.tool_provider.enforce_governance", governance),
        patch(
            "src.gateway.governance.routing_seal.verify_and_consume_seal",
            new_callable=AsyncMock,
        ),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
        patch("src.gateway.infrastructure.redis_client.redis_client", None),
        patch(
            "src.cage_finance.tools.tool_provider.record_refusal",
            new_callable=AsyncMock,
        ) as refusals,
    ):
        yield governance, refusals


async def _trade(governor: Any, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "symbol": "AAPL",
        "amount": 10.0,
        "currency": "USD",
        "confidence": 0.99,
        "transaction_id": _TXN,
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

    assert first.startswith("EXECUTED: AAPL x 10.0")
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
    executed = [r for r in results if isinstance(r, str)]
    in_flight = [
        r
        for r in results
        if isinstance(r, UnsettledDuplicate) and str(r).startswith("IN_FLIGHT:")
    ]
    assert len(executed) >= 1
    assert all(r.startswith("EXECUTED: AAPL") for r in executed)
    assert len(executed) + len(in_flight) == len(results)


@pytest.mark.asyncio
async def test_enforcing_posture_without_redis_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_ENV", "production")
    gov = trade_governor()
    gov.components.execution_ledger = ExecutionLedger(None)
    actuate = AsyncMock(return_value=_accepted())

    with _pipeline(actuate) as (governance, refusals):
        result = await _trade(gov)

    assert result.startswith("BLOCKED: execution ledger unavailable")
    governance.assert_not_awaited()
    actuate.assert_not_awaited()
    refusals.assert_awaited_once()


@pytest.mark.asyncio
async def test_unknown_outcome_keeps_the_claim(
    governor: MagicMock, redis: fakeredis.aioredis.FakeRedis
) -> None:
    actuate = AsyncMock(return_value=_not_accepted(ActuationOutcome.UNKNOWN))
    with _pipeline(actuate) as (governance, _):
        with pytest.raises(SymbolicGovernorViolation, match="indeterminate"):
            await _trade(governor)
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
async def test_rejected_actuation_is_recorded_as_blocked(governor: MagicMock) -> None:
    actuate = AsyncMock(return_value=_not_accepted(ActuationOutcome.REJECTED))
    with _pipeline(actuate):
        with pytest.raises(SymbolicGovernorViolation, match="Actuation rejected"):
            await _trade(governor)
        replay = await _trade(governor)

    assert replay.startswith("BLOCKED: ")
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

    assert first == "BLOCKED: Governance Blocked: DENY"
    assert second == first
    assert governance.await_count == 1
    actuate.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_approval_reclaims_a_blocked_key_and_executes_once(
    governor: MagicMock,
) -> None:
    refused = AsyncMock(side_effect=PermissionError("Governance Blocked: HITL"))
    approved = AsyncMock(return_value="seal-1")
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

    assert blocked == "BLOCKED: Governance Blocked: HITL"
    assert executed.startswith("EXECUTED: AAPL")
    assert refused.await_count == 1
    assert approved.await_count == 1
    assert actuate.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("transaction_id", "expected"),
    [
        (None, "BLOCKED: transaction_id is required"),
        ("", "BLOCKED: transaction_id is required"),
        (str(uuid.uuid1()), "BLOCKED: invalid transaction_id"),
        ("not-a-uuid", "BLOCKED: invalid transaction_id"),
    ],
    ids=["missing", "empty", "uuid1", "garbage"],
)
async def test_missing_or_invalid_transaction_id_is_refused(
    governor: MagicMock, transaction_id: str | None, expected: str
) -> None:
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate) as (governance, _):
        result = await _trade(governor, transaction_id=transaction_id)

    assert result.startswith(expected)
    governance.assert_not_awaited()
    actuate.assert_not_awaited()


@pytest.mark.asyncio
async def test_transaction_id_case_does_not_create_a_second_key(
    governor: MagicMock,
) -> None:
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate):
        first = await _trade(governor, transaction_id=_TXN.upper())
        second = await _trade(governor, transaction_id=_TXN)

    assert second == first
    assert actuate.await_count == 1


@pytest.mark.asyncio
async def test_dry_run_claims_nothing(
    governor: MagicMock, redis: fakeredis.aioredis.FakeRedis
) -> None:
    actuate = AsyncMock(return_value=_accepted())
    with _pipeline(actuate):
        assert (await _trade(governor, dry_run=True)).startswith("DRY_RUN:")
        assert await redis.exists(_KEY) == 0
        executed = await _trade(governor)

    assert executed.startswith("EXECUTED: AAPL")
    assert actuate.await_count == 1
