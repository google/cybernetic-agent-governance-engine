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

"""execute_trade_action settles its seal exactly once on every exit (ADR-009).

Only a broker-accepted trade confirms the seal's reservations; every other
exit after the seal is issued (invalid seal, dry run, rejection, actuation
error, missing actuator) releases them.
"""

from __future__ import annotations

from contextlib import ExitStack
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cage_finance.simulated_feeds import (
    SimulatedMarketQuoteFeed,
    SimulatedPortfolioNavSource,
)
from src.cage_finance.tools.tool_provider import execute_trade_action
from src.cage_finance.tools.trade_inputs import ServerTradeInputs
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import ActuationReceipt

pytestmark = [pytest.mark.unit, pytest.mark.local]

#: The gateway's STPA input sources, in limit: a 10 ms quote age and no drawdown.
_TRADE_INPUTS = ServerTradeInputs(
    market_feed=SimulatedMarketQuoteFeed(seed=0, publication_delay_ms=(10.0, 10.0)),
    nav_source=SimulatedPortfolioNavSource(),
)


_SEAL = "seal-under-test"


def _receipt(accepted: bool) -> ActuationReceipt:
    return ActuationReceipt(
        accepted=accepted,
        receipt_id="r-1",
        session_uuid="s-1",
        raw_receipt={},
        findings=[] if accepted else [{"code": "VENUE_REJECT", "detail": "halted"}],
        retryable=False,
    )


def _governor() -> MagicMock:
    governor = MagicMock()
    governor.settle = AsyncMock(return_value=[])
    return governor


async def _run(
    governor: MagicMock, *, actuate: Any = None, verify: Any = None, **kwargs: Any
) -> Any:
    with ExitStack() as stack:
        stack.enter_context(
            patch(
                "src.cage_finance.tools.tool_provider.enforce_governance",
                new_callable=AsyncMock,
                return_value=_SEAL,
            )
        )
        stack.enter_context(
            patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                verify or AsyncMock(),
            )
        )
        stack.enter_context(
            patch("src.gateway.infrastructure.redis_client.redis_client", None)
        )
        if actuate is not None:
            stack.enter_context(
                patch(
                    "src.cage_finance.tools.tool_provider._broker_actuator.actuate",
                    actuate,
                )
            )
        return await execute_trade_action(
            symbol="AAPL",
            amount=10.0,
            currency="USD",
            confidence=0.99,
            inputs=_TRADE_INPUTS,
            governor=governor,
            **kwargs,
        )


@pytest.mark.asyncio
async def test_accepted_trade_confirms() -> None:
    governor = _governor()
    result = await _run(governor, actuate=AsyncMock(return_value=_receipt(True)))
    assert result.startswith("EXECUTED")
    governor.settle.assert_awaited_once_with(_SEAL, executed=True)


@pytest.mark.asyncio
async def test_rejected_trade_releases() -> None:
    governor = _governor()
    with pytest.raises(SymbolicGovernorViolation, match="Actuation rejected"):
        await _run(governor, actuate=AsyncMock(return_value=_receipt(False)))
    governor.settle.assert_awaited_once_with(_SEAL, executed=False)


@pytest.mark.asyncio
async def test_actuation_error_confirms() -> None:
    # An actuator that raised (e.g. timed out mid-request) gives no proof the
    # order did not fill: dispatch_actuation records it as an UNKNOWN receipt,
    # so reservations are confirmed (conservative), never released.
    governor = _governor()
    with pytest.raises(SymbolicGovernorViolation, match="indeterminate"):
        await _run(governor, actuate=AsyncMock(side_effect=TimeoutError("broker")))
    governor.settle.assert_awaited_once_with(_SEAL, executed=True)


@pytest.mark.asyncio
async def test_dry_run_releases() -> None:
    governor = _governor()
    actuate = AsyncMock()
    result = await _run(governor, actuate=actuate, dry_run=True)
    assert result.startswith("DRY_RUN")
    actuate.assert_not_awaited()
    governor.settle.assert_awaited_once_with(_SEAL, executed=False)


@pytest.mark.asyncio
async def test_invalid_seal_releases() -> None:
    governor = _governor()
    verify = AsyncMock(
        side_effect=SymbolicGovernorViolation("expired", action="execute_trade")
    )
    result = await _run(governor, verify=verify)
    assert result.startswith("BLOCKED")
    governor.settle.assert_awaited_once_with(_SEAL, executed=False)


@pytest.mark.asyncio
async def test_missing_actuator_releases() -> None:
    governor = _governor()
    registry = MagicMock()
    registry.get_actuator.return_value = None
    with patch(
        "src.cage_finance.tools.tool_provider.get_actuator_registry",
        return_value=registry,
    ):
        with pytest.raises(SymbolicGovernorViolation, match="No actuator"):
            await _run(governor)
    governor.settle.assert_awaited_once_with(_SEAL, executed=False)


@pytest.mark.asyncio
async def test_refused_governance_settles_nothing() -> None:
    """No seal, nothing reserved: the governor already rolled back."""
    governor = _governor()
    with patch(
        "src.cage_finance.tools.tool_provider.enforce_governance",
        new_callable=AsyncMock,
        side_effect=PermissionError("denied"),
    ):
        result = await execute_trade_action(
            symbol="AAPL",
            amount=10.0,
            currency="USD",
            inputs=_TRADE_INPUTS,
            governor=governor,
        )
    assert result.startswith("BLOCKED")
    governor.settle.assert_not_awaited()


@pytest.mark.asyncio
async def test_settlement_failures_do_not_mask_the_trade_result(caplog) -> None:
    from src.gateway.governance.contracts import Violation, ViolationKind

    governor = _governor()
    governor.settle.return_value = [
        Violation(
            tier="fiscal",
            code="CONFIRM_FAILED",
            message="redis down",
            kind=ViolationKind.HARD,
        )
    ]
    result = await _run(governor, actuate=AsyncMock(return_value=_receipt(True)))
    assert result.startswith("EXECUTED")
    assert "settlement (executed=True) failed" in caplog.text
