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

"""Tri-state actuation outcome: receipt invariants and settlement direction.

An actuation that failed *after* the order may have reached the venue is
``UNKNOWN``.  It must settle like ``ACCEPTED`` (confirm the seal's
reservations) — releasing headroom for an order that actually filled would be
fail-open — and it must never be retryable, since a retry could
double-execute.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import ActuationOutcome, ActuationReceipt

pytestmark = [pytest.mark.unit, pytest.mark.local]

_SEAL = "valid-seal-outcome"


def _receipt(**overrides) -> ActuationReceipt:
    fields = {
        "accepted": False,
        "receipt_id": None,
        "session_uuid": None,
        "raw_receipt": None,
        "findings": [{"code": "X", "detail": "y"}],
        "retryable": False,
    }
    fields.update(overrides)
    return ActuationReceipt(**fields)


class TestReceiptOutcomeInvariants:
    def test_outcome_derived_from_accepted(self) -> None:
        assert _receipt(accepted=True).outcome is ActuationOutcome.ACCEPTED
        assert _receipt(accepted=False).outcome is ActuationOutcome.REJECTED

    def test_accepted_contradicting_outcome_rejected(self) -> None:
        with pytest.raises(ValueError):
            _receipt(accepted=True, outcome=ActuationOutcome.REJECTED)
        with pytest.raises(ValueError):
            _receipt(accepted=False, outcome=ActuationOutcome.ACCEPTED)
        with pytest.raises(ValueError):
            _receipt(accepted=True, outcome=ActuationOutcome.UNKNOWN)

    def test_unknown_cannot_be_retryable(self) -> None:
        with pytest.raises(ValueError):
            _receipt(outcome=ActuationOutcome.UNKNOWN, retryable=True)

    def test_may_have_executed(self) -> None:
        assert _receipt(accepted=True).may_have_executed
        assert _receipt(outcome=ActuationOutcome.UNKNOWN).may_have_executed
        assert not _receipt(outcome=ActuationOutcome.REJECTED).may_have_executed


async def _run_trade(actuate_mock: AsyncMock) -> tuple[MagicMock, object]:
    """Run execute_trade_action with a stub actuator; return (governor, result|exc)."""
    governor = MagicMock(settle=AsyncMock(return_value=[]))
    with (
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            new_callable=AsyncMock,
            return_value=_SEAL,
        ),
        patch(
            "src.gateway.governance.routing_seal.verify_and_consume_seal",
            new_callable=AsyncMock,
        ),
        patch(
            "src.cage_finance.tools.tool_provider._broker_actuator.actuate",
            actuate_mock,
        ),
        patch("src.gateway.infrastructure.redis_client.redis_client", None),
    ):
        try:
            outcome: object = await execute_trade_action(
                governor=governor,
                symbol="AAPL",
                amount=100.0,
                currency="USD",
                confidence=0.99,
            )
        except SymbolicGovernorViolation as exc:
            outcome = exc
    return governor, outcome


class TestSettlementDirection:
    @pytest.mark.asyncio
    async def test_unknown_outcome_confirms_reservations(self) -> None:
        governor, result = await _run_trade(
            AsyncMock(return_value=_receipt(outcome=ActuationOutcome.UNKNOWN))
        )
        assert isinstance(result, SymbolicGovernorViolation)
        assert "indeterminate" in str(result)
        governor.settle.assert_awaited_once_with(_SEAL, executed=True)

    @pytest.mark.asyncio
    async def test_rejected_outcome_releases_reservations(self) -> None:
        governor, result = await _run_trade(
            AsyncMock(return_value=_receipt(outcome=ActuationOutcome.REJECTED))
        )
        assert isinstance(result, SymbolicGovernorViolation)
        assert "Actuation rejected" in str(result)
        governor.settle.assert_awaited_once_with(_SEAL, executed=False)

    @pytest.mark.asyncio
    async def test_actuator_exception_confirms_reservations(self) -> None:
        """An actuator that raised gives no proof of non-execution."""
        governor, result = await _run_trade(
            AsyncMock(side_effect=RuntimeError("venue socket died"))
        )
        assert isinstance(result, str) and result.startswith("ERROR:")
        governor.settle.assert_awaited_once_with(_SEAL, executed=True)
