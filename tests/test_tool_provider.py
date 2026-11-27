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
Negative tests for execute_trade_action routing seal enforcement.

Validates the fail-closed invariant: execute_trade_action() must reject a
governance result that is not a ``SealedAction`` carrying a non-empty seal and
dict params (a missing, empty, whitespace-only or non-string seal, or a bare
seal string), and must verify and actuate exactly ``SealedAction.params``,
the evaluated params the seal commits to, never the caller's params.
"""

import hashlib
import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance.commit_outcome import CommitStatus
from src.gateway.governance.governor.sealing import SealedAction
from src.gateway.governance.routing_seal import SymbolicGovernorViolation, seal_digest
from src.gateway.governance.seams.actuation import ActuationOutcome, ActuationReceipt
from tests.fixtures.trade_inputs import sealed_governance, trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_SEAL_REQUIRED = "execute_trade_action invoked without mandatory routing seal"


def _deps() -> dict:
    """Composition-root dependencies injected into execute_trade_action()."""
    return {
        "governor": trade_governor(),
        "idempotency_key": str(uuid.uuid4()),
    }


def _accepted() -> ActuationReceipt:
    return ActuationReceipt(
        accepted=True,
        receipt_id="mock-123",
        session_uuid="mock-session",
        raw_receipt={"execution_result": "EXECUTED: AAPL x 100.0"},
        findings=[],
        retryable=False,
        outcome=ActuationOutcome.ACCEPTED,
    )


def _sealed_with(seal: Any, params: Any = None) -> SealedAction:
    """A SealedAction with an arbitrary (possibly invalid) seal or params."""
    return SealedAction(
        "execute_trade",
        seal,
        {"symbol": "AAPL", "amount": 1.0} if params is None else params,
    )


class TestExecuteTradeActionRoutingSealEnforcement:
    """Fail-closed routing seal validation in execute_trade_action()."""

    async def _refused(self, governance_result: Any, **trade: Any) -> None:
        """execute_trade_action() refuses ``governance_result`` before anything runs."""
        kwargs: dict[str, Any] = {
            "symbol": "AAPL",
            "amount": 100.0,
            "currency": "USD",
            "confidence": 0.99,
            **trade,
        }
        deps = _deps()
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            new_callable=AsyncMock,
            return_value=governance_result,
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                await execute_trade_action(**deps, **kwargs)

        assert "CRITICAL" in str(exc_info.value)
        assert _SEAL_REQUIRED in str(exc_info.value)
        # Refused before the seal's commits could exist: nothing to settle.
        deps["governor"].settle.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_none_seal(self):
        """A governance result of None must raise SymbolicGovernorViolation."""
        await self._refused(None, symbol="AAPL", amount=100.0, confidence=0.99)

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_empty_string_seal(self):
        """A SealedAction with seal='' must raise SymbolicGovernorViolation."""
        await self._refused(
            _sealed_with(""), symbol="MSFT", amount=50.0, confidence=0.95
        )

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_whitespace_seal(self):
        """A SealedAction with seal='   ' must raise SymbolicGovernorViolation."""
        await self._refused(
            _sealed_with("   "), symbol="TSLA", amount=25.0, confidence=0.90
        )

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_non_string_seal(self):
        """A SealedAction with seal=123 must raise SymbolicGovernorViolation."""
        await self._refused(
            _sealed_with(123), symbol="GOOG", amount=10.0, confidence=0.88
        )

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_a_bare_seal_string(self):
        """A bare seal string (no evaluated params) is not a sealed action: refused."""
        await self._refused("valid-seal-abc123")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("params", [None, "symbol=AAPL", ["AAPL", 100.0]])
    async def test_execute_trade_action_rejects_a_sealed_action_without_dict_params(
        self, params: Any
    ):
        """A seal without dict evaluated params cannot be verified or actuated."""
        await self._refused(SealedAction("execute_trade", "valid-seal-abc123", params))

    @pytest.mark.asyncio
    async def test_execute_trade_action_accepts_valid_seal(self):
        """execute_trade_action() with a valid sealed action proceeds and executes."""

        deps = _deps()
        with (
            patch(
                "src.cage_finance.tools.tool_provider.enforce_governance",
                new_callable=AsyncMock,
                side_effect=sealed_governance("valid-seal-abc123"),
            ),
            patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                new_callable=AsyncMock,
            ),
            patch(
                "src.cage_finance.tools.tool_provider._broker_actuator.actuate",
                new_callable=AsyncMock,
                return_value=_accepted(),
            ),
            patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                None,  # Disable Redis receipt lookup
            ),
        ):
            # Should not raise SymbolicGovernorViolation during seal validation
            result = await execute_trade_action(
                **deps,
                symbol="AAPL",
                amount=100.0,
                currency="USD",
                confidence=0.99,
            )

            # Should reach execute_trade without raising seal error
            assert result.status is CommitStatus.EXECUTED
            assert "EXECUTED" in result.message
            assert "AAPL" in result.message
            # The executed trade settles its seal: reservations become permanent.
            deps["governor"].settle.assert_awaited_once_with(
                "valid-seal-abc123", executed=True
            )

    @pytest.mark.asyncio
    async def test_seal_is_verified_and_cleared_against_the_sealed_params(self):
        """The seal is verified against, and the clearance names, SealedAction.params.

        The committing run returns the evaluated params it sealed (here with
        the trader identity and STPA inputs the kernel bound); the tool
        verifies the seal against them and actuates exactly them, never the
        params it handed governance.
        """
        seal = "seal-over-evaluated-params"
        evaluated: dict[str, Any] = {}

        def _govern(_governor: Any, action: str, params: dict[str, Any]) -> Any:
            evaluated.update(
                params,
                trader_role="junior",
                trader_id="desk-a.trading.serviceaccount.identity.linkerd.cluster.local",
                latency_ms=12.5,
            )
            return SealedAction(action, seal, evaluated)

        deps = _deps()
        verify = AsyncMock()
        actuate = AsyncMock(return_value=_accepted())
        with (
            patch(
                "src.cage_finance.tools.tool_provider.enforce_governance",
                new_callable=AsyncMock,
                side_effect=_govern,
            ) as governance,
            patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal", verify
            ),
            patch(
                "src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate
            ),
            patch("src.gateway.infrastructure.redis_client.redis_client", None),
        ):
            result = await execute_trade_action(
                **deps, symbol="AAPL", amount=100.0, currency="USD", confidence=0.99
            )

        assert result.status is CommitStatus.EXECUTED, result
        assert result.message.startswith("EXECUTED: AAPL x 100.0"), result
        handed = governance.await_args.args[2]
        assert "trader_role" not in handed  # the tool binds nothing itself
        verify.assert_awaited_once_with(seal, "execute_trade", evaluated)
        assert verify.await_args.args[2] is evaluated
        clearance = actuate.await_args.args[0]
        assert clearance.params == evaluated
        assert clearance.operator_urn == evaluated["trader_id"]
        assert clearance.routing_seal == seal
        assert clearance.governance_decision_digest == seal_digest(seal)
        assert (
            clearance.opa_input_digest
            == hashlib.sha256(
                json.dumps(evaluated, sort_keys=True).encode()
            ).hexdigest()
        )
        deps["governor"].settle.assert_awaited_once_with(seal, executed=True)

    @pytest.mark.asyncio
    async def test_execute_trade_action_dry_run_requires_seal(self):
        """execute_trade_action() in dry_run mode still requires a valid seal."""
        await self._refused(
            _sealed_with(""),  # Empty seal
            symbol="NVDA",
            amount=15.0,
            confidence=0.92,
            dry_run=True,
        )
