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

Validates fail-closed invariant: execute_trade_action() must reject calls with
missing, empty, or whitespace-only routing seals from enforce_governance().
"""

from unittest.mock import AsyncMock, patch

import pytest

from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import ActuationReceipt

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestExecuteTradeActionRoutingSealEnforcement:
    """Fail-closed routing seal validation in execute_trade_action()."""

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_none_seal(self):
        """execute_trade_action() with seal=None must raise SymbolicGovernorViolation."""

        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            new_callable=AsyncMock,
            return_value=None,
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                await execute_trade_action(
                    symbol="AAPL",
                    amount=100.0,
                    currency="USD",
                    confidence=0.99,
                )

            assert "CRITICAL" in str(exc_info.value)
            assert "execute_trade_action invoked without mandatory routing seal" in str(
                exc_info.value
            )

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_empty_string_seal(self):
        """execute_trade_action() with seal='' must raise SymbolicGovernorViolation."""

        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            new_callable=AsyncMock,
            return_value="",
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                await execute_trade_action(
                    symbol="MSFT",
                    amount=50.0,
                    currency="USD",
                    confidence=0.95,
                )

            assert "CRITICAL" in str(exc_info.value)
            assert "execute_trade_action invoked without mandatory routing seal" in str(
                exc_info.value
            )

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_whitespace_seal(self):
        """execute_trade_action() with seal='   ' must raise SymbolicGovernorViolation."""

        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            new_callable=AsyncMock,
            return_value="   ",
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                await execute_trade_action(
                    symbol="TSLA",
                    amount=25.0,
                    currency="USD",
                    confidence=0.90,
                )

            assert "CRITICAL" in str(exc_info.value)
            assert "execute_trade_action invoked without mandatory routing seal" in str(
                exc_info.value
            )

    @pytest.mark.asyncio
    async def test_execute_trade_action_rejects_non_string_seal(self):
        """execute_trade_action() with seal=123 must raise SymbolicGovernorViolation."""

        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            new_callable=AsyncMock,
            return_value=123,
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                await execute_trade_action(
                    symbol="GOOG",
                    amount=10.0,
                    currency="USD",
                    confidence=0.88,
                )

            assert "CRITICAL" in str(exc_info.value)
            assert "execute_trade_action invoked without mandatory routing seal" in str(
                exc_info.value
            )

    @pytest.mark.asyncio
    async def test_execute_trade_action_accepts_valid_seal(self):
        """execute_trade_action() with valid seal proceeds to NARROW receipt check."""

        with (
            patch(
                "src.cage_finance.tools.tool_provider.enforce_governance",
                new_callable=AsyncMock,
                return_value="valid-seal-abc123",
            ),
            patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                new_callable=AsyncMock,
            ),
            patch(
                "src.cage_finance.tools.tool_provider._broker_actuator.actuate",
                new_callable=AsyncMock,
                return_value=ActuationReceipt(
                    accepted=True,
                    receipt_id="mock-123",
                    session_uuid="mock-session",
                    raw_receipt={"execution_result": "EXECUTED: AAPL x 100.0"},
                    findings=[],
                    retryable=False,
                ),
            ),
            patch(
                "src.gateway.infrastructure.redis_client.redis_client",
                None,  # Disable Redis receipt lookup
            ),
        ):
            # Should not raise SymbolicGovernorViolation during seal validation
            result = await execute_trade_action(
                symbol="AAPL",
                amount=100.0,
                currency="USD",
                confidence=0.99,
            )

            # Should reach execute_trade without raising seal error
            assert "EXECUTED" in result
            assert "AAPL" in result

    @pytest.mark.asyncio
    async def test_execute_trade_action_dry_run_requires_seal(self):
        """execute_trade_action() in dry_run mode still requires a valid seal."""

        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            new_callable=AsyncMock,
            return_value="",  # Empty seal
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                await execute_trade_action(
                    symbol="NVDA",
                    amount=15.0,
                    currency="USD",
                    confidence=0.92,
                    dry_run=True,
                )

            assert "CRITICAL" in str(exc_info.value)
            assert "execute_trade_action invoked without mandatory routing seal" in str(
                exc_info.value
            )
