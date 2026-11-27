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
# Closure regression guard for: POAM-2026-208

"""
Negative tests for execute_trade routing seal enforcement and notional order sizing.

Validates fail-closed invariant: execute_trade() must reject calls with
missing, empty, or whitespace-only routing seals.
"""

import os
import uuid
from unittest.mock import MagicMock, patch

import pytest

from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.trade_executor import execute_trade
from src.gateway.governance.routing_seal import SymbolicGovernorViolation

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestExecuteTradeRoutingSealEnforcement:
    """Fail-closed routing seal validation in execute_trade()."""

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_none_seal(self):
        """execute_trade() with routing_seal=None must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="AAPL",
            amount=100,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.99,
            idempotency_key=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal=None)  # type: ignore[arg-type]

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_empty_string_seal(self):
        """execute_trade() with routing_seal='' must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="MSFT",
            amount=50,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.95,
            idempotency_key=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal="")

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_whitespace_only_seal(self):
        """execute_trade() with routing_seal='   ' must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="TSLA",
            amount=25,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.90,
            idempotency_key=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal="   ")

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_tabs_and_newlines_seal(self):
        """execute_trade() with routing_seal='\\t\\n' must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="GOOG",
            amount=10,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.88,
            idempotency_key=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal="\t\n")

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_non_string_seal(self):
        """execute_trade() with routing_seal=123 must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="NVDA",
            amount=15,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.92,
            idempotency_key=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal=123)  # type: ignore[arg-type]

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_accepts_valid_seal(self, monkeypatch):
        """execute_trade() with a valid Ed25519 routing_seal proceeds to Redis checks."""
        import src.gateway.governance.jwks as jwks_mod
        import src.gateway.governance.kms_signer as ks
        from src.gateway.governance.routing_seal import generate_seal

        provider = ks.SoftwareEd25519Provider(key_id="trade-exec-test-k1")
        monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=provider))
        monkeypatch.setattr(jwks_mod, "_global_jwks", None)

        order = TradeOrder(
            symbol="AMZN",
            amount=5,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.98,
            idempotency_key=str(uuid.uuid4()),
        )
        valid_seal = await generate_seal(
            "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
        )

        # Mock Redis and broker to validate seal check passes
        with (
            patch("src.cage_finance.tools.trade_executor.redis_client") as mock_redis,
            patch("src.cage_finance.tools.trade_executor._USE_MOCK_BROKER", True),
        ):
            mock_redis.get.return_value = None  # No safety violation

            result = await execute_trade(order, routing_seal=valid_seal)

            # Should reach mock broker execution without raising seal error
            assert "EXECUTED" in result
            assert "AMZN" in result


class TestExecuteTradeOrderSizing:
    """The broker order must carry the same dollar amount governance priced."""

    @pytest.mark.asyncio
    async def test_execute_trade_sends_amount_as_notional(self, monkeypatch):
        """amount is a USD notional (fiscal tier, CBF, UCA-6), never a share count."""
        import json as _json

        import httpx

        import src.gateway.governance.jwks as jwks_mod
        import src.gateway.governance.kms_signer as ks
        from src.gateway.governance.routing_seal import generate_seal

        provider = ks.SoftwareEd25519Provider(key_id="trade-notional-test-k1")
        monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=provider))
        monkeypatch.setattr(jwks_mod, "_global_jwks", None)

        order = TradeOrder(
            symbol="NVDA",
            amount=1000,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.99,
            idempotency_key=str(uuid.uuid4()),
        )
        valid_seal = await generate_seal(
            "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
        )
        captured_payload: dict = {}

        def _fake_post(req: httpx.Request) -> httpx.Response:
            captured_payload.update(_json.loads(req.content.decode("utf-8")))
            return httpx.Response(200, json={"id": "order-notional-001"})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_fake_post)
        ) as client:
            with (
                patch(
                    "src.cage_finance.tools.trade_executor.redis_client"
                ) as mock_redis,
                patch("src.cage_finance.tools.trade_executor._USE_MOCK_BROKER", False),
                patch.dict(
                    os.environ,
                    {"BROKER_API_KEY": "test-key", "BROKER_API_SECRET": "test-secret"},
                ),
            ):
                mock_redis.get.return_value = None

                result = await execute_trade(
                    order, routing_seal=valid_seal, http_client=client
                )

        assert "EXECUTED" in result
        assert captured_payload.get("notional") == 1000
        assert "qty" not in captured_payload
