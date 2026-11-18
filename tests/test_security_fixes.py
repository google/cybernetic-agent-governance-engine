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
tests/test_security_fixes.py

Regression tests for Sprint 1 Critical security findings.

C-01 — Trade side inversion (tools.py):
    Verifies that execute_trade() uses the requested side ("sell") rather than
    the previously hardcoded "buy", and that an invalid side is rejected.

C-02 — CBF fail-closed on Redis unavailability:
    The original regression tests exercised ``compute_nemo_context()``, which
    was deleted with the dead NeMo pre-check path. CBF fail-closed behaviour on
    Redis errors is covered in tests/test_cbf_chaos.py and
    tests/test_cbf_negative_paths.py.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# C-01 — Trade side inversion
# ---------------------------------------------------------------------------


class TestC01TradeSide:
    """C-01: execute_trade() must forward the requested side, not hardcode 'buy'."""

    async def _mint_order_seal(self, monkeypatch, order) -> str:
        import src.gateway.governance.jwks as jwks_mod
        import src.gateway.governance.kms_signer as ks
        from src.gateway.governance.routing_seal import generate_seal

        provider = ks.SoftwareEd25519Provider(key_id=f"sec-c01-{uuid.uuid4().hex[:8]}")
        monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=provider))
        monkeypatch.setattr(jwks_mod, "_global_jwks", None)
        return await generate_seal(
            "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
        )

    @pytest.mark.asyncio
    async def test_sell_order_sends_sell_to_broker(self, monkeypatch):
        """A sell order must reach the broker with side='sell'."""
        import json as _json

        import httpx

        import src.cage_finance.tools.trade_executor as tools_module
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="AAPL",
            amount=50,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.95,
            transaction_id=tx_id,
        )
        seal = await self._mint_order_seal(monkeypatch, order)

        captured_payload: dict = {}

        def _fake_post(req: httpx.Request) -> httpx.Response:
            captured_payload.update(_json.loads(req.content.decode("utf-8")))
            return httpx.Response(200, json={"id": "order-sell-001"})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_fake_post)
        ) as client:
            with (
                patch(
                    "src.cage_finance.tools.trade_executor.redis_client"
                ) as mock_redis,
                patch.object(tools_module, "_USE_MOCK_BROKER", False),
                patch.dict(
                    os.environ,
                    {
                        "BROKER_API_KEY": "test-key",
                        "BROKER_API_SECRET": "test-secret",
                        "USE_MOCK_BROKER": "false",
                    },
                ),
            ):
                mock_redis.get.return_value = None  # no safety violation

                result = await execute_trade(
                    order, routing_seal=seal, http_client=client
                )

        assert captured_payload.get("side") == "sell", (
            f"Expected side='sell' in broker payload but got: {captured_payload}"
        )
        assert "EXECUTED" in result

    @pytest.mark.asyncio
    async def test_buy_order_sends_buy_to_broker(self, monkeypatch):
        """A buy order must reach the broker with side='buy'."""
        import json as _json

        import httpx

        import src.cage_finance.tools.trade_executor as tools_module
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="MSFT",
            amount=10,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.90,
            transaction_id=tx_id,
        )
        seal = await self._mint_order_seal(monkeypatch, order)

        captured_payload: dict = {}

        def _fake_post(req: httpx.Request) -> httpx.Response:
            captured_payload.update(_json.loads(req.content.decode("utf-8")))
            return httpx.Response(200, json={"id": "order-buy-001"})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_fake_post)
        ) as client:
            with (
                patch(
                    "src.cage_finance.tools.trade_executor.redis_client"
                ) as mock_redis,
                patch.object(tools_module, "_USE_MOCK_BROKER", False),
                patch.dict(
                    os.environ,
                    {
                        "BROKER_API_KEY": "test-key",
                        "BROKER_API_SECRET": "test-secret",
                        "USE_MOCK_BROKER": "false",
                    },
                ),
            ):
                mock_redis.get.return_value = None

                result = await execute_trade(
                    order, routing_seal=seal, http_client=client
                )

        assert captured_payload.get("side") == "buy", (
            f"Expected side='buy' in broker payload but got: {captured_payload}"
        )
        assert "EXECUTED" in result

    @pytest.mark.asyncio
    async def test_invalid_side_raises_assertion_error(self, monkeypatch):
        """An order with an invalid side must be rejected before any broker call."""
        import httpx

        import src.cage_finance.tools.trade_executor as tools_module
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="TSLA",
            amount=5,
            currency="USD",
            side="short",  # invalid — not in {"buy", "sell"}
            type="market",
            confidence=0.80,
            transaction_id=tx_id,
        )
        seal = await self._mint_order_seal(monkeypatch, order)
        broker_called = False

        def _never_called(_req: httpx.Request) -> httpx.Response:
            nonlocal broker_called
            broker_called = True
            return httpx.Response(200, json={"id": "unexpected"})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_never_called)
        ) as client:
            with (
                patch(
                    "src.cage_finance.tools.trade_executor.redis_client"
                ) as mock_redis,
                patch.object(tools_module, "_USE_MOCK_BROKER", False),
                patch.dict(
                    os.environ,
                    {
                        "BROKER_API_KEY": "test-key",
                        "BROKER_API_SECRET": "test-secret",
                        "USE_MOCK_BROKER": "false",
                    },
                ),
            ):
                mock_redis.get.return_value = None

                with pytest.raises(
                    (ValueError, AssertionError), match="Invalid trade side"
                ):
                    await execute_trade(order, routing_seal=seal, http_client=client)

        # Broker must never be called for an invalid side.
        assert broker_called is False

    @pytest.mark.asyncio
    async def test_mock_broker_preserves_sell_side(self, monkeypatch):
        """Mock broker fast-path must also reflect the requested side in its return value.

        _USE_MOCK_BROKER is a module-level constant evaluated at import time, so
        patch.dict(os.environ) cannot change it after the module is loaded.
        We patch the constant directly on the module instead.
        """
        import src.cage_finance.tools.trade_executor as tools_module
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="NVDA",
            amount=20,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.88,
            transaction_id=tx_id,
        )
        seal = await self._mint_order_seal(monkeypatch, order)

        with (
            patch("src.cage_finance.tools.trade_executor.redis_client") as mock_redis,
            patch.object(tools_module, "_USE_MOCK_BROKER", True),
        ):
            mock_redis.get.return_value = None

            result = await execute_trade(order, routing_seal=seal)

        # The mock result string includes the side from the order object.
        assert "sell" in result.lower(), (
            f"Mock broker result should mention 'sell' but got: {result}"
        )
