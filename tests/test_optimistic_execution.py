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

import pytest

pytestmark = pytest.mark.unit
import asyncio
import uuid
from unittest.mock import MagicMock, patch

from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.trade_executor import execute_trade


@pytest.fixture
def mock_redis():
    # Mock Redis to avoid needing a real instance
    with patch("src.cage_finance.tools.trade_executor.redis_client") as mock:
        store = {}

        def get(key):
            return store.get(key)

        def set(key, val):
            store[key] = val

        mock.get.side_effect = get
        mock.set.side_effect = set
        yield mock


@pytest.fixture
def slow_executor_setup(monkeypatch):
    import httpx

    import src.cage_finance.tools.trade_executor as tools_module

    monkeypatch.setattr(tools_module, "_USE_MOCK_BROKER", False)
    real_async_client = httpx.AsyncClient

    def _ok_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "123"})

    with patch(
        "src.cage_finance.tools.trade_executor.httpx.AsyncClient",
        side_effect=lambda *a, **kw: real_async_client(
            transport=httpx.MockTransport(_ok_handler)
        ),
    ) as mock_client:
        yield mock_client


@pytest.fixture
def mock_env(monkeypatch):
    import src.gateway.governance.jwks as jwks_mod
    import src.gateway.governance.kms_signer as ks

    # Mock Environment variables for API Keys and Ed25519 seal signer
    monkeypatch.setenv("BROKER_API_KEY", "test")
    monkeypatch.setenv("BROKER_API_SECRET", "test")
    provider = ks.SoftwareEd25519Provider(key_id=f"opt-exec-{uuid.uuid4().hex[:8]}")
    monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=provider))
    monkeypatch.setattr(jwks_mod, "_global_jwks", None)


@pytest.mark.asyncio
async def test_optimistic_execution_interruption(
    mock_redis, slow_executor_setup, mock_env
):
    """
    Test that a slow trade execution is INTERRUPTED if the safety flag is set
    while it is running.
    """
    from src.gateway.governance.routing_seal import generate_seal

    # 1. Start the Trade (Slow)
    tx_id = str(uuid.uuid4())
    order = TradeOrder(
        symbol="AAPL",
        amount=100,
        currency="USD",
        side="buy",
        type="market",
        confidence=0.99,
        transaction_id=tx_id,
    )
    seal = await generate_seal(
        "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
    )

    # Simulate:
    # 1. Main check -> None
    # 2. Late pre-wire check -> "Simulated Hazard"
    mock_redis.get.side_effect = [None, "Simulated Hazard", "Simulated Hazard"]

    # We use create_task to run it "in the background"
    trade_task = asyncio.create_task(execute_trade(order, routing_seal=seal))

    # 3. Wait for trade to finish (it should fail)
    with pytest.raises(RuntimeError) as excinfo:
        await trade_task

    # 4. Assert Interruption
    assert "INTERRUPTED" in str(excinfo.value)
    assert "Simulated Hazard" in str(excinfo.value)


@pytest.mark.asyncio
async def test_optimistic_execution_success(mock_redis, slow_executor_setup, mock_env):
    """
    Test that execution succeeds if no interruption occurs.
    """
    from src.gateway.governance.routing_seal import generate_seal

    mock_redis.get.side_effect = None  # Reset side effect
    mock_redis.get.return_value = None  # No violation

    tx_id = str(uuid.uuid4())
    order = TradeOrder(
        symbol="AAPL",
        amount=100,
        currency="USD",
        side="buy",
        type="market",
        confidence=0.99,
        transaction_id=tx_id,
    )
    seal = await generate_seal(
        "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
    )

    result = await execute_trade(order, routing_seal=seal)
    assert "EXECUTED" in result
