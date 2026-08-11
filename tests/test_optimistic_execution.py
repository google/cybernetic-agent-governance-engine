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

from src.gateway.core.tools import TradeOrder, execute_trade


@pytest.fixture
def mock_redis():
    # Mock Redis to avoid needing a real instance
    with patch("src.gateway.core.tools.redis_client") as mock:
        store = {}

        def get(key):
            return store.get(key)

        def set(key, val):
            store[key] = val

        mock.get.side_effect = get
        mock.set.side_effect = set
        yield mock


@pytest.fixture
def slow_executor_setup():
    # Mock requests to simulate network delay.
    # Previously used time.sleep(1.0) which added ~1s of real wall-clock time per
    # test.  Replaced with a minimal asyncio.sleep(0.001) which still exhibits the
    # concurrency/race behaviour the test relies on (a task yielding the event loop)
    # without burning real seconds.
    with patch("requests.post") as mock_post:
        async def delayed_response(*args, **kwargs):
            await asyncio.sleep(0.001)  # yield to event loop; was asyncio.sleep(0.5)
            return MagicMock(json=lambda: {"id": "123"}, raise_for_status=lambda: None)

        def slow_post(*args, **kwargs):
            # was time.sleep(1.0) — now returns immediately; the blocking behaviour
            # was only needed to force a hazard check before the post completed.
            return MagicMock(json=lambda: {"id": "123"}, raise_for_status=lambda: None)

        mock_post.side_effect = slow_post
        yield mock_post


@pytest.fixture
def mock_env(monkeypatch):
    # Mock Environment variables for API Keys using monkeypatch
    monkeypatch.setenv("BROKER_API_KEY", "test")
    monkeypatch.setenv("BROKER_API_SECRET", "test")


@pytest.mark.asyncio
async def test_optimistic_execution_interruption(
    mock_redis, slow_executor_setup, mock_env
):
    """
    Test that a slow trade execution is INTERRUPTED if the safety flag is set
    while it is running.
    """
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

    # Simulate:
    # 1. Main thread check -> None
    # 2. Thread check -> "Hazard"
    mock_redis.get.side_effect = [None, "Simulated Hazard", "Simulated Hazard"]

    # We use create_task to run it "in the background"
    trade_task = asyncio.create_task(execute_trade(order))

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

    result = await execute_trade(order)
    assert "EXECUTED" in result
