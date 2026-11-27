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

"""A trade's idempotency_key is its idempotency key, at the gateway and the broker (#514)."""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import ValidationError

from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools import trade_executor
from src.gateway.governance.execution_idempotency import is_valid_idempotency_key
from src.gateway.governance.routing_seal import SymbolicGovernorViolation, generate_seal

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _order(idempotency_key: str) -> TradeOrder:
    return TradeOrder(
        symbol="AAPL",
        amount=10,
        currency="USD",
        side="buy",
        confidence=0.99,
        idempotency_key=idempotency_key,
    )


@pytest.mark.parametrize(
    "idempotency_key",
    [
        str(uuid.uuid4()),
        str(uuid.uuid5(uuid.NAMESPACE_URL, "thread:t-1|call:c-1")),
        str(uuid.uuid4()).upper(),
    ],
    ids=["uuid4", "uuid5", "uuid4-upper"],
)
def test_uuid4_and_uuid5_are_accepted(idempotency_key: str) -> None:
    assert is_valid_idempotency_key(idempotency_key)
    assert _order(idempotency_key).idempotency_key == idempotency_key


@pytest.mark.parametrize(
    "idempotency_key",
    [
        str(uuid.uuid1()),
        str(uuid.uuid3(uuid.NAMESPACE_URL, "x")),
        uuid.uuid4().hex,  # not canonical
        f"{uuid.uuid4()}\n",  # a trailing newline would be a second key
        "not-a-uuid",
    ],
    ids=["uuid1", "uuid3", "hex", "trailing-newline", "garbage"],
)
def test_other_idempotency_keys_are_refused(idempotency_key: str) -> None:
    assert not is_valid_idempotency_key(idempotency_key)
    with pytest.raises(ValidationError, match="UUID v4 or v5"):
        _order(idempotency_key)


def test_non_string_idempotency_key_is_not_valid() -> None:
    assert not is_valid_idempotency_key(None)
    assert not is_valid_idempotency_key(uuid.uuid4())


@pytest.mark.asyncio
async def test_broker_order_carries_the_idempotency_key_as_client_order_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    order = _order(str(uuid.uuid4()))
    seal = await generate_seal(
        "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
    )
    sent: dict[str, Any] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        sent.update(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"id": "broker-order-1"})

    config = MagicMock()
    config.get.side_effect = lambda key, default=None: {
        "BROKER_API_KEY": "key",
        "BROKER_API_SECRET": "secret",
    }.get(key, default or "https://broker.test")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        with (
            patch.object(trade_executor, "_USE_MOCK_BROKER", False),
            patch.object(trade_executor, "config_manager", config),
            patch.object(trade_executor, "_redis_get", AsyncMock(return_value=None)),
        ):
            result = await trade_executor.execute_trade(
                order,
                routing_seal=seal,
                http_client=client,
            )

    assert result == "EXECUTED: AAPL x 10.0 (Order ID: broker-order-1)"
    assert sent["client_order_id"] == order.idempotency_key


@pytest.mark.asyncio
async def test_execute_trade_rejects_unverified_truthy_seal_before_wire() -> None:
    order = _order(str(uuid.uuid4()))
    called = False

    def _handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"id": "never"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        with pytest.raises(SymbolicGovernorViolation):
            await trade_executor.execute_trade(
                order,
                routing_seal="forged-truthy-seal",
                http_client=client,
            )
    assert called is False
