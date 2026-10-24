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

"""A trade's transaction_id is its idempotency key, at the gateway and the broker (#514)."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from src.cage_finance.models.trade_order import TradeOrder, is_valid_transaction_id
from src.cage_finance.tools import trade_executor

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _order(transaction_id: str) -> TradeOrder:
    return TradeOrder(
        symbol="AAPL",
        amount=10,
        currency="USD",
        side="buy",
        confidence=0.99,
        transaction_id=transaction_id,
    )


@pytest.mark.parametrize(
    "transaction_id",
    [
        str(uuid.uuid4()),
        str(uuid.uuid5(uuid.NAMESPACE_URL, "thread:t-1|call:c-1")),
        str(uuid.uuid4()).upper(),
    ],
    ids=["uuid4", "uuid5", "uuid4-upper"],
)
def test_uuid4_and_uuid5_are_accepted(transaction_id: str) -> None:
    assert is_valid_transaction_id(transaction_id)
    assert _order(transaction_id).transaction_id == transaction_id


@pytest.mark.parametrize(
    "transaction_id",
    [
        str(uuid.uuid1()),
        str(uuid.uuid3(uuid.NAMESPACE_URL, "x")),
        uuid.uuid4().hex,  # not canonical
        f"{uuid.uuid4()}\n",  # a trailing newline would be a second key
        "not-a-uuid",
    ],
    ids=["uuid1", "uuid3", "hex", "trailing-newline", "garbage"],
)
def test_other_transaction_ids_are_refused(transaction_id: str) -> None:
    assert not is_valid_transaction_id(transaction_id)
    with pytest.raises(ValidationError, match="UUID v4 or v5"):
        _order(transaction_id)


def test_non_string_transaction_id_is_not_valid() -> None:
    assert not is_valid_transaction_id(None)
    assert not is_valid_transaction_id(uuid.uuid4())


@pytest.mark.asyncio
async def test_broker_order_carries_the_transaction_id_as_client_order_id() -> None:
    order = _order(str(uuid.uuid4()))
    sent: dict[str, Any] = {}

    def fake_post(url: str, *, json: dict[str, Any], **_: Any) -> MagicMock:
        sent.update(json)
        response = MagicMock()
        response.json.return_value = {"id": "broker-order-1"}
        return response

    config = MagicMock()
    config.get.side_effect = lambda key, default=None: {
        "BROKER_API_KEY": "key",
        "BROKER_API_SECRET": "secret",
    }.get(key, default or "https://broker.test")

    with (
        patch.object(trade_executor, "_USE_MOCK_BROKER", False),
        patch.object(trade_executor, "config_manager", config),
        patch.object(trade_executor, "_redis_get", AsyncMock(return_value=None)),
        patch("requests.post", side_effect=fake_post),
    ):
        result = await trade_executor.execute_trade(order, routing_seal="seal-1")

    assert result == "EXECUTED: AAPL x 10.0 (Order ID: broker-order-1)"
    assert sent["client_order_id"] == order.transaction_id
