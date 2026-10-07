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

"""The finance plugin owns every measured ``execute_trade`` STPA input.

``TRADE_SERVER_INPUT_KEYS`` must cover each param the generated measured-state
rules read (UCA-2 latency, UCA-5 drawdown and its aliases, UCA-13's
``portfolio_total``). A key it misses would be read from the caller again,
on the preview or the committing path (POAM-2026-105).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_finance.tools.trade_inputs import (
    TRADE_SERVER_INPUT_KEYS,
    TradeInputResolver,
)
from src.gateway.governance.contracts import ServerInputResolver
from tests.fixtures.trade_inputs import trade_server_inputs

pytestmark = [pytest.mark.unit, pytest.mark.local]

_HAZARDS = (
    Path(__file__).resolve().parents[2]
    / "src/cage_finance/config/stpa/trade_hazards.yaml"
)


def _ucas() -> dict[str, dict[str, Any]]:
    doc = yaml.safe_load(_HAZARDS.read_text())
    return {u["id"]: u for u in doc["unsafe_control_actions"]}


def test_owned_keys_cover_the_uca_2_and_uca_5_params_and_aliases() -> None:
    ucas = _ucas()
    measured = {ucas["UCA-2"]["condition"]["param"]}
    measured |= {ucas["UCA-5"]["condition"]["param"]}
    measured |= set(ucas["UCA-5"]["condition"].get("param_aliases", []))

    assert measured <= TRADE_SERVER_INPUT_KEYS


def test_owned_keys_cover_the_uca_13_portfolio_total() -> None:
    composite = _ucas()["UCA-13"]["condition"]["composite"]

    assert "portfolio_total" in composite
    assert "portfolio_total" in TRADE_SERVER_INPUT_KEYS


def test_caller_intent_is_never_owned() -> None:
    # Amount, side and symbol are what the caller asks for; they stay its own.
    assert not {"amount", "side", "symbol", "trader_role"} & TRADE_SERVER_INPUT_KEYS


def test_plugin_contributes_the_execute_trade_resolver() -> None:
    contribution = FinanceCagePlugin().contribute()

    resolver = contribution.server_inputs["execute_trade"]
    assert isinstance(resolver, TradeInputResolver)
    assert isinstance(resolver, ServerInputResolver)
    assert resolver.owned_keys == TRADE_SERVER_INPUT_KEYS
    assert set(contribution.server_inputs) <= set(contribution.registered_actions)


async def test_resolver_returns_nothing_without_a_symbol() -> None:
    resolver = trade_server_inputs()["execute_trade"]

    assert await resolver.resolve({"amount": 1.0}) == {}


async def test_resolver_resolves_sell_inputs_for_a_mixed_case_side() -> None:
    resolver = trade_server_inputs()["execute_trade"]

    resolved = await resolver.resolve(
        {"symbol": "AAPL", "side": "SELL", "amount": 500.0}
    )

    assert {
        "latency_ms",
        "drawdown",
        "order_size",
        "daily_vol",
        "portfolio_total",
    } <= set(resolved)
    assert set(resolved) <= TRADE_SERVER_INPUT_KEYS


def test_owned_keys_cover_the_uca_6_operands() -> None:
    condition = _ucas()["UCA-6"]["condition"]

    assert condition.get("require_params") is True
    for operand in ("order_size", "daily_vol"):
        assert operand in condition["composite"]
        assert operand in TRADE_SERVER_INPUT_KEYS
