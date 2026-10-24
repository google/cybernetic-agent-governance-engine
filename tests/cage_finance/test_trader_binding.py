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

"""Who is trading is bound to the verified caller identity (GHSA-w39v-5v7h-fxg9).

``trade_governance.rego`` sets a trade's limits by ``trader_role``. These tests
pin that the gateway binds the role and ``trader_id`` from the caller's
verified workload identity, never from the request, and that each fail-closed
path refuses: an invalid ``CAGE_TRADER_ROLE_BINDINGS`` stops the finance
plugin from assembling, and a missing identity under an enforcing posture binds
no role, which the policy denies. The governor-level scenarios (a claimed
``senior`` routed as junior, a senior binding's limits) run in
``tests/test_trade_governance_e2e.py``.
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_finance.tools import tool_provider
from src.cage_finance.tools.trade_inputs import TRADE_ACTIONS, TradeInputResolver
from src.cage_finance.tools.trader_binding import (
    ALLOWED_TRADER_ROLES,
    LEAST_PRIVILEGE_ROLE,
    TRADER_KEYS,
    TRADER_ROLE_BINDINGS_ENV,
    UNVERIFIED_TRADER_ID,
    TraderBinding,
    TraderIdentityUnavailable,
    TraderRoleBindings,
    parse_trader_role_bindings,
)
from src.gateway.governance.governor.server_inputs import bind_server_inputs
from src.gateway.server.workload_identity import _serving
from tests.fixtures.trade_inputs import trade_server_inputs

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REGO = (
    Path(__file__).resolve().parents[2] / "src/cage_finance/opa/trade_governance.rego"
)
DESK = "desk-a.trading.serviceaccount.identity.linkerd.cluster.local"
SENIOR_DESK = "desk-b.trading.serviceaccount.identity.linkerd.cluster.local"
#: A tool call that claims the senior role and another desk's trader id.
CLAIMED: dict[str, Any] = {
    "symbol": "AAPL",
    "amount": 6_000.0,
    "currency": "USD",
    "side": "buy",
    "trader_role": "senior",
    "trader_id": "desk-b",
}


def _bindings(**kwargs: Any) -> TraderRoleBindings:
    return TraderRoleBindings(
        {SENIOR_DESK: TraderBinding(role="senior", trader_id="desk-b")}, **kwargs
    )


# ---------------------------------------------------------------------------
# CAGE_TRADER_ROLE_BINDINGS
# ---------------------------------------------------------------------------


def test_the_allowed_roles_are_the_trade_policys() -> None:
    match = re.search(r"allowed_roles := \{([^}]*)\}", _REGO.read_text())
    assert match is not None
    assert set(re.findall(r'"([^"]+)"', match.group(1))) == ALLOWED_TRADER_ROLES
    assert LEAST_PRIVILEGE_ROLE == "junior"


def test_unset_or_blank_configuration_has_no_bindings() -> None:
    assert parse_trader_role_bindings(None) == {}
    assert parse_trader_role_bindings("   ") == {}
    assert dict(TraderRoleBindings.from_env({}).bindings) == {}


def test_configuration_maps_an_identity_to_a_role_and_an_optional_trader() -> None:
    raw = json.dumps(
        {DESK: "senior", SENIOR_DESK: {"role": "senior", "trader_id": "desk-b"}}
    )

    bindings = TraderRoleBindings.from_env({TRADER_ROLE_BINDINGS_ENV: raw})

    assert dict(bindings.bindings) == {
        DESK: TraderBinding(role="senior"),
        SENIOR_DESK: TraderBinding(role="senior", trader_id="desk-b"),
    }


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("senior", id="not-json"),
        pytest.param("[]", id="array"),
        pytest.param('"senior"', id="string"),
        pytest.param(json.dumps({DESK: "admin"}), id="role-outside-policy"),
        pytest.param(json.dumps({DESK: "Senior"}), id="role-wrong-case"),
        pytest.param(json.dumps({DESK: ""}), id="empty-role"),
        pytest.param(json.dumps({DESK: 1}), id="numeric-role"),
        pytest.param(json.dumps({DESK: ["senior"]}), id="list-binding"),
        pytest.param(json.dumps({DESK: {"trader_id": "d"}}), id="no-role"),
        pytest.param(
            json.dumps({DESK: {"role": "senior", "limit": 1}}), id="unknown-field"
        ),
        pytest.param(
            json.dumps({DESK: {"role": "senior", "trader_id": "a b"}}),
            id="malformed-trader-id",
        ),
        pytest.param(
            json.dumps({DESK: {"role": "senior", "trader_id": 7}}),
            id="numeric-trader-id",
        ),
        pytest.param(
            json.dumps({"spiffe://cluster.local/ns/trading/sa/desk-a": "senior"}),
            id="spiffe-uri-key",
        ),
        pytest.param(json.dumps({DESK.upper(): "senior"}), id="non-canonical-key"),
        pytest.param(f'{{"{DESK}": "junior", "{DESK}": "senior"}}', id="duplicate-key"),
    ],
)
def test_invalid_configuration_fails_closed(raw: str) -> None:
    with pytest.raises(ValueError):
        TraderRoleBindings.from_env({TRADER_ROLE_BINDINGS_ENV: raw})


def test_a_binding_must_be_a_trader_binding() -> None:
    with pytest.raises(TypeError):
        TraderRoleBindings({DESK: "senior"})  # type: ignore[dict-item]


def test_invalid_configuration_stops_the_finance_plugin_from_assembling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fail closed at the composition root: no governor, so the gateway does
    # not start with a role binding it cannot trust.
    monkeypatch.setenv(TRADER_ROLE_BINDINGS_ENV, json.dumps({DESK: "admin"}))

    with pytest.raises(ValueError, match="admin"):
        FinanceCagePlugin().contribute()


def test_the_plugin_binds_every_trade_action_from_the_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(TRADER_ROLE_BINDINGS_ENV, json.dumps({SENIOR_DESK: "senior"}))

    contribution = FinanceCagePlugin().contribute()

    for action in TRADE_ACTIONS:
        resolver = contribution.server_inputs[action]
        assert isinstance(resolver, TradeInputResolver)
        assert TRADER_KEYS <= resolver.owned_keys
        assert resolver.traders.bind(SENIOR_DESK)["trader_role"] == "senior"
        assert resolver.traders.bind(DESK)["trader_role"] == LEAST_PRIVILEGE_ROLE


# ---------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------


def test_an_unbound_identity_is_least_privilege_and_its_own_trader() -> None:
    assert _bindings().bind(DESK) == {"trader_role": "junior", "trader_id": DESK}


def test_a_bound_identity_gets_its_role_and_trader_id() -> None:
    assert _bindings().bind(SENIOR_DESK) == {
        "trader_role": "senior",
        "trader_id": "desk-b",
    }
    no_id = TraderRoleBindings({SENIOR_DESK: TraderBinding(role="senior")})
    assert no_id.bind(SENIOR_DESK) == {
        "trader_role": "senior",
        "trader_id": SENIOR_DESK,
    }


def test_no_identity_is_refused_when_the_posture_requires_one() -> None:
    with pytest.raises(TraderIdentityUnavailable):
        _bindings(require_identity=True).bind(None)


def test_no_identity_is_junior_in_a_permissive_posture() -> None:
    assert _bindings(require_identity=False).bind(None) == {
        "trader_role": "junior",
        "trader_id": UNVERIFIED_TRADER_ID,
    }


@pytest.mark.parametrize(
    ("cage_env", "required"),
    [
        ("production", True),
        ("staging", True),
        ("local", True),
        ("unknown-posture", True),
        (None, True),  # unset resolves to production (fail secure)
        ("dev", False),
        ("test", False),
        ("ci", False),
    ],
)
def test_the_identity_requirement_follows_the_posture(
    monkeypatch: pytest.MonkeyPatch, cage_env: str | None, required: bool
) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    if cage_env is None:
        monkeypatch.delenv("CAGE_ENV", raising=False)
    else:
        monkeypatch.setenv("CAGE_ENV", cage_env)

    assert TraderRoleBindings().require_identity is required


# ---------------------------------------------------------------------------
# Through the kernel binder (every path that evaluates a trade)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", TRADE_ACTIONS)
async def test_claimed_role_and_trader_are_dropped_and_rebound(action: str) -> None:
    resolvers = trade_server_inputs(traders=_bindings(require_identity=True))

    with _serving(DESK):
        as_desk = await bind_server_inputs(resolvers, action, CLAIMED)
    with _serving(SENIOR_DESK):
        as_senior = await bind_server_inputs(
            resolvers, action, {**CLAIMED, "trader_role": "junior"}
        )

    assert (as_desk["trader_role"], as_desk["trader_id"]) == ("junior", DESK)
    assert (as_senior["trader_role"], as_senior["trader_id"]) == ("senior", "desk-b")


async def test_no_identity_under_an_enforcing_posture_binds_no_trader() -> None:
    resolvers = trade_server_inputs(traders=_bindings(require_identity=True))

    bound = await bind_server_inputs(resolvers, "execute_trade", CLAIMED)

    # The claimed values are dropped and nothing replaces them, so the trade
    # policy sees no role (an explicit DENY); the measurements are unaffected.
    assert TRADER_KEYS.isdisjoint(bound)
    assert {"latency_ms", "drawdown", "order_size", "daily_vol"} <= set(bound)


async def test_the_default_resolver_binds_every_identity_as_junior() -> None:
    resolvers = trade_server_inputs()

    with _serving(SENIOR_DESK):
        bound = await bind_server_inputs(resolvers, "execute_trade", CLAIMED)

    assert (bound["trader_role"], bound["trader_id"]) == ("junior", SENIOR_DESK)


# ---------------------------------------------------------------------------
# The agent-facing tool
# ---------------------------------------------------------------------------


def test_the_trade_tool_takes_no_trader_arguments() -> None:
    params = inspect.signature(tool_provider.execute_trade_action).parameters
    assert TRADER_KEYS.isdisjoint(params)


async def test_the_mcp_tool_schema_exposes_no_trader_fields() -> None:
    server = FastMCP("trader-binding-schema")
    tool_provider.FinancialToolProvider().register_tools(server, MagicMock())

    tools = {tool.name: tool for tool in await server.list_tools()}
    properties = tools["execute_trade_action"].inputSchema["properties"]

    assert TRADER_KEYS.isdisjoint(properties)
    assert {"symbol", "amount", "currency", "side", "deferred_id"} <= set(properties)
    assert "governor" not in properties
