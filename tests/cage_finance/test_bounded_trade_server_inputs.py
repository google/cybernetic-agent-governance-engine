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

"""A bounded trade's measured inputs are server-bound (POAM-2026-108).

``execute_trade_bounded`` had no server-input resolver, so the kernel passed
the caller's params straight through, and bounding contract B2 (daily drawdown
circuit breaker) was never given a measured drawdown. The finance plugin now
registers its trade resolver for every trade action, and the bounding tier
hands B2 the drawdown the gateway measured from one verified NAV snapshot. A
caller's ``drawdown`` (or alias) is dropped on every path.

The guard tests derive the measured-state consumers from the STPA hazard file
and the contributed tiers, so a future action or tier that reads an owned key
without a resolver fails here.
"""

from __future__ import annotations

import ast
import inspect
import math
import re
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_finance.simulated_feeds import SimulatedPortfolioNavSource
from src.cage_finance.stpa import uca_rules
from src.cage_finance.tiers.bounding_tier import (
    BOUNDING_SERVER_INPUT_KEYS,
    BoundingContractTierPlugin,
    bound_drawdown_fraction,
)
from src.cage_finance.tools.trade_inputs import (
    TRADE_ACTIONS,
    TRADE_SERVER_INPUT_KEYS,
    TradeInputResolver,
)
from src.gateway.governance.contracts import (
    PluginContribution,
    ViolationKind,
)
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.server_inputs import bind_server_inputs
from src.gateway.governance.schemas import thresholds as thresholds_module
from src.gateway.governance.seams.ground_truth import FaultMode
from src.gateway.server.governance_middleware import governance_app
from tests.fixtures.governor import make_governor
from tests.test_trade_governance_e2e import ADVISOR, Gateway, gw  # noqa: F401

pytestmark = [pytest.mark.unit, pytest.mark.local]

_BOUNDED = "execute_trade_bounded"
_B2 = "BOUNDING_B2_HARD_BLOCK"
#: region -> B2 daily drawdown limit, percent (``domains.finance.drawdown.limit``)
_B2_LIMIT_PCT = {"US_FED": 5.0, "APAC_MAS": 4.5, "EU_ECB": 4.0}
#: Every caller spelling of the drawdown, all claiming a flat day.
_CALLER_DRAWDOWN = {
    "drawdown": 0.0,
    "current_drawdown": 0.0,
    "portfolio_drawdown_pct": 0.0,
}
_NAV_FAULTS = [
    FaultMode.TIMEOUT,
    FaultMode.CONNECTION_ERROR,
    FaultMode.MALFORMED_PAYLOAD,
    FaultMode.NEGATIVE_VALUE,
    FaultMode.NAN_VALUE,
    FaultMode.STALE_TIMESTAMP,
    FaultMode.FUTURE_TIMESTAMP,
    FaultMode.UNVERIFIED_SOURCE,
]
_HAZARDS = (
    Path(__file__).resolve().parents[2]
    / "src/cage_finance/config/stpa/trade_hazards.yaml"
)
#: Params a tier's ``claims_action`` may look at; a claim-by-cost tier needs a
#: trade-shaped request.
_PROBE_PARAMS = {"symbol": "AAPL", "amount": 1_000.0, "side": "buy", "venue": "NYSE"}


def _bounded(**extra: Any) -> dict[str, Any]:
    return {
        "symbol": "AAPL",
        "amount": 1_000.0,
        "side": "buy",
        "venue": "NYSE",
        "rollback_window_seconds": 300,
        "trader_role": "senior",
        "confidence": 0.98,
        **extra,
    }


@pytest.fixture(params=tuple(_B2_LIMIT_PCT))
def region(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the plugin and the generated rules to ``region``'s thresholds."""
    name: str = request.param
    effective = thresholds_module.load_and_validate_thresholds(region=name)
    monkeypatch.setattr(thresholds_module, "THRESHOLDS", effective)
    monkeypatch.setattr(uca_rules, "THRESHOLDS", effective)
    return name


@pytest.fixture
def contribution(region: str) -> PluginContribution:
    return FinanceCagePlugin().contribute()


def _bounding(c: PluginContribution) -> BoundingContractTierPlugin:
    (tier,) = [t for t in c.tiers if isinstance(t, BoundingContractTierPlugin)]
    return tier


def _nav(c: PluginContribution) -> SimulatedPortfolioNavSource:
    resolver = c.server_inputs[_BOUNDED]
    assert isinstance(resolver, TradeInputResolver)
    nav = resolver.inputs.nav_source
    assert isinstance(nav, SimulatedPortfolioNavSource)
    return nav


async def _b2(
    c: PluginContribution, **params: Any
) -> tuple[Mapping[str, Any], list[tuple[str, ViolationKind, str]]]:
    """Bind as the kernel does; return (bound params, B2 findings)."""
    bound = await bind_server_inputs(c.server_inputs, _BOUNDED, _bounded(**params))
    found = [
        (v.code, v.kind, v.message)
        for v in await _bounding(c).evaluate(_BOUNDED, dict(bound))
        if v.code == _B2
    ]
    return bound, found


# ---------------------------------------------------------------------------
# Guards: every consumer of an owned key has a resolver that owns it
# ---------------------------------------------------------------------------


def _uca_params(condition: Mapping[str, Any]) -> set[str]:
    """The param names an STPA condition reads."""
    names: set[str] = set()
    if isinstance(condition.get("param"), str):
        names.add(condition["param"])
    names |= set(condition.get("param_aliases", ()))
    composite = condition.get("composite")
    if isinstance(composite, str):
        names |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", composite))
    applies = condition.get("applies_when")
    if isinstance(applies, Mapping) and isinstance(applies.get("param"), str):
        names.add(applies["param"])
    return names


def _stpa_consumers() -> dict[str, set[str]]:
    """action -> owned keys its STPA rules read (from ``trade_hazards.yaml``)."""
    doc = yaml.safe_load(_HAZARDS.read_text())
    consumers: dict[str, set[str]] = {}
    for uca in doc["unsafe_control_actions"]:
        used = _uca_params(uca.get("condition") or {}) & TRADE_SERVER_INPUT_KEYS
        if used:
            consumers.setdefault(uca["action"], set()).update(used)
    return consumers


def _literal_owned_keys(tier: object) -> set[str]:
    """Owned keys named as string literals in the tier's own module."""
    tree = ast.parse(inspect.getsource(inspect.getmodule(type(tier))))  # type: ignore[arg-type]
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value in TRADE_SERVER_INPUT_KEYS
    }


def _tier_consumers(c: PluginContribution) -> dict[str, set[str]]:
    """action -> owned keys the contributed tiers claiming it read."""
    consumers: dict[str, set[str]] = {}
    for tier in c.tiers:
        keys = set(getattr(tier, "server_input_keys", frozenset()))
        if not keys:
            continue
        for action in c.registered_actions:
            if tier.claims_action(action, dict(_PROBE_PARAMS)):
                consumers.setdefault(action, set()).update(keys)
    return consumers


def _unbound_consumers(c: PluginContribution) -> dict[str, set[str]]:
    """action -> consumed owned keys no resolver for that action owns."""
    missing: dict[str, set[str]] = {}
    for source in (_stpa_consumers(), _tier_consumers(c)):
        for action, keys in source.items():
            resolver = c.server_inputs.get(action)
            owned = set(resolver.owned_keys) if resolver is not None else set()
            if keys - owned:
                missing.setdefault(action, set()).update(keys - owned)
    return missing


def test_every_consumer_of_an_owned_key_has_a_resolver(
    contribution: PluginContribution,
) -> None:
    assert _unbound_consumers(contribution) == {}


def test_the_guard_sees_the_bounded_tier_and_the_stpa_rules(
    contribution: PluginContribution,
) -> None:
    # The guard is not vacuous: it finds both kinds of consumer.
    assert _tier_consumers(contribution)[_BOUNDED] == {"drawdown"}
    assert {"latency_ms", "drawdown", "order_size", "daily_vol"} <= (
        _stpa_consumers()["execute_trade"]
    )


def test_the_guard_catches_an_action_without_a_resolver(
    contribution: PluginContribution,
) -> None:
    # The defect this PR fixes, reintroduced: no resolver for the bounded verb.
    unbound = replace(
        contribution,
        server_inputs={"execute_trade": contribution.server_inputs["execute_trade"]},
    )
    assert _unbound_consumers(unbound) == {_BOUNDED: {"drawdown"}}


def test_every_tier_declares_the_owned_keys_it_names(
    contribution: PluginContribution,
) -> None:
    # A tier that starts reading an owned key must declare it, or the guard
    # above would not know to look for its resolver.
    for tier in contribution.tiers:
        declared = set(getattr(tier, "server_input_keys", frozenset()))
        assert _literal_owned_keys(tier) <= declared, type(tier).__name__


def test_every_trade_action_gets_the_trade_resolver(
    contribution: PluginContribution,
) -> None:
    resolvers = {contribution.server_inputs[a] for a in TRADE_ACTIONS}
    assert len(resolvers) == 1  # one resolver, one set of sources
    (resolver,) = resolvers
    assert isinstance(resolver, TradeInputResolver)
    assert BOUNDING_SERVER_INPUT_KEYS <= resolver.owned_keys
    assert set(TRADE_ACTIONS) <= set(contribution.registered_actions)


# ---------------------------------------------------------------------------
# B2 reads the server-bound drawdown, per region
# ---------------------------------------------------------------------------


def test_b2_limit_is_the_regional_limit(
    region: str, contribution: PluginContribution
) -> None:
    limit = _bounding(contribution).registry.thresholds["drawdown"]["limit"]
    assert limit * 100.0 == pytest.approx(_B2_LIMIT_PCT[region])


async def test_caller_zero_drawdown_cannot_pass_b2_over_the_limit(
    region: str, contribution: PluginContribution
) -> None:
    _nav(contribution).set_drawdown_pct(_B2_LIMIT_PCT[region] + 0.5)

    bound, found = await _b2(contribution, **_CALLER_DRAWDOWN)

    assert bound["drawdown"] == pytest.approx(_B2_LIMIT_PCT[region] + 0.5)
    assert "current_drawdown" not in bound
    assert "portfolio_drawdown_pct" not in bound
    assert [(code, kind) for code, kind, _ in found] == [(_B2, ViolationKind.HARD)]
    assert "exceeds circuit breaker limit" in found[0][2]


async def test_server_drawdown_under_the_limit_passes_b2(
    region: str, contribution: PluginContribution
) -> None:
    _nav(contribution).set_drawdown_pct(_B2_LIMIT_PCT[region] - 0.5)

    # A caller claiming a breach is ignored just the same.
    bound, found = await _b2(contribution, drawdown=99.0, current_drawdown=0.99)

    assert bound["drawdown"] == pytest.approx(_B2_LIMIT_PCT[region] - 0.5)
    assert found == []


@pytest.mark.parametrize("fault", _NAV_FAULTS, ids=lambda f: f.value)
async def test_nav_fault_refuses_with_b2(
    region: str, contribution: PluginContribution, fault: FaultMode
) -> None:
    _nav(contribution).inject_fault(fault)

    bound, found = await _b2(contribution, **_CALLER_DRAWDOWN)

    assert "drawdown" not in bound
    assert [(code, kind) for code, kind, _ in found] == [(_B2, ViolationKind.HARD)]
    assert "Missing current drawdown data" in found[0][2]


async def test_no_nav_source_refuses_with_b2(
    contribution: PluginContribution,
) -> None:
    resolver = contribution.server_inputs[_BOUNDED]
    assert isinstance(resolver, TradeInputResolver)
    blind = replace(
        contribution,
        server_inputs={
            _BOUNDED: replace(
                resolver, inputs=replace(resolver.inputs, nav_source=None)
            )
        },
    )

    bound, found = await _b2(blind, **_CALLER_DRAWDOWN)

    assert "drawdown" not in bound
    assert [(code, kind) for code, kind, _ in found] == [(_B2, ViolationKind.HARD)]


@pytest.mark.parametrize("raw", [None, "0.0", True, [0.0]])
def test_unusable_bound_drawdown_is_unmeasured(raw: Any) -> None:
    assert bound_drawdown_fraction({"drawdown": raw}) is None


def test_bound_drawdown_is_converted_to_a_fraction() -> None:
    assert bound_drawdown_fraction({"drawdown": 4.5}) == pytest.approx(0.045)
    assert math.isnan(bound_drawdown_fraction({"drawdown": math.nan}) or 0.0)


# ---------------------------------------------------------------------------
# Through the gateway: POST /governance/validate-action and verify()
# ---------------------------------------------------------------------------


def _install(contribution: PluginContribution) -> Any:
    governor = make_governor(
        domain_tiers=(_bounding(contribution),),
        server_inputs=contribution.server_inputs,
        posture=DeploymentPosture.TEST,
    )
    governance_app.state.governor = governor
    return governor


async def test_validate_action_refuses_a_caller_drawdown_over_the_limit(
    region: str,
    contribution: PluginContribution,
    gw: Gateway,  # noqa: F811
) -> None:
    _install(contribution)
    _nav(contribution).set_drawdown_pct(_B2_LIMIT_PCT[region] + 0.5)

    resp = await gw.validate(_bounded(**_CALLER_DRAWDOWN), action=_BOUNDED)

    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["verdict"] == "DENIED"
    assert any(_B2 in v for v in body["violations"]), body["violations"]
    gw.refusals.assert_awaited_once()


async def test_validate_action_does_not_raise_b2_under_the_limit(
    region: str,
    contribution: PluginContribution,
    gw: Gateway,  # noqa: F811
) -> None:
    _install(contribution)
    _nav(contribution).set_drawdown_pct(_B2_LIMIT_PCT[region] - 0.5)

    resp = await gw.validate(_bounded(drawdown=99.0), action=_BOUNDED)

    assert not any(_B2 in v for v in resp.json().get("violations", [])), resp.text


async def test_validate_action_refuses_when_the_nav_source_faults(
    region: str,
    contribution: PluginContribution,
    gw: Gateway,  # noqa: F811
) -> None:
    _install(contribution)
    _nav(contribution).inject_fault(FaultMode.STALE_TIMESTAMP)

    resp = await gw.validate(_bounded(**_CALLER_DRAWDOWN), action=_BOUNDED)

    assert resp.status_code == 403, resp.text
    assert any(_B2 in v for v in resp.json()["violations"])


async def test_verify_preview_binds_the_bounded_drawdown(
    region: str, contribution: PluginContribution
) -> None:
    governor = make_governor(
        domain_tiers=(_bounding(contribution),),
        server_inputs=contribution.server_inputs,
        posture=DeploymentPosture.TEST,
    )
    _nav(contribution).set_drawdown_pct(_B2_LIMIT_PCT[region] + 0.5)

    result = await governor.verify(_BOUNDED, _bounded(**_CALLER_DRAWDOWN))

    assert result["decision"] != "ALLOW"
    assert any(v.code == _B2 for v in result["violations"])
