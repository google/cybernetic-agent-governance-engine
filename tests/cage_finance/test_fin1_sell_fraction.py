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

"""FIN-1 / UCA-13: regional portfolio sell-fraction limit.

A sell (``side == "sell"``, case-insensitive) whose ``amount`` exceeds
``domains.finance.stpa.max_sell_portfolio_fraction * portfolio_total`` is a
HARD STPA violation, like its sibling UCA-5 / UCA-6 rules. A sell without a
numeric ``amount`` and ``portfolio_total`` fails closed. Buys, unscoped trades
and other actions are outside the rule.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.cage_finance.stpa import uca_rules
from src.cage_finance.stpa.uca_rules import UCA_RULES, GeneratedSTPAValidator
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds

pytestmark = [pytest.mark.unit, pytest.mark.local]

_CODE = "STPA_UCA_UCA_13"
_PORTFOLIO = 100_000.0
_FRACTION = {"US_FED": 0.10, "EU_ECB": 0.08, "APAC_MAS": 0.09}
REGIONS = tuple(_FRACTION)


@pytest.fixture(params=REGIONS)
def region(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the generated rules to ``region``'s effective thresholds.

    ``uca_rules`` binds ``THRESHOLDS`` at import (the process region), so the
    test swaps in the region's overlay there.
    """
    name: str = request.param
    monkeypatch.setattr(
        uca_rules, "THRESHOLDS", load_and_validate_thresholds(region=name)
    )
    return name


def _check(params: dict[str, Any], action: str = "execute_trade") -> Any:
    return GeneratedSTPAValidator()._check_uca_13(action, params)


def _sell(amount: Any, portfolio_total: Any = _PORTFOLIO, **extra: Any) -> dict:
    return {
        "side": "sell",
        "amount": amount,
        "portfolio_total": portfolio_total,
        **extra,
    }


def _limit(region: str) -> float:
    return _FRACTION[region] * _PORTFOLIO


def test_regional_fraction_is_the_effective_threshold(region: str) -> None:
    assert uca_rules.THRESHOLDS.resolve(
        "domains.finance.stpa.max_sell_portfolio_fraction"
    ) == pytest.approx(_FRACTION[region])


def test_sell_at_the_limit_is_allowed(region: str) -> None:
    assert _check(_sell(_limit(region))) is None


def test_sell_below_the_limit_is_allowed(region: str) -> None:
    assert _check(_sell(_limit(region) - 1.0)) is None


def test_sell_above_the_limit_is_a_hard_violation(region: str) -> None:
    violation = _check(_sell(_limit(region) + 0.01))
    assert violation is not None
    assert violation.code == _CODE
    assert violation.tier == "stpa"
    assert violation.kind is ViolationKind.HARD


def test_regions_differ_at_the_same_amount(region: str) -> None:
    """8,500 of 100,000 is refused under EU_ECB (8%) only."""
    violation = _check(_sell(8_500.0))
    assert (violation is not None) is (region == "EU_ECB")


@pytest.mark.parametrize("side", ["SELL", " Sell ", "sell"])
def test_side_match_is_case_insensitive(region: str, side: str) -> None:
    params = _sell(_limit(region) * 2)
    params["side"] = side
    assert _check(params) is not None


@pytest.mark.parametrize(
    "params",
    [
        {"side": "buy", "amount": 1e12, "portfolio_total": 1.0},
        {"amount": 1e12, "portfolio_total": 1.0},
        {"side": "buy"},
        {"side": None, "amount": 1e12},
        {"side": 1, "amount": 1e12},
    ],
    ids=["buy", "no-side", "buy-no-inputs", "side-none", "side-not-str"],
)
def test_non_sells_are_out_of_scope(region: str, params: dict) -> None:
    assert _check(params) is None


def test_other_actions_are_out_of_scope(region: str) -> None:
    assert _check(_sell(1e12), action="execute_trade_bounded") is None
    assert _check(_sell(1e12), action="market_analysis") is None


@pytest.mark.parametrize(
    "params",
    [
        {"side": "sell", "amount": 1.0},
        {"side": "sell", "portfolio_total": _PORTFOLIO},
        {"side": "sell"},
        _sell(1.0, portfolio_total=None),
        _sell(None),
    ],
    ids=["no-portfolio", "no-amount", "no-inputs", "portfolio-none", "amount-none"],
)
def test_sell_with_missing_input_fails_closed(region: str, params: dict) -> None:
    violation = _check(params)
    assert violation is not None
    assert violation.code == _CODE
    assert violation.kind is ViolationKind.HARD
    assert "Missing required" in violation.message


@pytest.mark.parametrize(
    ("amount", "portfolio_total"),
    [
        (1.0, True),
        (True, _PORTFOLIO),
        (1.0, "not-a-number"),
        (1.0, [1.0]),
        (1.0, float("nan")),
        (1.0, float("inf")),
        (1.0, -1.0),
        (-1.0, _PORTFOLIO),
        (1.0, 0.0),
    ],
    ids=[
        "portfolio-bool",
        "amount-bool",
        "portfolio-str",
        "portfolio-list",
        "portfolio-nan",
        "portfolio-inf",
        "portfolio-negative",
        "amount-negative",
        "portfolio-zero",
    ],
)
def test_sell_with_invalid_input_fails_closed(
    region: str, amount: Any, portfolio_total: Any
) -> None:
    violation = _check(_sell(amount, portfolio_total))
    assert violation is not None
    assert violation.code == _CODE
    assert violation.kind is ViolationKind.HARD


def test_numeric_strings_are_parsed(region: str) -> None:
    assert _check(_sell(str(_limit(region)), str(_PORTFOLIO))) is None
    assert _check(_sell(str(_limit(region) + 1), str(_PORTFOLIO))) is not None


def test_rule_is_contributed_to_the_kernel_stpa_stage(region: str) -> None:
    rule = next(r for r in UCA_RULES if r.uca_id == "UCA-13")
    assert rule.action_name == "execute_trade"
    assert rule.predicate(_sell(_limit(region))) is None
    violation = rule.predicate(_sell(_limit(region) + 1))
    assert violation is not None and violation.kind is ViolationKind.HARD


def test_validator_reports_uca_13_among_generated_checks(region: str) -> None:
    violations = GeneratedSTPAValidator().validate_generated(
        "execute_trade", _sell(_limit(region) + 1)
    )
    assert _CODE in {v.code for v in violations}
