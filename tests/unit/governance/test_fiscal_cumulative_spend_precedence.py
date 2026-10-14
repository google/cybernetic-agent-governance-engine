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

"""Cumulative-spend keys in ``evaluate_trajectory``: the seeded
``_shadow_daily_spend_usd`` must not mask a caller-supplied ``cumulative_notional``.

``FiscalTierPlugin`` prefers ``_shadow_daily_spend_usd`` whenever it is present,
so the eval harness has to keep both keys consistent with the spend the caller
carries (initial state or per-step context).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.eval_harness import FoundationModelEvalHarness, ToolActionStep
from src.eval_harness.harness import _seed_cumulative_spend_keys
from tests.fixtures.governor import default_classifier, make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_CAP = 500_000.0
_TRADE = {"ticker": "AAPL", "action": "BUY", "shares": 10, "amount": 5_000.0}


def _tier() -> FiscalTierPlugin:
    guard = MagicMock()
    guard._daily_cap_usd = _CAP
    return FiscalTierPlugin(guard=guard)


def _harness() -> FoundationModelEvalHarness:
    gov = make_governor(
        core_stages=(),
        classifier=default_classifier(),
        domain_tiers=(_tier(),),
    )
    return FoundationModelEvalHarness(gov)


def _step(step_id: int, context: dict[str, object] | None = None) -> ToolActionStep:
    return ToolActionStep(
        step_id=step_id,
        tool_name="execute_trade",
        arguments=dict(_TRADE),
        context={"confidence": 0.99, **(context or {})},
    )


@pytest.mark.asyncio
async def test_step_context_cumulative_notional_is_not_masked() -> None:
    """Case A: per-step ``cumulative_notional``, no initial state."""
    report, _ = await _harness().evaluate_trajectory(
        trajectory_id="fiscal-A",
        model_id="test",
        prompt="trade",
        steps=[_step(1, {"cumulative_notional": 1e9})],
    )
    assert report.allow_steps == 0


@pytest.mark.asyncio
async def test_step_context_shadow_daily_spend_is_honoured() -> None:
    """Case B: per-step ``_shadow_daily_spend_usd`` (already worked)."""
    report, _ = await _harness().evaluate_trajectory(
        trajectory_id="fiscal-B",
        model_id="test",
        prompt="trade",
        steps=[_step(1, {"_shadow_daily_spend_usd": 1e9})],
    )
    assert report.allow_steps == 0


@pytest.mark.asyncio
async def test_initial_state_cumulative_notional_is_not_masked() -> None:
    """Case C: ``initial_shadow_state`` carrying only ``cumulative_notional``."""
    report, _ = await _harness().evaluate_trajectory(
        trajectory_id="fiscal-C",
        model_id="test",
        prompt="trade",
        steps=[_step(1)],
        initial_shadow_state={"cumulative_notional": 1e9},
    )
    assert report.allow_steps == 0


@pytest.mark.asyncio
async def test_control_no_spend_context_allows() -> None:
    """Case D: no spend carried anywhere still admits a small trade."""
    report, _ = await _harness().evaluate_trajectory(
        trajectory_id="fiscal-D",
        model_id="test",
        prompt="trade",
        steps=[_step(1)],
    )
    assert report.allow_steps == 1


@pytest.mark.asyncio
async def test_initial_cumulative_notional_accumulates_across_steps() -> None:
    """Case E: spend carried in ``cumulative_notional`` keeps binding as steps accumulate.

    495k + 5k fits the 500k cap (step 1 allowed); the accumulated 500k + 5k does not
    (step 2 denied). If the seeded ``_shadow_daily_spend_usd`` started at 0.0 both
    steps would be allowed.
    """
    report, _ = await _harness().evaluate_trajectory(
        trajectory_id="fiscal-E",
        model_id="test",
        prompt="two trades",
        steps=[_step(1), _step(2)],
        initial_shadow_state={"cumulative_notional": 495_000.0},
    )
    assert report.allow_steps == 1
    assert report.step_results[1].decision.value == "DENY"


@pytest.mark.asyncio
async def test_initial_state_with_unequal_keys_uses_the_larger_spend() -> None:
    """Case F: both keys present in ``initial_shadow_state`` but out of sync.

    ``FiscalTierPlugin`` prefers ``_shadow_daily_spend_usd``, so the smaller value
    must be raised to the larger one rather than left to mask it.
    """
    report, _ = await _harness().evaluate_trajectory(
        trajectory_id="fiscal-F",
        model_id="test",
        prompt="trade",
        steps=[_step(1)],
        initial_shadow_state={
            "_shadow_daily_spend_usd": 0.0,
            "cumulative_notional": 1e9,
        },
    )
    assert report.allow_steps == 0


def test_seed_synchronises_valid_values_and_preserves_invalid_ones() -> None:
    nan = float("nan")

    state: dict[str, object] = {}
    _seed_cumulative_spend_keys(state)
    assert state == {"_shadow_daily_spend_usd": 0.0, "cumulative_notional": 0.0}

    state = {"cumulative_notional": 7.0}
    _seed_cumulative_spend_keys(state)
    assert state == {"_shadow_daily_spend_usd": 7.0, "cumulative_notional": 7.0}

    state = {"_shadow_daily_spend_usd": 1.0, "cumulative_notional": 9.0}
    _seed_cumulative_spend_keys(state)
    assert state == {"_shadow_daily_spend_usd": 9.0, "cumulative_notional": 9.0}

    # An invalid value is never overwritten (the tier ignores it and consults the live
    # guard); a missing key is filled from the valid one.
    state = {"_shadow_daily_spend_usd": nan}
    _seed_cumulative_spend_keys(state)
    assert state["_shadow_daily_spend_usd"] is nan
    assert state["cumulative_notional"] == 0.0

    state = {"_shadow_daily_spend_usd": True, "cumulative_notional": 5.0}
    _seed_cumulative_spend_keys(state)
    assert state["_shadow_daily_spend_usd"] is True
    assert state["cumulative_notional"] == 5.0
