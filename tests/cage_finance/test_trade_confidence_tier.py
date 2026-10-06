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

"""[CTRL_AGT_001] The finance trade-confidence tier enforces each region's floor.

Floors come from the real regional baselines (``load_and_validate_thresholds``
with an explicit region), so the matrix fails if a baseline value drifts.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.cage_finance.thresholds import FinanceThresholds
from src.cage_finance.tiers.trade_confidence_tier import (
    TRADE_EXECUTION_ACTIONS,
    TradeConfidenceTier,
)
from src.gateway.governance.classification_engine import (
    ClassificationContext,
    ClassificationEngine,
)
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.pipeline import Profile, StageContext
from src.gateway.governance.governor.stages.confidence import ConfidenceStage
from src.gateway.governance.narrower import NarrowerRegistry
from src.gateway.governance.schemas import thresholds as thresholds_module
from src.gateway.governance.schemas.thresholds import (
    THRESHOLDS,
    load_and_validate_thresholds,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _regional_tier(region: str) -> TradeConfidenceTier:
    finance = FinanceThresholds.model_validate(
        load_and_validate_thresholds(region=region).domains["finance"]
    )
    return TradeConfidenceTier(finance.confidence.min_trade_confidence)


async def _kinds(tier: TradeConfidenceTier, score: Any, action: str = "execute_trade"):
    params = {"confidence": score, "amount": 100.0}
    assert tier.claims_action(action, params)
    return [v.kind for v in await tier.evaluate(action, params)]


# ── Region matrix ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("region", "score", "expected"),
    [
        ("EU_ECB", 0.96, [ViolationKind.HITL]),
        ("EU_ECB", 0.97, []),
        ("EU_ECB", 0.99, []),
        ("APAC_MAS", 0.955, [ViolationKind.HITL]),
        ("APAC_MAS", 0.96, []),
        ("US_FED", 0.955, []),
        ("US_FED", 0.95, []),
        ("US_FED", 0.949, [ViolationKind.HITL]),
        ("EU_ECB", 0.70, [ViolationKind.HITL]),  # defer_floor is inside the HITL zone
        ("EU_ECB", 0.5, [ViolationKind.DEFERRABLE]),
        ("APAC_MAS", 0.69, [ViolationKind.DEFERRABLE]),
        ("US_FED", 0.0, [ViolationKind.DEFERRABLE]),
    ],
)
async def test_regional_floor_matrix(region: str, score: float, expected: list) -> None:
    assert await _kinds(_regional_tier(region), score) == expected


@pytest.mark.parametrize("action", sorted(TRADE_EXECUTION_ACTIONS))
async def test_every_trade_execution_action_is_claimed(action: str) -> None:
    assert await _kinds(_regional_tier("EU_ECB"), 0.96, action) == [ViolationKind.HITL]


@pytest.mark.parametrize(
    "action",
    ["check_balance", "market_analysis", "check_market_status", "reverse_trade"],
)
def test_non_trade_actions_are_unaffected(action: str) -> None:
    assert not _regional_tier("EU_ECB").claims_action(action, {"confidence": 0.5})


@pytest.mark.parametrize(
    "score", [None, "0.99", True, float("nan"), float("inf"), -0.1, 1.01]
)
async def test_malformed_score_is_hard(score: Any) -> None:
    violations = await _regional_tier("EU_ECB").evaluate(
        "execute_trade", {"confidence": score}
    )
    assert [v.kind for v in violations] == [ViolationKind.HARD]
    assert violations[0].code == "TRADE_CONFIDENCE_INVALID"


async def test_violation_names_control_and_floor() -> None:
    (violation,) = await _regional_tier("EU_ECB").evaluate(
        "execute_trade", {"confidence": 0.96}
    )
    assert violation.tier == "trade_confidence"
    assert violation.code == "TRADE_CONFIDENCE_BELOW_FLOOR"
    assert violation.message.startswith("[CTRL_AGT_001]")
    assert "0.970" in violation.message


async def test_band_edge_follows_the_kernel_defer_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same band semantics as ConfidenceStage: the edge is the universal floor."""
    from src.cage_finance.tiers import trade_confidence_tier

    monkeypatch.setattr(
        trade_confidence_tier, "get_confidence_defer_floor", lambda: 0.9
    )
    assert await _kinds(_regional_tier("EU_ECB"), 0.89) == [ViolationKind.DEFERRABLE]
    assert await _kinds(_regional_tier("EU_ECB"), 0.9) == [ViolationKind.HITL]


@pytest.mark.parametrize("floor", [0.0, -0.5, 1.01, float("nan"), True, "0.97"])
def test_invalid_floor_is_refused(floor: Any) -> None:
    with pytest.raises(ValueError, match="min_trade_confidence"):
        TradeConfidenceTier(floor)


# ── Verdicts: the tier and the universal band classify together ──────────────


async def _verdict(region: str, score: float) -> GovernanceDecision:
    params = {"confidence": score, "amount": 100.0}
    violations = list(await _regional_tier(region).evaluate("execute_trade", params))
    violations += await ConfidenceStage().run(
        StageContext(action="execute_trade", params=params, profile=Profile.FULL)
    )
    if not violations:
        return GovernanceDecision.ALLOW
    classifier = ClassificationEngine(
        narrower_registry=NarrowerRegistry(),
        confidence_threshold=THRESHOLDS.confidence.agent_threshold,
        defer_enabled=True,
    )
    return classifier.classify(
        ClassificationContext(
            violations=violations,
            confidence=score,
            opa_decision="ALLOW",
            policy_ambiguous=False,
            params=params,
        ),
        "execute_trade",
    ).decision


@pytest.mark.parametrize(
    ("region", "score", "expected"),
    [
        ("EU_ECB", 0.96, GovernanceDecision.REQUIRE_APPROVAL),
        ("EU_ECB", 0.97, GovernanceDecision.ALLOW),
        ("APAC_MAS", 0.955, GovernanceDecision.REQUIRE_APPROVAL),
        ("US_FED", 0.955, GovernanceDecision.ALLOW),
        ("EU_ECB", 0.5, GovernanceDecision.DEFER),
    ],
)
async def test_regional_floor_verdicts(
    region: str, score: float, expected: GovernanceDecision
) -> None:
    assert await _verdict(region, score) == expected


# ── Plugin wiring ────────────────────────────────────────────────────────────


def _contribution_under(region: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    from src.cage_finance.plugin import FinanceCagePlugin

    monkeypatch.setattr(
        thresholds_module, "THRESHOLDS", load_and_validate_thresholds(region=region)
    )
    return FinanceCagePlugin().contribute()


@pytest.mark.parametrize(
    ("region", "floor", "gamma"),
    [("US_FED", 0.95, 0.5), ("EU_ECB", 0.97, 0.6), ("APAC_MAS", 0.96, 0.55)],
)
def test_plugin_wires_the_effective_floor_and_gamma(
    region: str, floor: float, gamma: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    contribution = _contribution_under(region, monkeypatch)
    (tier,) = [t for t in contribution.tiers if t.tier_name == "trade_confidence"]
    assert isinstance(tier, TradeConfidenceTier)
    assert tier.min_trade_confidence == floor
    assert (tier.phase, tier.order) == (1, 1)
    (barrier,) = contribution.invariants
    assert barrier.gamma == gamma


def test_plugin_refuses_an_unknown_finance_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import ValidationError

    from src.cage_finance.plugin import FinanceCagePlugin

    base = load_and_validate_thresholds(region="US_FED")
    finance = {**base.domains["finance"], "confidence": {"min_trade_confidnce": 0.97}}
    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        base.model_copy(update={"domains": {**base.domains, "finance": finance}}),
    )
    with pytest.raises(ValidationError):
        FinanceCagePlugin().contribute()
