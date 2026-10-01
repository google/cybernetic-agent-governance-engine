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

"""Phase 1 governor wiring: claim-by-cost, governed-action fail-closed,
kind-not-code classification, and magnitude-extractor injection at assembly.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.gateway.governance.classification_engine import ClassificationContext
from src.gateway.governance.contracts import (
    ConsensusContribution,
    PluginContribution,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.ftra.models import (
    FtraBoundaryResult,
    RegistryState,
    TerminalClassification,
)
from src.gateway.governance.governor.assembly import DecisionFlags, assemble_governor
from src.gateway.governance.governor.pipeline import Profile, StageContext, run_pipeline
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.stages.ftra import FtraStage
from tests.fixtures.governor import allow_opa, clean_stpa, default_classifier, make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_TIERS = [
    pytest.param(lambda: CBFTierPlugin(MagicMock()), id="cbf"),
    pytest.param(lambda: FiscalTierPlugin(MagicMock()), id="fiscal"),
]


# ── claim-by-cost ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("make", _TIERS)
@pytest.mark.parametrize(
    ("action", "params", "claimed"),
    [
        ("execute_trade", {"amount": 10.0}, True),
        ("execute_trade_bounded", {"amount": 10.0}, True),
        ("execute_trade", {"amount": 0.0}, False),
        ("check_balance", {"amount": 10.0}, False),
    ],
)
def test_tiers_claim_by_cost(make, action, params, claimed) -> None:
    assert make().claims_action(action, params) is claimed


@pytest.mark.parametrize("make", _TIERS)
@pytest.mark.parametrize("amount", [-1.0, float("nan"), float("inf")])
def test_malformed_cost_raises_in_claims(make, amount) -> None:
    with pytest.raises(ValueError):
        make().claims_action("execute_trade", {"amount": amount})


@pytest.mark.asyncio
@pytest.mark.parametrize("make", _TIERS)
async def test_malformed_cost_becomes_hard_tier_exception(make) -> None:
    stages = order_stages([make()])
    ctx = StageContext(action="execute_trade", params={"amount": -5.0}, profile=Profile.DRY_RUN)
    result = await run_pipeline(stages, ctx, profile=Profile.DRY_RUN)
    assert [(v.code, v.kind) for v in result.violations] == [("TIER_EXCEPTION", ViolationKind.HARD)]


@pytest.mark.parametrize("make", _TIERS)
def test_cost_resolver_is_injectable(make) -> None:
    tier = make()
    tier._cost = lambda action, params: 3.0 if action == "dispense" else 0.0  # noqa: SLF001
    assert tier.claims_action("dispense", {}) and not tier.claims_action("execute_trade", {"amount": 9.0})


# ── _is_governed_action fails closed ─────────────────────────────────────────


class _RaisingTier:
    tier_name, phase, order = "raiser", 2, 1

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        raise KeyError("boom")

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Any]:
        return []


class _NeverTier(_RaisingTier):
    tier_name = "never"

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return False


def test_raising_claims_counts_as_governed() -> None:
    governor = make_governor(domain_tiers=[_RaisingTier()])
    assert governor._is_governed_action("anything", {}) is True  # noqa: SLF001


def test_no_claiming_tier_is_ungoverned() -> None:
    governor = make_governor(domain_tiers=[_NeverTier()])
    assert governor._is_governed_action("anything", {}) is False  # noqa: SLF001


# ── R5: classification keys on ViolationKind, never on FTRA codes ───────────


@pytest.mark.parametrize(
    ("state", "decision"),
    [
        (RegistryState.REGISTERED, GovernanceDecision.REQUIRE_APPROVAL),
        (RegistryState.UNREGISTERED, GovernanceDecision.REQUIRE_APPROVAL),
        (RegistryState.INVALID_ENTRY, GovernanceDecision.REQUIRE_APPROVAL),
        (RegistryState.UNAVAILABLE, GovernanceDecision.DENY),
    ],
)
def test_ftra_provenance_codes_classify_by_kind(state, decision) -> None:
    violations = FtraBoundaryResult.from_classification(
        TerminalClassification.IRREVERSIBLE_TERMINAL, "a", registry_state=state
    ).violations
    result = default_classifier().classify(
        ClassificationContext(
            violations=list(violations),
            confidence=0.99,
            opa_decision="ALLOW",
            policy_ambiguous=False,
            params={},
        ),
        "a",
    )
    assert result.decision == decision


# ── assembly injects the domain's magnitude extractor ───────────────────────


class _Plugin:
    api_version = "1.0"
    domain_config = None

    def __init__(self, **contribution: Any) -> None:
        self.name = "probe"
        self._contribution = {"domain": "probe", **contribution}

    def contribute(self) -> PluginContribution:
        return PluginContribution(**self._contribution)


def _assemble(**contribution: Any) -> Any:
    return assemble_governor(
        [_Plugin(**contribution)],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=False, narrow=False, pause=False),
    )


def _ftra_stage(governor: Any) -> FtraStage:
    (stage,) = [s for s in governor.stages if isinstance(s, FtraStage)]
    return stage


def _extractor(params: Any) -> float:
    return 7.0


def _own_extractor(params: Any) -> float:
    return 1.0


def test_assembly_injects_extractor_into_ftra_and_consensus() -> None:
    governor = _assemble(
        magnitude_extractor=_extractor,
        consensus=ConsensusContribution(critics=(), threshold=0.5),
    )
    assert _ftra_stage(governor)._magnitude_extractor is _extractor  # noqa: SLF001
    assert governor.components.consensus.magnitude_extractor is _extractor


def test_consensus_keeps_its_own_extractor() -> None:
    governor = _assemble(
        magnitude_extractor=_extractor,
        consensus=ConsensusContribution(
            critics=(), threshold=0.5, magnitude_extractor=_own_extractor
        ),
    )
    assert governor.components.consensus.magnitude_extractor is _own_extractor
    assert _ftra_stage(governor)._magnitude_extractor is _extractor  # noqa: SLF001


def test_no_extractor_means_ftra_clears_nothing() -> None:
    governor = _assemble()
    assert _ftra_stage(governor)._magnitude_extractor is None  # noqa: SLF001
