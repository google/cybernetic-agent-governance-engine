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

"""Required tiers: an enforcing posture refuses to start without them.

A tier that is not enabled examined no evidence, so it can never stand in for
a verdict. These tests pin the refusal half: whatever later decides a tier is
disabled (for example, a tier whose data source is absent), an enforcing
posture with a required tier disabled or missing does not start. A permissive
posture logs the failure at CRITICAL and continues.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from typing import Any

import pytest

from src.gateway.governance.contracts import (
    PluginContribution,
    ReadOnlyTier,
    Violation,
)
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor import posture as posture_mod
from src.gateway.governance.governor.assembly import (
    DisabledTier,
    GovernorAssemblyError,
    _reject_unknown_required_tiers,
)
from src.gateway.governance.governor.posture import (
    PostureViolation,
    assert_production_posture,
)
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_PROD = DeploymentPosture.PRODUCTION
_STAGING = DeploymentPosture.STAGING
_DEV = DeploymentPosture.DEV
_REGISTERED_CHECKS = posture_mod.CHECKS


class _Tier(ReadOnlyTier):
    order = 1

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def tier_name(self) -> str:
        return self._name

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return False

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []


@pytest.fixture(autouse=True)
def _only_required_tiers_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run only the check under test, so no other probe can mask it."""
    monkeypatch.setattr(
        posture_mod,
        "CHECKS",
        tuple(c for c in posture_mod.CHECKS if c[0] == "required_tiers"),
    )


def _components(
    posture: DeploymentPosture,
    *,
    enabled: tuple[str, ...],
    required: frozenset[str],
    disabled: tuple[DisabledTier, ...] = (),
) -> Any:
    tiers = tuple(_Tier(n) for n in enabled)
    base = make_governor(posture=posture, domain_tiers=tiers).components
    contribution = PluginContribution(
        domain="d",
        tiers=(*tiers, *(_Tier(d.tier_name) for d in disabled)),
        required_tiers=required,
    )
    return dataclasses.replace(
        base, contributions=(contribution,), disabled_tiers=disabled
    )


def test_required_tiers_check_is_registered_first() -> None:
    assert _REGISTERED_CHECKS[0][0] == "required_tiers"


@pytest.mark.parametrize("posture", [_PROD, _STAGING, DeploymentPosture.LOCAL])
def test_enforcing_posture_refuses_a_disabled_required_tier(
    posture: DeploymentPosture,
) -> None:
    components = _components(
        posture,
        enabled=("cbf",),
        required=frozenset({"cbf", "causal"}),
        disabled=(DisabledTier("causal", "no telemetry provider configured"),),
    )
    with pytest.raises(PostureViolation) as exc:
        assert_production_posture(posture, components=components)
    message = str(exc.value)
    assert "required_tiers" in message
    assert "'causal' is disabled (no telemetry provider configured)" in message


def test_enforcing_posture_refuses_a_required_tier_that_is_not_assembled() -> None:
    components = _components(
        _PROD, enabled=("cbf",), required=frozenset({"cbf", "causal"})
    )
    # Bypass the assembly-time check to model a hand-composed governor.
    components = dataclasses.replace(
        components,
        contributions=(
            dataclasses.replace(
                components.contributions[0],
                tiers=(_Tier("cbf"),),
            ),
        ),
    )
    with pytest.raises(PostureViolation, match="'causal' is not assembled"):
        assert_production_posture(_PROD, components=components)


def test_enforcing_posture_starts_with_every_required_tier_enabled() -> None:
    components = _components(
        _PROD, enabled=("cbf", "causal"), required=frozenset({"cbf", "causal"})
    )
    assert_production_posture(_PROD, components=components)


def test_disabling_a_tier_that_is_not_required_does_not_refuse() -> None:
    components = _components(
        _PROD,
        enabled=("cbf",),
        required=frozenset({"cbf"}),
        disabled=(DisabledTier("optional", "no data source"),),
    )
    assert_production_posture(_PROD, components=components)


def test_permissive_posture_logs_critical_and_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    components = _components(
        _DEV,
        enabled=(),
        required=frozenset({"causal"}),
        disabled=(DisabledTier("causal", "no telemetry provider configured"),),
    )
    with caplog.at_level(logging.CRITICAL, logger=posture_mod.__name__):
        assert_production_posture(_DEV, components=components)
    events = [json.loads(r.getMessage()) for r in caplog.records]
    assert any(
        e["check"] == "required_tiers" and "'causal' is disabled" in e["detail"]
        for e in events
    )


def test_a_tier_cannot_be_both_enabled_and_disabled() -> None:
    base = make_governor(posture=_PROD, domain_tiers=(_Tier("causal"),)).components
    with pytest.raises(ValueError, match="both enabled and disabled"):
        dataclasses.replace(base, disabled_tiers=(DisabledTier("causal", "x"),))


def test_assembly_rejects_a_required_tier_the_domain_does_not_contribute() -> None:
    contribution = PluginContribution(
        domain="d", tiers=(_Tier("cbf"),), required_tiers=frozenset({"causal"})
    )
    with pytest.raises(GovernorAssemblyError, match="does not contribute"):
        _reject_unknown_required_tiers((contribution,))


def test_finance_requires_every_tier_it_contributes() -> None:
    from src.cage_finance.plugin import FINANCE_REQUIRED_TIERS

    assert FINANCE_REQUIRED_TIERS == frozenset(
        {"trade_confidence", "bounding", "cbf", "fiscal", "consensus", "causal"}
    )
