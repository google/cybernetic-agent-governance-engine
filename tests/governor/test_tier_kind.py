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

"""ADR-009: a tier is a ReadOnlyTier or a MutatingTier, by subclassing.

``check_tier_kind`` runs when the governor wraps a tier
(``DomainTierStage.__init__``). Every refusal path is exercised here, both
directly and through the stage, so a tier of the wrong kind can never reach
the pipeline.
"""

from typing import Any

import pytest

from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTier,
    MutatingTier,
    ReadOnlyTier,
    Violation,
)
from src.gateway.governance.governor.stages.domain_tiers import (
    DomainTierStage,
    check_tier_kind,
)
from src.gateway.governance.jurisdiction.contribution import JurisdictionContribution

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _Behaviour:
    """Identity and evaluation shared by every double below."""

    tier_name = "t"
    order = 1

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []


class _Hooks:
    """The three mutating hooks, as no-ops."""

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        return [], None

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        return None

    async def confirm(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        return None


class _ReadOnly(_Behaviour, ReadOnlyTier):
    pass


class _Mutating(_Behaviour, _Hooks, MutatingTier):
    pass


def _refused(tier: object, exc: type[Exception], match: str) -> None:
    """``tier`` is refused by check_tier_kind and by the stage that wraps it."""
    with pytest.raises(exc, match=match):
        check_tier_kind(tier)
    with pytest.raises(exc, match=match):
        DomainTierStage(tier)  # type: ignore[arg-type]


# ── Positive cases ──────────────────────────────────────────────────────────


def test_read_only_tier_is_not_mutating() -> None:
    assert check_tier_kind(_ReadOnly()) is False
    stage = DomainTierStage(_ReadOnly())
    assert stage.mutating is False
    assert stage.tier.phase == 1


def test_mutating_tier_is_mutating() -> None:
    assert check_tier_kind(_Mutating()) is True
    stage = DomainTierStage(_Mutating())
    assert stage.mutating is True
    assert stage.tier.phase == 2


# ── Refusals ────────────────────────────────────────────────────────────────


def test_duck_typed_tier_is_refused() -> None:
    """Structural conformance is not enough: the kind is nominal."""

    class _Duck(_Behaviour, _Hooks):
        phase = 2

    _refused(_Duck(), TypeError, "is not a governance tier")


def test_non_tier_object_is_refused() -> None:
    _refused(object(), TypeError, "is not a governance tier")


@pytest.mark.parametrize("hook", ["commit", "rollback", "confirm"])
def test_read_only_tier_defining_a_mutating_hook_is_refused(hook: str) -> None:
    """A read-only tier with a commit meant to reserve; running it read-only would skip it."""
    stray = type(f"_ReadOnlyWith_{hook}", (_ReadOnly,), {hook: getattr(_Hooks, hook)})
    _refused(stray(), TypeError, rf"defines \['{hook}'\]")


@pytest.mark.parametrize(
    ("base", "wrong_phase"),
    [(_ReadOnly, 2), (_Mutating, 1)],
    ids=["read-only-claims-2", "mutating-claims-1"],
)
def test_phase_override_contradicting_kind_is_refused(base: type, wrong_phase: int) -> None:
    liar = type("_Liar", (base,), {"phase": property(lambda self: wrong_phase)})
    _refused(liar(), ValueError, f"reports phase {wrong_phase}")


def test_mutating_tier_without_confirm_cannot_be_instantiated() -> None:
    class _NoConfirm(_Behaviour, MutatingTier):
        async def commit(self, action, params):
            return [], None

        async def rollback(self, action, params, receipt):
            return None

    with pytest.raises(TypeError, match="confirm"):
        _NoConfirm()  # type: ignore[abstract]


def test_tier_of_both_kinds_is_refused() -> None:
    class _Both(_Behaviour, _Hooks, ReadOnlyTier, MutatingTier):
        pass

    _refused(_Both(), TypeError, "exactly one of ReadOnlyTier and MutatingTier")


def test_tier_of_neither_kind_is_refused() -> None:
    """Subclassing the GovernanceTier root directly picks no kind."""

    class _Neither(_Behaviour, GovernanceTier):
        phase = property(lambda self: 1)

    _refused(_Neither(), TypeError, "exactly one of ReadOnlyTier and MutatingTier")


# ── Jurisdiction tiers must be read-only ────────────────────────────────────


def test_jurisdiction_contribution_refuses_mutating_tier() -> None:
    with pytest.raises(TypeError, match="jurisdiction tiers must be read-only"):
        JurisdictionContribution(region="EU_ECB", tiers=(_Mutating(),))


def test_jurisdiction_contribution_accepts_read_only_tier() -> None:
    contribution = JurisdictionContribution(region="EU_ECB", tiers=[_ReadOnly()])
    assert isinstance(contribution.tiers, tuple)
    assert [check_tier_kind(t) for t in contribution.tiers] == [False]
