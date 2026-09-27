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

"""P3c: NARROW re-runs the FULL profile on the clamped params before sealing.

Before P3c, ``handle_narrow`` sealed the narrower's proposal without
re-running any check.  The NARROWABLE stage (e.g. fiscal) had already been
rolled back, so the NARROW seal authorised an action with no reservation and
no policy check on the clamped params.  proof/model.py defines NARROW as:
(a) every violation is NARROWABLE, (b) a narrower returned a proposal, and
(c) the FULL profile passes on the clamped params.  Otherwise DENY.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from proof.model import enumerate_reachable, gated_transitions
from src.gateway.governance.classification_engine import (
    ClassificationContext,
    ClassificationEngine,
    ClassificationResult,
)
from src.gateway.governance.contracts import CommitReceipt, Violation, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.env_posture import is_cage_narrow_enabled
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor import verdicts as verdicts_module
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.pipeline import StageContext
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.verdicts import handle_narrow
from src.gateway.governance.narrower import NarrowerRegistry, NarrowingResult
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

ACTION = "execute_trade"
REQUESTED = 5000.0


# ── Doubles ─────────────────────────────────────────────────────────────────


class _Budget:
    """Phase-2 tier double: reserves ``params["amount"]`` up to ``limit``.

    Above the limit it refuses with a violation of ``kind`` and mutates nothing.
    """

    def __init__(
        self,
        name: str,
        order: int,
        log: list[str],
        *,
        limit: float | None = None,
        kind: ViolationKind = ViolationKind.NARROWABLE,
        mutate_params: bool = False,
    ) -> None:
        self._name, self._order, self.log = name, order, log
        self.limit, self.kind, self.mutate_params = limit, kind, mutate_params

    tier_name = property(lambda self: self._name)
    phase = property(lambda self: 2)
    order = property(lambda self: self._order)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(self, action: str, params: dict[str, Any]):
        amount = float(params["amount"])
        if self.limit is not None and amount > self.limit:
            self.log.append(f"reject:{self._name}:{amount:g}")
            violation = Violation(
                tier=self._name, code="LIMIT_EXCEEDED", message=f"{amount:g} > {self.limit:g}", kind=self.kind
            )
            return [violation], None
        self.log.append(f"commit:{self._name}:{amount:g}")
        if self.mutate_params:
            params["amount"] = 999_999.0  # a misbehaving tier must not change what gets sealed
        return [], CommitReceipt(tier=self._name, magnitude=amount)

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        self.log.append(f"rollback:{self._name}:{receipt.magnitude:g}")


class _Flag:
    """Phase-1 (read-only) tier double emitting fixed violations."""

    def __init__(self, name: str, violations: list[Violation]) -> None:
        self._name, self._violations = name, violations

    tier_name = property(lambda self: self._name)
    phase = property(lambda self: 1)
    order = property(lambda self: 0)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return list(self._violations)


class _Policy:
    """Read-only "opa" stage double: HARD-denies the listed amounts."""

    name = "opa"
    mutating = False

    def __init__(self, deny_amounts: frozenset[float] = frozenset()) -> None:
        self.deny_amounts = deny_amounts
        self.seen: list[float] = []

    async def run(self, ctx: StageContext) -> list[Violation]:
        amount = float(ctx.params.get("amount", 0.0))
        self.seen.append(amount)
        if amount in self.deny_amounts:
            return [Violation(tier="opa", code="OPA_DENY", message="policy denies", kind=ViolationKind.HARD)]
        return []


class _Clamp:
    """Narrower double: clamps ``amount`` to ``cap`` and counts calls."""

    def __init__(self, cap: float) -> None:
        self.cap = cap
        self.calls = 0

    def can_narrow(self, violation: Violation, action: str, params: dict[str, Any]) -> bool:
        return violation.kind == ViolationKind.NARROWABLE

    def narrow(self, violation: Violation, action: str, params: dict[str, Any]) -> NarrowingResult:
        self.calls += 1
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={**params, "amount": min(float(params["amount"]), self.cap)},
            constraints_applied=[f"amount clamped to {self.cap:g}"],
            narrowing_reason="amount exceeds limit",
        )


def _governor(
    stages: list[Any], narrower: _Clamp | None = None, *, narrow_enabled: bool = True
) -> SymbolicGovernor:
    engine = ClassificationEngine(
        NarrowerRegistry([narrower] if narrower else []), narrow_enabled=narrow_enabled
    )
    return make_governor(core_stages=stages, classifier=engine)


def _params() -> dict[str, Any]:
    return {"amount": REQUESTED, "agent_id": "agent-1"}


@pytest.fixture
def seal(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mock = AsyncMock(return_value="sealed-narrow")
    monkeypatch.setattr(sealing_module, "issue_seal", mock)
    return mock


@pytest.fixture(autouse=True)
def refusals(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mock = AsyncMock()
    monkeypatch.setattr(verdicts_module, "publish_refusal", mock)
    return mock


# ── Re-run passes → NARROW over exactly the re-verified params ─────────────


@pytest.mark.asyncio
async def test_rerun_passes_seals_clamped_params_with_fresh_reservation(seal: AsyncMock) -> None:
    log: list[str] = []
    policy = _Policy()
    clamp = _Clamp(cap=1000.0)
    gov = _governor([policy, *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])], clamp)

    result = await gov.validate_action(ACTION, _params())

    assert result["verdict"] == GovernanceDecision.NARROW
    assert result["seal"] == "sealed-narrow"
    assert result["narrowed_params"] == {"amount": 1000.0, "agent_id": "agent-1"}
    assert result["original_params"] == _params()
    seal.assert_awaited_once_with(ACTION, result["narrowed_params"], path="narrow")
    # The fiscal reservation behind the seal is for the clamped amount, and it stays.
    assert log == ["reject:fiscal:5000", "commit:fiscal:1000"]
    assert policy.seen == [REQUESTED, 1000.0]  # OPA re-checked the clamped params
    assert clamp.calls == 1


@pytest.mark.asyncio
async def test_sealed_params_are_the_verified_snapshot_even_if_a_tier_mutates_its_input(
    seal: AsyncMock,
) -> None:
    log: list[str] = []
    tier = _Budget("fiscal", 4, log, limit=1000.0, mutate_params=True)
    gov = _governor([_Policy(), *order_stages([tier])], _Clamp(cap=1000.0))

    result = await gov.validate_action(ACTION, _params())

    sealed_params = seal.await_args.args[1]
    assert sealed_params == {"amount": 1000.0, "agent_id": "agent-1"}
    assert result["narrowed_params"] is sealed_params
    assert result["classification_meta"]["narrowed_params"] is sealed_params


# ── Re-run fails → DENY, no seal, re-run commits rolled back ───────────────


@pytest.mark.asyncio
async def test_opa_denies_clamped_params_denies_without_seal(seal: AsyncMock, refusals: AsyncMock) -> None:
    log: list[str] = []
    policy = _Policy(deny_amounts=frozenset({1000.0}))
    gov = _governor([policy, *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])], _Clamp(cap=1000.0))

    with pytest.raises(GovernanceError, match=r"\[OPA_DENY\]") as info:
        await gov.validate_action(ACTION, _params())

    seal.assert_not_awaited()
    assert info.value.payload["classification_reason"] == "narrow_reverification_failed"
    assert log == ["reject:fiscal:5000"]  # OPA stopped the re-run before any commit
    refusals.assert_awaited_once()  # the refusal is primary evidence


@pytest.mark.asyncio
async def test_proposal_that_still_violates_denies_rolls_back_and_narrows_once(seal: AsyncMock) -> None:
    log: list[str] = []
    clamp = _Clamp(cap=2000.0)  # the clamp is not tight enough for the 1000 limit
    tiers = [_Budget("cbf", 1, log), _Budget("fiscal", 4, log, limit=1000.0)]
    gov = _governor([_Policy(), *order_stages(tiers)], clamp)

    with pytest.raises(GovernanceError, match=r"\[LIMIT_EXCEEDED\]"):
        await gov.validate_action(ACTION, _params())

    seal.assert_not_awaited()
    assert clamp.calls == 1  # never narrowed twice, even though the re-run is NARROWABLE again
    assert log == [
        "commit:cbf:5000", "reject:fiscal:5000", "rollback:cbf:5000",  # original run
        "commit:cbf:2000", "reject:fiscal:2000", "rollback:cbf:2000",  # re-run
    ]


@pytest.mark.asyncio
async def test_seal_failure_on_narrow_path_rolls_back_rerun_commits(seal: AsyncMock) -> None:
    log: list[str] = []
    seal.side_effect = RuntimeError("KMS unavailable")
    tiers = [_Budget("cbf", 1, log), _Budget("fiscal", 4, log, limit=1000.0)]
    gov = _governor([_Policy(), *order_stages(tiers)], _Clamp(cap=1000.0))

    with pytest.raises(RuntimeError, match="KMS unavailable"):
        await gov.validate_action(ACTION, _params())

    seal.assert_awaited_once()
    assert log[-4:] == ["commit:cbf:1000", "commit:fiscal:1000", "rollback:fiscal:1000", "rollback:cbf:1000"]


# ── NARROW preconditions (a) and (b) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_narrowable_plus_deferrable_is_not_narrow(seal: AsyncMock) -> None:
    clamp = _Clamp(cap=1000.0)
    flag = _Flag("screening", [
        Violation(tier="screening", code="OVER_SOFT_LIMIT", message="clampable", kind=ViolationKind.NARROWABLE),
        Violation(tier="screening", code="LOW_EVIDENCE", message="needs review", kind=ViolationKind.DEFERRABLE),
    ])
    gov = _governor([_Policy(), *order_stages([flag])], clamp)

    params = {**_params(), "confidence": 0.99}  # high confidence: DEFER does not apply either
    with pytest.raises(GovernanceError):
        await gov.validate_action(ACTION, params)

    assert clamp.calls == 0
    seal.assert_not_awaited()


def test_classifier_requires_every_violation_narrowable() -> None:
    clamp = _Clamp(cap=1000.0)
    engine = ClassificationEngine(NarrowerRegistry([clamp]), narrow_enabled=True)
    narrowable = Violation(tier="fiscal", code="LIMIT", message="m", kind=ViolationKind.NARROWABLE)
    deferrable = Violation(tier="x", code="D", message="m", kind=ViolationKind.DEFERRABLE)

    def classify(violations: list[Violation], confidence: float) -> ClassificationResult:
        ctx = ClassificationContext(violations, confidence, None, False, _params())
        return engine.classify(ctx, ACTION)

    assert classify([narrowable, narrowable], 0.99).decision == GovernanceDecision.NARROW
    assert classify([narrowable, deferrable], 0.99).decision == GovernanceDecision.DENY
    assert classify([deferrable, narrowable], 0.10).decision == GovernanceDecision.DEFER
    assert clamp.calls == 1  # only the all-NARROWABLE case consulted the narrower


@pytest.mark.asyncio
async def test_narrow_enabled_flag_unset_never_narrows(seal: AsyncMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CAGE_NARROW_ENABLED", raising=False)
    assert is_cage_narrow_enabled() is False  # documented default: NARROW is opt-in

    log: list[str] = []
    clamp = _Clamp(cap=1000.0)
    gov = _governor(
        [_Policy(), *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])],
        clamp,
        narrow_enabled=is_cage_narrow_enabled(),
    )

    with pytest.raises(GovernanceError, match=r"\[LIMIT_EXCEEDED\]"):
        await gov.validate_action(ACTION, _params())

    assert clamp.calls == 0
    seal.assert_not_awaited()
    assert log == ["reject:fiscal:5000"]


# ── Fail-closed guards ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_narrow_classification_without_proposal_denies(seal: AsyncMock) -> None:
    log: list[str] = []
    classifier = MagicMock()
    classifier.classify.return_value = ClassificationResult(
        decision=GovernanceDecision.NARROW, metadata={"classification_reason": "narrowable_resolved"}
    )
    gov = make_governor(
        core_stages=[_Policy(), *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])],
        classifier=classifier,
    )

    with pytest.raises(GovernanceError, match=r"\[LIMIT_EXCEEDED\]"):
        await gov.validate_action(ACTION, _params())

    seal.assert_not_awaited()
    assert log == ["reject:fiscal:5000"]


@pytest.mark.parametrize("bad_seal", ["", None])
def test_handle_narrow_refuses_without_a_seal(bad_seal: Any) -> None:
    with pytest.raises(GovernanceError, match="has no seal"):
        handle_narrow(
            ACTION, _params(), {"amount": 1000.0},
            seal=bad_seal, violations=[], classification_meta={},
        )


# ── Parity with proof/model.py's NARROW definition ─────────────────────────


def _model_narrow_outcomes() -> set[tuple[bool, bool, str]]:
    """(narrower_present, clamped_params_valid, phase) for every refused-tier terminal state."""
    return {
        (s.narrower_present, s.clamped_params_valid, s.phase)
        for s in enumerate_reachable(gated_transitions)
        if s.phase in ("NARROW", "DENIED") and s.any_tier_failed()
    }


def test_model_narrow_definition_is_what_production_implements() -> None:
    outcomes = _model_narrow_outcomes()
    assert outcomes == {
        (False, False, "DENIED"),
        (True, False, "DENIED"),
        (True, True, "NARROW"),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("narrower_present,clamped_params_valid,phase", sorted(_model_narrow_outcomes()))
async def test_production_matches_model_narrow_outcome(
    narrower_present: bool, clamped_params_valid: bool, phase: str, seal: AsyncMock
) -> None:
    log: list[str] = []
    # A 1000 cap satisfies the 1000 limit on re-run; a 2000 cap does not.
    clamp = _Clamp(cap=1000.0 if clamped_params_valid else 2000.0) if narrower_present else None
    gov = _governor([_Policy(), *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])], clamp)

    if phase == "NARROW":
        result = await gov.validate_action(ACTION, _params())
        assert result["verdict"] == GovernanceDecision.NARROW
        seal.assert_awaited_once()  # model: NARROW has seal_present=True
    else:
        with pytest.raises(GovernanceError):
            await gov.validate_action(ACTION, _params())
        seal.assert_not_awaited()
