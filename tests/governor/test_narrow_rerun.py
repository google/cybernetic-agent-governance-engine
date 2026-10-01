"""NARROW from ``validate_action`` is an unsealed, re-verified candidate.

proof/model.py defines NARROW as: (a) every violation is NARROWABLE, (b) a
narrower returned a proposal, and (c) every stage passes on the clamped
params; otherwise DENY. ``validate_action`` runs the non-committing DRY_RUN
profile, so it checks (c) by *previewing* the clamped params: nothing is
reserved, nothing is committed and no seal is minted. Executing the proposal
is a separate committing run over it: ``govern()`` re-runs the sealed FULL
pipeline on the clamped params and stores a single-use NARROW receipt (S10,
the last test below).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest

from proof.model import enumerate_reachable, gated_transitions
from src.gateway.governance.classification_engine import (
    ClassificationContext,
    ClassificationEngine,
    ClassificationResult,
)
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.env_posture import is_cage_narrow_enabled
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor import verdicts as verdicts_module
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.pipeline import StageContext
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.verdicts import handle_narrow
from src.gateway.governance.narrow_receipt import narrow_receipt_key
from src.gateway.governance.narrower import NarrowerRegistry, NarrowingResult
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

ACTION = "execute_trade"
REQUESTED = 5000.0


# ── Doubles ─────────────────────────────────────────────────────────────────


class _Budget(MutatingTier):
    """Phase-2 tier double limiting ``params["amount"]`` to ``limit``.

    ``evaluate()`` (the DRY_RUN preview) and ``commit()`` refuse above the
    limit with a violation of ``kind``; every hook call is logged.
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
    order = property(lambda self: self._order)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    def _refusal(self, amount: float) -> list[Violation]:
        if self.limit is not None and amount > self.limit:
            return [
                Violation(
                    tier=self._name,
                    code="LIMIT_EXCEEDED",
                    message=f"{amount:g} > {self.limit:g}",
                    kind=self.kind,
                )
            ]
        return []

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        amount = float(params["amount"])
        refused = self._refusal(amount)
        self.log.append(f"{'preview-reject' if refused else 'preview'}:{self._name}:{amount:g}")
        if self.mutate_params:
            params["amount"] = 999_999.0  # a misbehaving tier must not change the answer
        return refused

    async def commit(self, action: str, params: dict[str, Any]):
        amount = float(params["amount"])
        refused = self._refusal(amount)
        if refused:
            self.log.append(f"reject:{self._name}:{amount:g}")
            return refused, None
        self.log.append(f"commit:{self._name}:{amount:g}")
        return [], CommitReceipt(tier=self._name, magnitude=amount)

    async def confirm(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        self.log.append(f"confirm:{self._name}:{receipt.magnitude:g}")

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        self.log.append(f"rollback:{self._name}:{receipt.magnitude:g}")


class _Flag(ReadOnlyTier):
    """Phase-1 (read-only) tier double emitting fixed violations."""

    def __init__(self, name: str, violations: list[Violation]) -> None:
        self._name, self._violations = name, violations

    tier_name = property(lambda self: self._name)
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


# ── Re-verification passes → unsealed NARROW candidate ────────────────────


@pytest.mark.asyncio
async def test_rerun_passes_offers_clamped_params_without_committing(seal: AsyncMock) -> None:
    log: list[str] = []
    policy = _Policy()
    clamp = _Clamp(cap=1000.0)
    gov = _governor([policy, *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])], clamp)

    result = await gov.validate_action(ACTION, _params())

    assert result["verdict"] == GovernanceDecision.NARROW
    assert "seal" not in result
    assert result["narrowed_params"] == {"amount": 1000.0, "agent_id": "agent-1"}
    assert result["original_params"] == _params()
    seal.assert_not_awaited()
    # Both runs previewed; nothing was reserved.
    assert log == ["preview-reject:fiscal:5000", "preview:fiscal:1000"]
    assert policy.seen == [REQUESTED, 1000.0]  # OPA re-checked the clamped params
    assert clamp.calls == 1


@pytest.mark.asyncio
async def test_offered_params_are_the_verified_snapshot_even_if_a_tier_mutates_its_input(
    seal: AsyncMock,
) -> None:
    log: list[str] = []
    tier = _Budget("fiscal", 4, log, limit=1000.0, mutate_params=True)
    gov = _governor([_Policy(), *order_stages([tier])], _Clamp(cap=1000.0))

    result = await gov.validate_action(ACTION, _params())

    assert result["narrowed_params"] == {"amount": 1000.0, "agent_id": "agent-1"}
    assert result["classification_meta"]["narrowed_params"] is result["narrowed_params"]


# ── Re-verification fails → DENY ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_opa_denies_clamped_params_denies(seal: AsyncMock, refusals: AsyncMock) -> None:
    log: list[str] = []
    policy = _Policy(deny_amounts=frozenset({1000.0}))
    gov = _governor([policy, *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])], _Clamp(cap=1000.0))

    with pytest.raises(GovernanceError, match=r"\[OPA_DENY\]") as info:
        await gov.validate_action(ACTION, _params())

    seal.assert_not_awaited()
    assert info.value.payload["classification_reason"] == "narrow_reverification_failed"
    assert log == ["preview-reject:fiscal:5000"]  # OPA stopped the re-run before phase 2
    refusals.assert_awaited_once()  # the refusal is primary evidence


@pytest.mark.asyncio
async def test_proposal_that_still_violates_denies_and_narrows_once(seal: AsyncMock) -> None:
    log: list[str] = []
    clamp = _Clamp(cap=2000.0)  # the clamp is not tight enough for the 1000 limit
    tiers = [_Budget("cbf", 1, log), _Budget("fiscal", 4, log, limit=1000.0)]
    gov = _governor([_Policy(), *order_stages(tiers)], clamp)

    with pytest.raises(GovernanceError, match=r"\[LIMIT_EXCEEDED\]"):
        await gov.validate_action(ACTION, _params())

    seal.assert_not_awaited()
    assert clamp.calls == 1  # never narrowed twice, even though the re-run is NARROWABLE again
    assert not [entry for entry in log if entry.startswith(("commit", "rollback"))]


@pytest.mark.asyncio
async def test_validate_action_never_commits_or_seals(seal: AsyncMock) -> None:
    log: list[str] = []
    tiers = [_Budget("cbf", 1, log), _Budget("fiscal", 4, log, limit=1000.0)]
    gov = _governor([_Policy(), *order_stages(tiers)], _Clamp(cap=1000.0))

    await gov.validate_action(ACTION, {"amount": 10.0, "agent_id": "agent-1"})  # ALLOW
    await gov.validate_action(ACTION, _params())  # NARROW

    seal.assert_not_awaited()
    assert all(entry.startswith("preview") for entry in log), log


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
    assert log == ["preview-reject:fiscal:5000"]


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
    assert log == ["preview-reject:fiscal:5000"]


def test_handle_narrow_result_carries_no_seal() -> None:
    result = handle_narrow(
        ACTION, _params(), {"amount": 1000.0},
        violations=[], classification_meta={},
    )
    assert result["verdict"] == GovernanceDecision.NARROW
    assert "seal" not in result


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
    else:
        with pytest.raises(GovernanceError):
            await gov.validate_action(ACTION, _params())
    # The model's NARROW seal belongs to the committing run (S10), never to validate.
    seal.assert_not_awaited()


@pytest.fixture
def receipt_store(monkeypatch: pytest.MonkeyPatch) -> fakeredis.aioredis.FakeRedis:
    """The Redis the NARROW receipt is written to; without one the seal is refused."""
    store = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("src.gateway.infrastructure.redis_client.redis_client", store)
    return store


@pytest.mark.asyncio
async def test_s10_committing_run_seals_the_narrowed_params(
    seal: AsyncMock, receipt_store: fakeredis.aioredis.FakeRedis
) -> None:
    log: list[str] = []
    gov = _governor(
        [_Policy(), *order_stages([_Budget("fiscal", 4, log, limit=1000.0)])], _Clamp(cap=1000.0)
    )

    sealed = await gov.govern(ACTION, _params())

    assert sealed == "sealed-narrow"
    receipt = await receipt_store.get(narrow_receipt_key(sealed))
    assert receipt is not None, "a sealed NARROW must leave its single-use receipt"
    assert '"amount": 1000.0' in receipt
    seal.assert_awaited_once_with(
        ACTION, {"amount": 1000.0, "agent_id": "agent-1"}, path="govern_narrow"
    )
    assert log[-1] == "commit:fiscal:1000"
