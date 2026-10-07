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

"""The kernel warrant reliance gate (VEIP Phase 2, PR 3).

Invariants under test:

* ``WARRANT_FAILURE_DEFERS`` — every way a warranted norm can be ineligible
  (missing, revoked, suspended, expired, out of scope, version mismatch,
  tampered digest, wrong norm, source error, source timeout) yields exactly one
  ``RELIANCE_INELIGIBLE`` finding, and the governor answers DEFER with
  ``WARRANT_INELIGIBLE`` — never ALLOW, never a fabricated DENY.
* ``HARD_STILL_WINS`` — the gate never masks a HARD finding.
* ``NO_SEAL_ON_WARRANT_FAILURE`` — the committing path mints no seal.
* ``WARRANTED_ASSEMBLY_FAILS_CLOSED`` — a warranted norm without a source,
  with DEFER disabled, or with no tier claiming its actions refuses to assemble.
* ``WARRANTED_VALUE_PINNED`` — the EU_ECB (norm_id, value) pair is pinned to the
  governing_version its warrant was issued for.
"""

from __future__ import annotations

import pathlib
from typing import Any
from unittest.mock import patch

import pytest

from proof import model as proof
from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_finance.thresholds import FinanceThresholds
from src.cage_finance.tiers.trade_confidence_tier import (
    TRADE_CONFIDENCE_NORM_ID,
    TradeConfidenceTier,
)
from src.gateway.governance.classification_engine import (
    REASON_RELIANCE_INELIGIBLE,
    ClassificationContext,
)
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    NormBinding,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import DeferReason
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import (
    DecisionFlags,
    GovernorAssemblyError,
    assemble_governor,
    kernel_stages,
    warranted_assembly_admissible,
)
from src.gateway.governance.governor.errors import GovernanceDeferred, GovernanceError
from src.gateway.governance.governor.pipeline import Profile, StageContext
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.jurisdiction import eu_ai_act, resolve_jurisdiction
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.warrant import RelianceStatus, WarrantCache
from tests.fixtures.approval import SpendCounter, granted_approval
from tests.fixtures.governor import (
    WARRANT_TEST_GOVERNING_VERSION,
    WARRANT_TEST_NOW,
    StaticWarrantSource,
    allow_opa,
    clean_stpa,
    default_classifier,
    issue_test_warrant,
    make_governor,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = pathlib.Path(__file__).resolve().parents[2]

_BINDING = NormBinding(
    norm_id=TRADE_CONFIDENCE_NORM_ID,
    value=0.97,
    requires_warrant=True,
    actions=frozenset({"execute_trade", "execute_trade_bounded"}),
    governing_version=WARRANT_TEST_GOVERNING_VERSION,
)


def _stage(source: Any, *, jurisdiction: str = "EU_ECB", **cache: Any) -> WarrantStage:
    """The stage over a fresh cache; ``cache`` kwargs configure the cache."""
    return WarrantStage(
        [_BINDING],
        WarrantCache(source, **cache),
        jurisdiction=jurisdiction,
        clock=lambda: WARRANT_TEST_NOW,
    )


def _source_with(**overrides: Any) -> StaticWarrantSource:
    warrant = issue_test_warrant(**overrides)
    return StaticWarrantSource({TRADE_CONFIDENCE_NORM_ID: warrant})


def _tampered_source() -> StaticWarrantSource:
    import dataclasses

    intact = issue_test_warrant()
    tampered = dataclasses.replace(intact, authority_basis="Forged instrument")
    return StaticWarrantSource({TRADE_CONFIDENCE_NORM_ID: tampered})


async def _run(stage: WarrantStage, action: str = "execute_trade") -> list[Violation]:
    output = await stage.run(
        StageContext(action=action, params={"confidence": 0.99}, profile=Profile.FULL)
    )
    return list(output.violations)


# ── NormBinding contract ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs",
    [
        {"norm_id": ""},
        {"value": True},
        {"value": float("nan")},
        {"requires_warrant": 1},
        {"actions": frozenset()},
        {"actions": "execute_trade"},
        {"governing_version": ""},
        {"governing_version": None},  # requires_warrant without a version
    ],
)
def test_norm_binding_refuses_malformed_input(kwargs: dict[str, Any]) -> None:
    fields: dict[str, Any] = {
        "norm_id": "n",
        "value": 0.5,
        "requires_warrant": True,
        "actions": frozenset({"a"}),
        "governing_version": "v1",
        **kwargs,
    }
    with pytest.raises((ValueError, TypeError)):
        NormBinding(**fields)


def test_unwarranted_binding_needs_no_version() -> None:
    binding = NormBinding(
        norm_id="n", value=0.5, requires_warrant=False, actions=frozenset({"a"})
    )
    assert binding.governs("a")
    assert not binding.governs("b")


# ── Stage failure matrix ─────────────────────────────────────────────────────


async def test_eligible_warrant_yields_no_finding() -> None:
    source = StaticWarrantSource.eligible()
    assert await _run(_stage(source)) == []
    assert source.calls == [TRADE_CONFIDENCE_NORM_ID]


async def test_ungoverned_action_is_not_fetched() -> None:
    source = StaticWarrantSource.eligible()
    assert await _run(_stage(source), action="get_market_data") == []
    assert source.calls == []


@pytest.mark.parametrize(
    ("source_factory", "status"),
    [
        (lambda: StaticWarrantSource(), RelianceStatus.INELIGIBLE_MISSING),
        (
            lambda: _source_with(status="REVOKED", revocation_ref="REV-1"),
            RelianceStatus.INELIGIBLE_REVOKED,
        ),
        (
            lambda: _source_with(status="SUSPENDED"),
            RelianceStatus.INELIGIBLE_UNRESOLVED,
        ),
        (
            lambda: _source_with(valid_until="2026-08-21T00:00:00Z"),
            RelianceStatus.INELIGIBLE_EXPIRED,
        ),
        (
            lambda: _source_with(
                scope={
                    "actions": ["execute_trade"],
                    "actors": ["*"],
                    "systems": ["*"],
                    "jurisdictions": ["US_FED"],
                }
            ),
            RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
        ),
        (
            lambda: _source_with(governing_version="cage-policy-2.0.0"),
            RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
        ),
        (_tampered_source, RelianceStatus.INELIGIBLE_UNRESOLVED),
        (
            lambda: StaticWarrantSource(
                {TRADE_CONFIDENCE_NORM_ID: issue_test_warrant(norm_id="other.norm")}
            ),
            RelianceStatus.INELIGIBLE_UNRESOLVED,
        ),
        (
            lambda: StaticWarrantSource(error=ConnectionError("source down")),
            RelianceStatus.INELIGIBLE_UNRESOLVED,
        ),
    ],
    ids=[
        "missing",
        "revoked",
        "suspended",
        "expired",
        "out_of_scope",
        "version_mismatch",
        "tampered_digest",
        "wrong_norm",
        "source_error",
    ],
)
async def test_every_ineligible_standing_is_one_reliance_finding(
    source_factory: Any, status: RelianceStatus
) -> None:
    (violation,) = await _run(_stage(source_factory()))
    assert violation.kind is ViolationKind.RELIANCE_INELIGIBLE
    assert violation.tier == "warrant"
    assert violation.code == f"RELIANCE_{status.value}"
    assert TRADE_CONFIDENCE_NORM_ID in violation.message


async def test_source_timeout_is_ineligible() -> None:
    stage = _stage(StaticWarrantSource(hang=True), fetch_timeout_seconds=0.01)
    (violation,) = await _run(stage)
    assert violation.kind is ViolationKind.RELIANCE_INELIGIBLE
    assert violation.code == f"RELIANCE_{RelianceStatus.INELIGIBLE_UNRESOLVED.value}"
    assert "did not answer within 0.01s" in violation.message


async def test_out_of_jurisdiction_deployment_is_out_of_scope() -> None:
    (violation,) = await _run(
        _stage(StaticWarrantSource.eligible(), jurisdiction="APAC_MAS")
    )
    assert violation.code == f"RELIANCE_{RelianceStatus.INELIGIBLE_OUT_OF_SCOPE.value}"


def test_stage_refuses_unwarranted_bindings_and_bad_sources() -> None:
    plain = NormBinding(
        norm_id="n", value=0.5, requires_warrant=False, actions=frozenset({"a"})
    )
    cache = WarrantCache(StaticWarrantSource())
    with pytest.raises(ValueError):
        WarrantStage([plain], cache, jurisdiction="EU_ECB")
    with pytest.raises(TypeError):
        WarrantStage([_BINDING], object(), jurisdiction="EU_ECB")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="WarrantCache"):
        # A bare source bypasses the freshness window: refused.
        WarrantStage([_BINDING], StaticWarrantSource(), jurisdiction="EU_ECB")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        WarrantStage([_BINDING], cache, jurisdiction="")
    with pytest.raises(TypeError):
        WarrantCache(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        WarrantCache(StaticWarrantSource(), fetch_timeout_seconds=0)


# ── Classifier ───────────────────────────────────────────────────────────────


def _violation(kind: ViolationKind, tier: str = "t") -> Violation:
    return Violation(tier=tier, code=f"{tier.upper()}_X", message="m", kind=kind)


def _classify(
    violations: list[Violation], *, defer: bool = True, confidence: float = 0.99
) -> Any:
    return default_classifier(defer_enabled=defer).classify(
        ClassificationContext(
            violations=violations,
            confidence=confidence,
            opa_decision="ALLOW",
            policy_ambiguous=False,
            params={"confidence": confidence},
        ),
        "execute_trade",
    )


@pytest.mark.parametrize(
    "others",
    [
        [],
        [ViolationKind.HITL],
        [ViolationKind.NARROWABLE],
        [ViolationKind.DEFERRABLE],
        [ViolationKind.HITL, ViolationKind.NARROWABLE, ViolationKind.DEFERRABLE],
    ],
)
def test_reliance_ineligible_defers_above_every_soft_kind(
    others: list[ViolationKind],
) -> None:
    violations = [_violation(ViolationKind.RELIANCE_INELIGIBLE, "warrant")]
    violations += [_violation(k) for k in others]
    result = _classify(violations)
    assert result.decision == GovernanceDecision.DEFER
    assert result.metadata["classification_reason"] == REASON_RELIANCE_INELIGIBLE


def test_hard_outranks_reliance_ineligible() -> None:
    result = _classify(
        [
            _violation(ViolationKind.RELIANCE_INELIGIBLE, "warrant"),
            _violation(ViolationKind.HARD),
        ]
    )
    assert result.decision == GovernanceDecision.DENY


def test_reliance_ineligible_defers_regardless_of_confidence() -> None:
    result = _classify(
        [_violation(ViolationKind.RELIANCE_INELIGIBLE, "warrant")], confidence=0.0
    )
    assert result.decision == GovernanceDecision.DEFER


def test_reliance_ineligible_with_defer_disabled_denies() -> None:
    result = _classify(
        [_violation(ViolationKind.RELIANCE_INELIGIBLE, "warrant")], defer=False
    )
    assert result.decision == GovernanceDecision.DENY


# ── Governor end to end ──────────────────────────────────────────────────────


def _governor(source: Any) -> Any:
    opa, stpa = allow_opa(), clean_stpa()
    return make_governor(
        opa=opa,
        stpa_validator=stpa,
        core_stages=(*kernel_stages(opa, stpa), _stage(source)),
        domain_tiers=(TradeConfidenceTier(_BINDING),),
    )


async def test_revoked_warrant_with_high_confidence_defers_not_denies() -> None:
    governor = _governor(_source_with(status="REVOKED", revocation_ref="REV-1"))
    result = await governor.validate_action(
        "execute_trade", {"confidence": 0.99, "amount": 100.0, "symbol": "AAPL"}
    )
    assert result["verdict"] == GovernanceDecision.DEFER
    assert result["defer_reason"] == DeferReason.WARRANT_INELIGIBLE.value
    kinds = {v.kind for v in result["violations"]}
    # FTRA routes the irreversible trade to HITL; a human cannot repair a
    # warrant, so RELIANCE_INELIGIBLE outranks it and the verdict is DEFER.
    assert kinds == {ViolationKind.RELIANCE_INELIGIBLE, ViolationKind.HITL}


async def test_eligible_warrant_adds_no_finding() -> None:
    """With an eligible warrant only the FTRA irreversibility HITL remains."""
    governor = _governor(StaticWarrantSource.eligible())
    result = await governor.validate_action(
        "execute_trade", {"confidence": 0.99, "amount": 100.0, "symbol": "AAPL"}
    )
    assert result["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert {v.kind for v in result["violations"]} == {ViolationKind.HITL}


async def test_hard_finding_still_denies_when_warrant_also_fails() -> None:
    """A malformed score is HARD in the tier; the warrant failure must not mask it."""
    governor = _governor(StaticWarrantSource())
    with pytest.raises(GovernanceError):
        await governor.validate_action(
            "execute_trade", {"confidence": "0.99", "amount": 100.0, "symbol": "AAPL"}
        )


async def test_govern_mints_no_seal_on_warrant_failure() -> None:
    governor = _governor(_source_with(status="REVOKED", revocation_ref="REV-1"))
    with pytest.raises(GovernanceError):
        await governor.govern(
            "execute_trade", {"confidence": 0.99, "amount": 100.0, "symbol": "AAPL"}
        )


# ── Post-approval revalidation (TOCTOU) ──────────────────────────────────────


class _RecordingBarrier(MutatingTier):
    """A claiming phase-2 tier that records every commit and rollback."""

    tier_name = "recording_barrier"
    order = 9

    def __init__(self) -> None:
        self.commits: list[str] = []
        self.rollbacks: list[str] = []

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_trade"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        self.commits.append(action)
        return [], CommitReceipt(tier=self.tier_name, magnitude=1.0, token="debit-1")

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        self.rollbacks.append(action)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        return None


class _Monotonic:
    """A hand-advanced monotonic clock (no sleeps)."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _approval_governor(
    source: StaticWarrantSource, clock: _Monotonic | None = None
) -> tuple[Any, _RecordingBarrier]:
    opa, stpa = allow_opa(), clean_stpa()
    barrier = _RecordingBarrier()
    cache_kwargs: dict[str, Any] = {} if clock is None else {"monotonic": clock}
    governor = make_governor(
        opa=opa,
        stpa_validator=stpa,
        core_stages=(*kernel_stages(opa, stpa), _stage(source, **cache_kwargs)),
        domain_tiers=(TradeConfidenceTier(_BINDING), barrier),
    )
    return governor, barrier


_TRADE = {"confidence": 0.99, "amount": 100.0, "symbol": "AAPL"}


async def test_warrant_revoked_after_approval_defers_without_seal() -> None:
    """Eligible at approval, revoked before post-HITL revalidation: once the
    cached state is outside the 60 s window it is re-fetched, the revocation
    defers (never a DENY), no seal is minted, phase 2 commits nothing, and
    the approval is not spent (POAM-2026-104)."""
    source = StaticWarrantSource.eligible()
    clock = _Monotonic()
    governor, barrier = _approval_governor(source, clock)

    pending = await governor.validate_action("execute_trade", dict(_TRADE))
    assert pending["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert ViolationKind.RELIANCE_INELIGIBLE not in {
        v.kind for v in pending["violations"]
    }

    source.put(
        issue_test_warrant(status="REVOKED", revocation_ref="REV-AFTER-APPROVAL")
    )
    clock.now += 60.001  # the approval took longer than the freshness window
    calls_before = len(source.calls)
    counter = SpendCounter()
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence"
    ) as mint:
        with pytest.raises(GovernanceDeferred, match="RELIANCE_INELIGIBLE_REVOKED"):
            await governor.revalidate_post_hitl(
                "execute_trade",
                dict(_TRADE),
                approval=granted_approval("PASS", counter=counter),
            )
    assert len(source.calls) == calls_before + 1  # the warrant was re-fetched
    mint.assert_not_called()
    assert barrier.commits == []
    assert counter.calls == 0


async def test_warrant_still_eligible_after_approval_seals() -> None:
    """Control: the same flow with the warrant intact commits and seals."""
    source = StaticWarrantSource.eligible()
    governor, barrier = _approval_governor(source)
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        return_value="seal-ok",
    ):
        seal = await governor.revalidate_post_hitl(
            "execute_trade", dict(_TRADE), approval=granted_approval("PASS")
        )
    assert seal == "seal-ok"
    assert source.calls == [TRADE_CONFIDENCE_NORM_ID]
    assert barrier.commits == ["execute_trade"]


# ── Assembly ─────────────────────────────────────────────────────────────────


def _use_region_thresholds(monkeypatch: pytest.MonkeyPatch, region: str) -> None:
    from src.gateway.governance.schemas import thresholds as thresholds_module

    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        thresholds_module.load_and_validate_thresholds(region=region),
    )


class _AdmittingProvider:
    async def fetch_baseline(self, region: str) -> Any:  # pragma: no cover - unused
        raise NotImplementedError

    async def validate_fria(self, payload: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def submit_evidence(self, receipt: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError


def _assemble_eu(**kwargs: Any) -> Any:
    kwargs.setdefault("flags", DecisionFlags(defer=True, narrow=False))
    return assemble_governor(
        [FinanceCagePlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        jurisdiction=eu_ai_act.contribution(provider=_AdmittingProvider()),  # type: ignore[arg-type]
        **kwargs,
    )


def test_eu_assembly_without_a_warrant_source_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_region_thresholds(monkeypatch, "EU_ECB")
    with pytest.raises(GovernorAssemblyError, match="warrant"):
        _assemble_eu()


def test_eu_assembly_with_defer_disabled_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_region_thresholds(monkeypatch, "EU_ECB")
    with pytest.raises(GovernorAssemblyError, match="(?i)defer"):
        _assemble_eu(
            flags=DecisionFlags(defer=False, narrow=False),
            warrant_source=StaticWarrantSource.eligible(),
        )


def test_eu_assembly_refuses_a_non_source(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_region_thresholds(monkeypatch, "EU_ECB")
    with pytest.raises(GovernorAssemblyError):
        _assemble_eu(warrant_source=object())


def test_eu_assembly_wires_one_warrant_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_region_thresholds(monkeypatch, "EU_ECB")
    governor = _assemble_eu(warrant_source=StaticWarrantSource.eligible())
    stages = [s for s in governor.stages if isinstance(s, WarrantStage)]
    assert len(stages) == 1
    assert [b.norm_id for b in stages[0].bindings] == [TRADE_CONFIDENCE_NORM_ID]
    assert governor.components.norm_bindings[0].governing_version == (
        WARRANT_TEST_GOVERNING_VERSION
    )


@pytest.mark.parametrize("region", ["US_FED", "APAC_MAS"])
def test_unwarranted_regions_assemble_without_source(
    monkeypatch: pytest.MonkeyPatch, region: str
) -> None:
    _use_region_thresholds(monkeypatch, region)
    governor = assemble_governor(
        [FinanceCagePlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=False, narrow=False),
        jurisdiction=resolve_jurisdiction(region),
    )
    assert not any(isinstance(s, WarrantStage) for s in governor.stages)


@pytest.mark.parametrize("has_warranted_norm", [False, True])
@pytest.mark.parametrize("defer_enabled", [False, True])
@pytest.mark.parametrize("has_source", [False, True])
def test_assembly_rule_matches_the_proof(
    has_warranted_norm: bool, defer_enabled: bool, has_source: bool
) -> None:
    kwargs = {
        "has_warranted_norm": has_warranted_norm,
        "defer_enabled": defer_enabled,
        "has_source": has_source,
    }
    assert warranted_assembly_admissible(**kwargs) == (
        proof.warranted_assembly_admissible(**kwargs)
    )


# ── Value / version pinning ──────────────────────────────────────────────────


def _finance(region: str) -> FinanceThresholds:
    return FinanceThresholds.model_validate(
        load_and_validate_thresholds(region=region).domains["finance"]
    )


def test_eu_warranted_value_is_pinned_to_its_governing_version() -> None:
    """Changing a warranted norm's value requires a new governing_version and a
    re-issued warrant. Update this pin only together with both."""
    norm = _finance("EU_ECB").confidence.min_trade_confidence
    assert (TRADE_CONFIDENCE_NORM_ID, norm.value, norm.requires_warrant) == (
        "confidence.min_trade_confidence",
        0.97,
        True,
    )
    assert norm.governing_version == "cage-policy-2.1.0"


@pytest.mark.parametrize("region", ["US_FED", "APAC_MAS"])
def test_other_regions_do_not_require_a_warrant(region: str) -> None:
    assert _finance(region).confidence.min_trade_confidence.requires_warrant is False


def test_warranted_norm_without_version_is_refused() -> None:
    from pydantic import ValidationError

    from src.cage_finance.thresholds import MinTradeConfidenceNorm

    with pytest.raises(ValidationError):
        MinTradeConfidenceNorm.model_validate({"value": 0.97, "requires_warrant": True})


def test_kernel_names_no_warrant_provider_or_finance_norm() -> None:
    """The gate is kernel-neutral: the plugin names the norm, the factory the provider."""
    kernel = _REPO / "src" / "gateway" / "governance" / "governor"
    for path in kernel.rglob("*.py"):
        text = path.read_text()
        for forbidden in ("provider_05", "min_trade_confidence", "VEIP"):
            assert forbidden not in text, f"{path} names {forbidden!r}"
