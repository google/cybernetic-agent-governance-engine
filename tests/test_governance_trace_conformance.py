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

"""Every trace the real governor emits is a state of proof/model.py.

The governor publishes one ``GOVERNANCE_TRACE`` event per decision
(``src/gateway/governance/governor/trace.py``); ``proof/trace_conformance.py``
projects each onto ``proof.model.State`` and checks it against the model
instantiated over the run's plan. This module drives the real
``SymbolicGovernor`` (real ``run_pipeline``, ``run_sealed`` and
``ClassificationEngine``) through every entry point over single- and
double-fault stage configurations, and checks every trace, plus a simulated
actuation for every seal. Negative controls show the checker rejects
hand-built violations of each rule.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from proof import model
from proof.trace_conformance import (
    TRACE_EVENT_TYPE,
    TRACE_SCHEMA_VERSION,
    check_trace,
)
from scripts.check_trace_conformance import main as cli_main
from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    NarrowingResult,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor import governor as governor_module
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor import trace as trace_module
from src.gateway.governance.governor import verdicts as verdicts_module
from src.gateway.governance.governor.assembly import kernel_stages
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.pipeline import (
    UNGOVERNED_STAGES,
    StageContext,
    run_pipeline,
)
from src.gateway.governance.governor.reservation import ReservationScope
from src.gateway.governance.narrower import NarrowerRegistry
from tests.fixtures.governor import allow_opa, make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

ACTION = "act"
KINDS = ("HARD", "HITL", "NARROWABLE", "DEFERRABLE")
STAGES = ("ftra", "stpa", "opa", "confidence", "domain_check", "barrier")
ENTRY_POINTS = ("govern", "validate_action", "revalidate_post_hitl")


# ── Doubles ──────────────────────────────────────────────────────────────────


def _violations(tier: str, kind: str | None, params: dict[str, Any], sticky: bool) -> list[Violation]:
    """``kind`` from ``tier``, unless a narrower already clamped the params."""
    if kind is None or (params.get("narrowed") and not sticky):
        return []
    return [Violation(tier=tier, code=f"{tier.upper()}_{kind}", message=kind, kind=ViolationKind[kind])]


class _Kernel:
    """A read-only kernel-stage double named like the real one."""

    mutating = False

    def __init__(self, name: str, kind: str | None, sticky: bool) -> None:
        self.name, self._kind, self._sticky = name, kind, sticky

    async def run(self, ctx: StageContext) -> list[Violation]:
        return _violations(self.name, self._kind, dict(ctx.params), self._sticky)


class _Check(ReadOnlyTier):
    """A claiming phase-1 domain tier."""

    tier_name = property(lambda self: "domain_check")
    order = property(lambda self: 1)

    def __init__(self, kind: str | None, sticky: bool) -> None:
        self._kind, self._sticky = kind, sticky

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return _violations("domain_check", self._kind, params, self._sticky)


class _Barrier(MutatingTier):
    """A claiming phase-2 tier: preview and commit report the same kind."""

    tier_name = property(lambda self: "barrier")
    order = property(lambda self: 1)

    def __init__(self, kind: str | None, sticky: bool) -> None:
        self._kind, self._sticky = kind, sticky

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return _violations("barrier", self._kind, params, self._sticky)

    async def commit(self, action: str, params: dict[str, Any]):
        refused = _violations("barrier", self._kind, params, self._sticky)
        return (refused, None) if refused else ([], CommitReceipt(tier="barrier", magnitude=1.0))

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        return None

    async def confirm(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        return None


class _Clamp:
    """Narrower double: marks the params as clamped."""

    def can_narrow(self, violation: Violation, action: str, params: dict[str, Any]) -> bool:
        return violation.kind == ViolationKind.NARROWABLE

    def narrow(self, violation: Violation, action: str, params: dict[str, Any]) -> NarrowingResult:
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={**params, "narrowed": True},
            constraints_applied=["clamped"],
            narrowing_reason="test",
        )


def _governor(kinds: dict[str, str], *, governed: bool = True, sticky: bool = False) -> SymbolicGovernor:
    core = [_Kernel(name, kinds.get(name), sticky) for name in ("ftra", "stpa", "opa", "confidence")]
    tiers = [_Check(kinds.get("domain_check"), sticky), _Barrier(kinds.get("barrier"), sticky)]
    classifier = ClassificationEngine(
        NarrowerRegistry([_Clamp()]), confidence_threshold=0.70, defer_enabled=True, narrow_enabled=True
    )
    return make_governor(
        core_stages=core, domain_tiers=tiers if governed else (), classifier=classifier
    )


class _Recorder:
    """Captures trace events and the seals behind them."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.seals: list[str] = []

    async def publish(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    async def issue_seal(self, action: str, params: dict[str, Any], *, path: str) -> str:
        seal = f"seal-{len(self.seals)}"
        self.seals.append(seal)
        return seal


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(governor_module, "publish_trace", rec.publish)
    monkeypatch.setattr(sealing_module, "issue_seal", rec.issue_seal)
    monkeypatch.setattr(governor_module, "issue_narrow_receipt", AsyncMock())
    monkeypatch.setattr(verdicts_module, "publish_refusal", AsyncMock())
    parked = AsyncMock(side_effect=lambda *a, **k: {"verdict": "PARKED"})
    monkeypatch.setitem(governor_module._VERDICT_HANDLERS, GovernanceDecision.REQUIRE_APPROVAL, parked)
    monkeypatch.setitem(governor_module._VERDICT_HANDLERS, GovernanceDecision.DEFER, parked)
    return rec


async def _decide(gov: SymbolicGovernor, entry: str) -> None:
    params = {"confidence": 0.5}  # below the threshold, so DEFERRABLE defers
    try:
        if entry == "govern":
            await gov.govern(ACTION, params)
        elif entry == "validate_action":
            await gov.validate_action(ACTION, params)
        else:
            await gov.revalidate_post_hitl(ACTION, params, approved_barrier_preview=None)
    except GovernanceError:
        pass


def _configs() -> Iterator[dict[str, str]]:
    yield {}
    for stage, kind in itertools.product(STAGES, KINDS):
        yield {stage: kind}
    for (s1, s2), (k1, k2) in itertools.product(
        itertools.combinations(STAGES, 2), itertools.product(KINDS, repeat=2)
    ):
        yield {s1: k1, s2: k2}


def _with_actuation(rec: _Recorder, seals_before: int) -> None:
    for seal in rec.seals[seals_before:]:
        rec.events.append(trace_module.executed_trace_event(seal, action=ACTION))


# ── Parity between the kernel and the model ──────────────────────────────────


def test_ungoverned_stage_sets_agree() -> None:
    assert UNGOVERNED_STAGES == model.UNGOVERNED_TIERS


def test_kernel_tiers_are_the_kernel_stages() -> None:
    names = tuple(stage.name for stage in kernel_stages(allow_opa(), None))
    assert names == model.KERNEL_TIERS


def test_event_schema_constants_agree() -> None:
    assert trace_module.TRACE_EVENT_TYPE == TRACE_EVENT_TYPE
    assert trace_module.TRACE_SCHEMA_VERSION == TRACE_SCHEMA_VERSION
    assert {p.value for p in trace_module.TracePhase} <= set(model.PHASES)
    assert trace_module.SEALING_VERDICTS == model.SEALING_VERDICTS


# ── The real governor conforms ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_every_governor_trace_is_a_model_state(recorder: _Recorder) -> None:
    phases: set[str] = set()
    for kinds in _configs():
        for entry in ENTRY_POINTS:
            before_events, before_seals = len(recorder.events), len(recorder.seals)
            await _decide(_governor(kinds), entry)
            decisions = recorder.events[before_events:]
            assert len(decisions) == 1, (kinds, entry, decisions)
            phases.add(decisions[0]["phase"])
            _with_actuation(recorder, before_seals)
    assert check_trace(recorder.events) == []
    # The sweep exercises every decision phase, so the check is not vacuous.
    assert phases == {"SEAL_ISSUED", "NARROW", "DENIED", "CHECKING"}


@pytest.mark.asyncio
async def test_narrow_whose_rerun_fails_is_a_model_denial(recorder: _Recorder) -> None:
    await _decide(_governor({"barrier": "NARROWABLE"}, sticky=True), "govern")
    [event] = recorder.events
    assert (event["phase"], event["narrower_present"], event["clamped_params_valid"]) == (
        "DENIED",
        True,
        False,
    )
    assert check_trace(recorder.events) == []


@pytest.mark.asyncio
async def test_ungoverned_seal_plans_only_ungoverned_stages(recorder: _Recorder) -> None:
    await _decide(_governor({}, governed=False), "govern")
    [event] = recorder.events
    assert event["governed"] is False and event["phase"] == "SEAL_ISSUED"
    assert {name for name, _ in event["plan"]} == UNGOVERNED_STAGES
    assert check_trace(recorder.events) == []


@pytest.mark.asyncio
async def test_a_governor_that_seals_over_findings_is_caught(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation control: break the seal gate in the real governor."""

    async def seals_regardless(stages, ctx, params, *, path, settlements, on_seal=None):
        async with ReservationScope() as scope:
            result = await run_pipeline(stages, ctx, profile=ctx.profile, scope=scope)
            seal = await recorder.issue_seal(ctx.action, params, path=path)
            scope.seal_issued(seal)
            return result, seal

    monkeypatch.setattr(governor_module, "run_sealed", seals_regardless)
    await _decide(_governor({"opa": "HARD"}), "govern")
    assert recorder.events[0]["phase"] == "SEAL_ISSUED"
    assert "reachable" in _rules(recorder.events)


# ── Negative controls: the checker rejects each violation ────────────────────


def _event(**overrides: Any) -> dict[str, Any]:
    plan = [["ftra", 1], ["stpa", 1], ["opa", 1], ["confidence", 1], ["barrier", 2]]
    base = {
        "type": TRACE_EVENT_TYPE,
        "schema_version": TRACE_SCHEMA_VERSION,
        "action": ACTION,
        "path": "govern",
        "profile": "FULL",
        "verdict": "ALLOW",
        "phase": "SEAL_ISSUED",
        "seal_present": True,
        "seal_ref": "ref-1",
        "governed": True,
        "narrower_present": False,
        "clamped_params_valid": False,
        "plan": plan,
        "outcomes": [[name, "PASS"] for name, _ in plan],
    }
    return base | overrides


def _executed(ref: str = "ref-1") -> dict[str, Any]:
    return {
        "type": TRACE_EVENT_TYPE,
        "schema_version": TRACE_SCHEMA_VERSION,
        "action": ACTION,
        "path": "actuation",
        "phase": "EXECUTED",
        "seal_present": True,
        "seal_ref": ref,
    }


def _rules(events: list[dict[str, Any]]) -> set[str]:
    return {finding.rule for finding in check_trace(events)}


def test_well_formed_seal_and_actuation_conform() -> None:
    assert check_trace([_event(), _executed()]) == []


def test_execution_without_issuance_is_a_direct_bind() -> None:
    assert _rules([_executed()]) == {"no_direct_bind"}


def test_second_execution_of_a_seal_is_rejected() -> None:
    assert _rules([_event(), _executed(), _executed()]) == {"single_use"}


def test_seal_over_a_failed_tier_is_unreachable() -> None:
    outcomes = _event()["outcomes"]
    outcomes[2] = ["opa", "FAIL"]
    assert "reachable" in _rules([_event(outcomes=outcomes)])


def test_seal_with_a_planned_tier_that_never_ran_is_unreachable() -> None:
    assert "reachable" in _rules([_event(outcomes=_event()["outcomes"][:-1])])


def test_dry_run_seal_is_rejected() -> None:
    rules = _rules([_event(profile="DRY_RUN", path="validate_action")])
    assert "seal" in rules


def test_pending_verdict_must_be_unsealed_checking() -> None:
    event = _event(verdict="REQUIRE_APPROVAL", phase="DENIED", seal_present=False, seal_ref=None)
    assert "seal" in _rules([event])


def test_phase2_before_phase1_is_rejected() -> None:
    plan = [["barrier", 2], ["ftra", 1], ["stpa", 1], ["opa", 1], ["confidence", 1]]
    assert "plan" in _rules([_event(plan=plan, outcomes=[[n, "PASS"] for n, _ in plan])])


def test_governed_run_must_plan_every_kernel_tier() -> None:
    plan = [["ftra", 1], ["stpa", 1], ["opa", 1], ["barrier", 2]]
    assert "coverage" in _rules([_event(plan=plan, outcomes=[[n, "PASS"] for n, _ in plan])])


def test_ungoverned_run_must_not_plan_a_barrier() -> None:
    assert "coverage" in _rules([_event(governed=False)])


def test_post_hitl_must_not_plan_read_only_tiers_beyond_opa() -> None:
    assert "plan" in _rules([_event(profile="POST_HITL", path="revalidate_post_hitl")])


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.jsonl"
    good.write_text(
        "\n".join(json.dumps(e) for e in [_event(), {"type": "OTHER"}, {"event": _executed()}])
    )
    assert cli_main([str(good)]) == 0
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps(_executed()))
    assert cli_main([str(bad)]) == 1
    assert "[no_direct_bind]" in capsys.readouterr().out
    broken = tmp_path / "broken.jsonl"
    broken.write_text("{not json")
    assert cli_main([str(broken)]) == 2
