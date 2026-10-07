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

import dataclasses
import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from opentelemetry import trace

from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTierFailure,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.reservation import ReservationScope
from src.gateway.governance.warrant.reliance import RelianceRecord

tracer = trace.get_tracer(__name__)


from src.gateway.governance.ftra.models import FtraBoundaryResult

logger = logging.getLogger(__name__)


class Profile(StrEnum):
    FULL = "FULL"
    POST_HITL = "POST_HITL"
    DRY_RUN = "DRY_RUN"


class OpaVerdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True)
class StageContext:
    action: str
    params: Mapping[str, Any]
    profile: Profile
    opa_verdict: OpaVerdict | None = None


@dataclass(frozen=True)
class StageOutput:
    """What a read-only stage reports for one request.

    Stages are shared across concurrent requests, so anything a stage learns
    about *this* request (the decoded OPA verdict, the FTRA boundary result,
    the warrant reliance records) travels back to :func:`run_pipeline` here,
    never as an attribute on the stage. ``run_pipeline`` threads
    ``opa_verdict`` into the ``StageContext`` of later stages and every field
    into the ``PipelineResult``.
    """

    violations: tuple[Violation, ...] = ()
    opa_verdict: OpaVerdict | None = None
    ftra: FtraBoundaryResult | None = None
    # One record per warranted norm the stage evaluated, eligible or not.
    reliance: tuple[RelianceRecord, ...] = ()


def as_stage_output(result: "list[Violation] | StageOutput") -> StageOutput:
    """Normalise a ``run()`` result: a bare violation list carries nothing else."""
    if isinstance(result, StageOutput):
        return result
    return StageOutput(violations=tuple(result))


class Stage(Protocol):
    """A pipeline stage.  Instances are shared across concurrent requests.

    Read-only stages implement ``run()``, returning their violations, or a
    :class:`StageOutput` when they also report per-request facts (OPA verdict,
    FTRA result).  Mutating stages implement ``preview()`` (side-effect-free:
    used under DRY_RUN and whenever phase 1 left only non-HARD findings, see
    :func:`phase2_mode`), ``commit()``, ``rollback()`` and ``confirm()``
    (ADR-009: called through the governor's settlement ledger once the
    sealed action has run).  A stage must never
    keep per-request state on itself — neither a ``CommitReceipt`` (the
    request's ``ReservationScope`` holds those) nor a decoded result (return
    a ``StageOutput``).
    """

    name: str
    mutating: bool

    async def run(self, ctx: StageContext) -> list[Violation] | StageOutput: ...

    # The four hooks below belong to mutating stages only. ``run_pipeline``
    # never calls them on a stage with ``mutating = False``; the defaults make
    # that contract explicit (and keep read-only subclasses concrete).

    # Side-effect-free stand-in for commit() (Phase2Mode.PREVIEW).
    async def preview(self, ctx: StageContext) -> list[Violation]:
        raise TypeError(f"read-only stage {self.name!r} has no preview()")

    # The receipt is not None iff state was mutated.
    async def commit(
        self, ctx: StageContext
    ) -> tuple[list[Violation], CommitReceipt | None]:
        raise TypeError(f"read-only stage {self.name!r} cannot commit")

    # Undo exactly what ``receipt`` records.
    async def rollback(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        raise TypeError(
            f"read-only stage {self.name!r} holds no reservation to roll back"
        )

    # The sealed action ran; make ``receipt`` permanent.
    async def confirm(self, ctx: StageContext, receipt: CommitReceipt) -> None:
        raise TypeError(
            f"read-only stage {self.name!r} holds no reservation to confirm"
        )


class Phase2Mode(StrEnum):
    """How the mutating (phase-2) stages are driven once phase 1 has run."""

    SKIP = "SKIP"  # phase 1 refused (HARD): nothing a barrier says can change that
    PREVIEW = "PREVIEW"  # side-effect-free preview(): DRY_RUN, or approval pending
    COMMIT = "COMMIT"  # phase 1 clean under a committing profile


class BarrierPreview(StrEnum):
    """Outcome of the phase-2 barriers (``PipelineResult.barrier_preview`` / ``barrier_outcome``)."""

    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class PipelineResult:
    violations: tuple[Violation, ...]
    tier_failures: tuple[GovernanceTierFailure, ...]
    opa_verdict: OpaVerdict | None
    ftra: FtraBoundaryResult | None
    committed_stages: tuple[str, ...]
    # Receipts still outstanding when the pipeline returns (empty after a
    # rollback).  The caller's ReservationScope undoes them unless it is sealed.
    commits: tuple[tuple[Stage, CommitReceipt], ...] = ()
    # Set iff claimed phase-2 stages answered through preview(); None when they
    # committed, were skipped, or none claimed the action.
    barrier_preview: BarrierPreview | None = None
    # The subset of ``violations`` those previews reported.
    preview_violations: tuple[Violation, ...] = ()
    # What the claimed phase-2 stages said, previewed *or* committed: PASS iff
    # none refused.  None when phase 2 was skipped or no mutating stage
    # claimed the action.  The committing run compares it with the snapshot
    # an approval was given against (APPROVAL_CONTEXT_DRIFT).
    barrier_outcome: BarrierPreview | None = None
    # The stages selected for this run, in execution order, as
    # ``(name, phase)`` with phase 1 = read-only and 2 = mutating.
    plan: tuple[tuple[str, int], ...] = ()
    # ``(name, StageOutcome)`` for every stage that ran (previewed or
    # committed), in execution order.  A planned stage that never ran is
    # absent: proof/model.py's ``PENDING``.
    stage_outcomes: tuple[tuple[str, str], ...] = ()
    # False when no domain tier claimed the action, so only
    # UNGOVERNED_STAGES ran.
    governed: bool = True
    # Every warrant reliance record the read-only stages reported, in
    # execution order (empty when no warranted norm governs the action). The
    # verdict's artefact carries them: seal evidence, DeferToken or receipt.
    reliance: tuple[RelianceRecord, ...] = ()


class StageOutcome(StrEnum):
    """What one stage reported in one run (proof/model.py tier results)."""

    PASS = "PASS"  # no violation
    FAIL = "FAIL"  # at least one violation, of any kind


def _outcome(stage_violations: Sequence[Violation]) -> str:
    return StageOutcome.FAIL.value if stage_violations else StageOutcome.PASS.value


#: Read-only stages re-run after human approval (TOCTOU): policy may have
#: changed, or a warrant been revoked, while the request waited. Mirrors
#: ``proof/model.py::POST_HITL_READ_ONLY_TIERS``; ``warrant`` is the kernel
#: ``WarrantStage`` (present only when a region marks a norm requires_warrant).
POST_HITL_READ_ONLY_STAGES: frozenset[str] = frozenset({"opa", "warrant"})

#: The only stages an action no domain tier claims runs through.  Mirrors
#: ``proof/model.py::UNGOVERNED_TIERS`` (``tests/test_governance_trace_conformance.py``).
UNGOVERNED_STAGES: frozenset[str] = frozenset({"ftra", "stpa", "opa"})


def stage_runs_under(profile: Profile, *, name: str, mutating: bool) -> bool:
    """Whether a stage runs under ``profile`` — decided by structure, not by name.

    FULL and DRY_RUN run every stage. POST_HITL runs the read-only stages in
    :data:`POST_HITL_READ_ONLY_STAGES` plus **every** mutating (phase-2)
    stage, so a plugin-named barrier (``dose_barrier``, ``bounding``) re-checks
    after approval exactly like ``cbf`` and ``fiscal``. Mirrors
    ``proof/model.py::runs_under_profile`` (``tests/test_formal_profile_parity.py``).
    """
    if profile == Profile.POST_HITL:
        return mutating or name in POST_HITL_READ_ONLY_STAGES
    return True


def phase2_mode(profile: Profile, phase1_kinds: Iterable[ViolationKind]) -> Phase2Mode:
    """The phase-2 gate: decided by the *kinds* phase 1 reported, never by tier.

    * any HARD → SKIP: the request is refused whatever the barriers say;
    * no violations → COMMIT (DRY_RUN: PREVIEW, it never commits);
    * only non-HARD (HITL, NARROWABLE, DEFERRABLE …) → PREVIEW. The request
      will not be sealed now (``run_sealed`` refuses any violation), so
      committing would reserve headroom for nothing; previewing lets a barrier
      that would refuse anyway deny it *before* a human is asked (a HARD
      preview) or tell the reviewer what it would breach.

    Mirrors ``proof/model.py::phase2_mode`` (``tests/test_formal_profile_parity.py``).
    """
    kinds = set(phase1_kinds)
    if ViolationKind.HARD in kinds:
        return Phase2Mode.SKIP
    if kinds or profile == Profile.DRY_RUN:
        return Phase2Mode.PREVIEW
    return Phase2Mode.COMMIT


def _claims_failure(stage: Stage, exc: Exception) -> Violation:
    return Violation(
        tier=stage.name,
        code="TIER_EXCEPTION",
        message=f"Exception in claims_action: {type(exc).__name__}: {exc}",
        kind=ViolationKind.HARD,
    )


def _check_scope(profile: Profile, scope: ReservationScope | None) -> None:
    """Mutating profiles need a scope to own their commits; DRY_RUN never gets one."""
    if profile == Profile.DRY_RUN:
        if scope is not None:
            raise ValueError(
                "DRY_RUN never commits; it must not receive a ReservationScope"
            )
    elif scope is None:
        raise ValueError(
            f"profile {profile} commits phase-2 stages and requires a ReservationScope"
        )


async def run_pipeline(
    stages: Sequence[Stage],
    ctx: StageContext,
    *,
    profile: Profile,
    scope: ReservationScope | None = None,
) -> PipelineResult:
    """Run ``profile``'s stages over ``ctx``.

    Phase 2 is gated by :func:`phase2_mode`: skipped after a HARD finding,
    previewed (never committed) after only non-HARD findings or under
    DRY_RUN, and committed only over a clean phase 1.  Mutating commits go
    through ``scope``, which the caller owns: the commits stay in force only
    if the caller issues a seal inside the scope.  On the first mutating
    violation the scope is rolled back here.
    """
    _check_scope(profile, scope)
    span = trace.get_current_span()

    # a. Select the stages that run under this profile (stage_runs_under).
    profile_stages = []
    claimed_domains = []
    # A domain tier whose claims() raised is treated as claiming the action and
    # fails closed where it would have run.  Kept per request (keyed by stage
    # identity), never on the stage: stages are shared across requests.
    claim_failures: dict[int, Violation] = {}

    for s in stages:
        claims: Callable[[StageContext], bool] | None = getattr(s, "claims", None)
        # Structural, never by name: domain tiers carry plugin-chosen names
        # (e.g. "dose_barrier"), and a name filter would silently skip them.
        if not stage_runs_under(
            profile, name=s.name, mutating=bool(getattr(s, "mutating", False))
        ):
            continue

        if claims is not None:
            try:
                claimed = claims(ctx)
            except Exception as exc:
                claim_failures[id(s)] = _claims_failure(s, exc)
                claimed = True
            if claimed:
                claimed_domains.append(s)
        else:
            profile_stages.append(s)

    is_governed = len(claimed_domains) > 0

    if not is_governed:
        span.set_attribute("governance.governed", False)
        # f. Ungoverned actions: run UNGOVERNED_STAGES only
        profile_stages = [s for s in profile_stages if s.name in UNGOVERNED_STAGES]
    else:
        span.set_attribute("governance.governed", True)
        profile_stages.extend(claimed_domains)

    def read_only_sort_key(s: Stage) -> tuple[int, str]:
        if s.name == "ftra":
            return (0, s.name)
        if s.name == "stpa":
            return (1, s.name)
        if s.name == "opa":
            return (2, s.name)
        if s.name == "confidence":
            return (3, s.name)
        return (
            4,
            "",
        )  # domain tiers: stable sort keeps order_stages() (phase, order, name)

    read_only = [s for s in profile_stages if not getattr(s, "mutating", False)]
    read_only.sort(key=read_only_sort_key)

    mutating = [s for s in profile_stages if getattr(s, "mutating", False)]
    plan = tuple((s.name, 1) for s in read_only) + tuple((s.name, 2) for s in mutating)

    violations: list[Violation] = []
    outcomes: list[tuple[str, str]] = []
    tier_failures: list[GovernanceTierFailure] = []
    committed_stages: list[str] = []
    current_ctx = ctx

    ftra_result: FtraBoundaryResult | None = None
    opa_verdict: OpaVerdict | None = None
    reliance: list[RelianceRecord] = []

    async def run_stage(stage: Stage, stage_ctx: StageContext) -> StageOutput:
        if id(stage) in claim_failures:
            return StageOutput(violations=(claim_failures[id(stage)],))
        return as_stage_output(await stage.run(stage_ctx))

    async def commit_stage(
        scope: ReservationScope, stage: Stage, stage_ctx: StageContext
    ) -> list[Violation]:
        if id(stage) in claim_failures:
            return [claim_failures[id(stage)]]
        return await scope.commit(stage, stage_ctx)

    # b. Read-only stages
    for stage in read_only:
        output = await run_stage(stage, current_ctx)
        stage_violations = list(output.violations)

        # Per-request facts come back in the StageOutput, never off the
        # (shared) stage instance.
        if output.opa_verdict is not None:
            opa_verdict = output.opa_verdict
            current_ctx = dataclasses.replace(current_ctx, opa_verdict=opa_verdict)
        if output.ftra is not None:
            ftra_result = output.ftra
        reliance.extend(output.reliance)
        outcomes.append((stage.name, _outcome(stage_violations)))

        if stage_violations:
            violations.extend(stage_violations)

        hard_violations = [v for v in stage_violations if v.kind == ViolationKind.HARD]
        if hard_violations:
            # Stop at the first HARD violation
            break

    # c. Phase 2, gated on the kinds phase 1 reported (phase2_mode).
    mode = phase2_mode(profile, (v.kind for v in violations))
    span.set_attribute("governance.phase2_mode", mode.value)
    barrier_preview: BarrierPreview | None = None
    barrier_outcome: BarrierPreview | None = None
    preview_violations: list[Violation] = []

    if mode == Phase2Mode.PREVIEW:
        # Nothing is committed (DRY_RUN, or a request that cannot be sealed
        # now), so nothing to roll back.  ``scope`` stays untouched: a run_sealed
        # caller sees no commits and refuses the seal on the violations.
        (
            preview_violations,
            preview_failures,
            preview_outcomes,
        ) = await _preview_mutating(mutating, current_ctx, claim_failures)
        outcomes.extend(preview_outcomes)
        violations.extend(preview_violations)
        tier_failures.extend(preview_failures)
        if mutating:
            barrier_preview = (
                BarrierPreview.FAIL if preview_violations else BarrierPreview.PASS
            )
            barrier_outcome = barrier_preview
            span.set_attribute("governance.barrier_preview", barrier_preview.value)
    elif mode == Phase2Mode.COMMIT:
        # Commit mutating stages in order.  The scope records every receipt
        # (even one returned alongside violations) and, if this coroutine
        # is cancelled, undoes them on exit.
        if scope is None:  # unreachable after _check_scope; never commit unowned
            raise ValueError(f"profile {profile} requires a ReservationScope")
        if mutating:
            barrier_outcome = BarrierPreview.PASS
        for stage in mutating:
            stage_violations = await commit_stage(scope, stage, current_ctx)
            outcomes.append((stage.name, _outcome(stage_violations)))
            if stage_violations:
                barrier_outcome = BarrierPreview.FAIL
                violations.extend(stage_violations)
                # e. A CBF/domain commit is a violation whenever it reports not committed
                tier_failures.append(_tier_failure(stage, stage_violations))
                violations.extend(await scope.rollback())
                break
            committed_stages.append(stage.name)

    return PipelineResult(
        violations=tuple(violations),
        tier_failures=tuple(tier_failures),
        opa_verdict=opa_verdict,
        ftra=ftra_result,
        committed_stages=tuple(committed_stages),
        commits=scope.commits if scope is not None else (),
        barrier_preview=barrier_preview,
        preview_violations=tuple(preview_violations),
        barrier_outcome=barrier_outcome,
        plan=plan,
        stage_outcomes=tuple(outcomes),
        governed=is_governed,
        reliance=tuple(reliance),
    )


def _tier_failure(
    stage: Stage, stage_violations: list[Violation]
) -> GovernanceTierFailure:
    return GovernanceTierFailure(
        tier=stage.name,
        control_id=stage_violations[0].code,
        rule_description=stage_violations[0].message,
    )


async def _preview_mutating(
    mutating: Sequence[Stage],
    ctx: StageContext,
    claim_failures: Mapping[int, Violation],
) -> tuple[list[Violation], list[GovernanceTierFailure], list[tuple[str, str]]]:
    """Ask every mutating stage what its ``commit()`` would say; change nothing.

    Never calls ``commit()``.  A stage that cannot be previewed is a HARD
    ``PREVIEW_UNAVAILABLE``: an unpredictable commit is not vouched for.
    Previewing stops at the first HARD finding (the request is refused) but
    continues past non-HARD ones, so a later barrier that would refuse
    outright still denies before a human is asked, and the reviewer sees
    every breach the approved request would hit.  Also returns each previewed
    stage's :class:`StageOutcome`.
    """
    violations: list[Violation] = []
    failures: list[GovernanceTierFailure] = []
    outcomes: list[tuple[str, str]] = []
    for stage in mutating:
        preview = getattr(stage, "preview", None)
        if id(stage) in claim_failures:
            stage_violations = [claim_failures[id(stage)]]
        elif preview is None:
            stage_violations = [
                Violation(
                    tier=stage.name,
                    code="PREVIEW_UNAVAILABLE",
                    message=f"{stage.name} cannot be previewed; dry run cannot vouch for it",
                    kind=ViolationKind.HARD,
                )
            ]
        else:
            stage_violations = await preview(ctx)
        outcomes.append((stage.name, _outcome(stage_violations)))
        if not stage_violations:
            continue
        violations.extend(stage_violations)
        failures.append(_tier_failure(stage, stage_violations))
        if any(v.kind == ViolationKind.HARD for v in stage_violations):
            break
    return violations, failures, outcomes
