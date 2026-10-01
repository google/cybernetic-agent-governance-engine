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
from dataclasses import dataclass
from enum import StrEnum
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from src.gateway.governance.contracts import (
    CommitReceipt,
    GovernanceTierFailure,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.reservation import ReservationScope

from opentelemetry import trace

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
    stpa_violation_count: int = 0


class Stage(Protocol):
    """A pipeline stage.  Instances are shared across concurrent requests.

    Read-only stages implement ``run()``.  Mutating stages implement
    ``preview()`` (side-effect-free, used under DRY_RUN), ``commit()`` and
    ``rollback()``.  A stage must never keep per-request state such as a
    ``CommitReceipt`` on itself; the request's ``ReservationScope`` holds them.
    """

    name: str
    mutating: bool

    async def run(self, ctx: StageContext) -> list[Violation]: ...

    # Mutating stages only: side-effect-free stand-in for commit() under DRY_RUN.
    async def preview(self, ctx: StageContext) -> list[Violation]: ...

    # Mutating stages only.  The receipt is not None iff state was mutated.
    async def commit(self, ctx: StageContext) -> tuple[list[Violation], CommitReceipt | None]: ...

    # Mutating stages only: undo exactly what ``receipt`` records.
    async def rollback(self, ctx: StageContext, receipt: CommitReceipt) -> None: ...


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


#: Read-only stages re-run after human approval (TOCTOU): policy may have
#: changed while the request waited. Must be members of proof/model.py TIERS.
POST_HITL_READ_ONLY_STAGES: frozenset[str] = frozenset({"opa"})


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
            raise ValueError("DRY_RUN never commits; it must not receive a ReservationScope")
    elif scope is None:
        raise ValueError(f"profile {profile} commits phase-2 stages and requires a ReservationScope")


async def run_pipeline(
    stages: Sequence[Stage],
    ctx: StageContext,
    *,
    profile: Profile,
    scope: ReservationScope | None = None,
) -> PipelineResult:
    """Run ``profile``'s stages over ``ctx``.

    Mutating commits go through ``scope``, which the caller owns: the commits
    stay in force only if the caller issues a seal inside the scope.  On the
    first mutating violation the scope is rolled back here.
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
        is_domain_tier = hasattr(s, "claims")
        # Structural, never by name: domain tiers carry plugin-chosen names
        # (e.g. "dose_barrier"), and a name filter would silently skip them.
        if not stage_runs_under(
            profile, name=s.name, mutating=bool(getattr(s, "mutating", False))
        ):
            continue

        if is_domain_tier:
            try:
                claimed = getattr(s, "claims")(ctx)
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
        # f. Ungoverned actions: run ftra, stpa, opa only
        profile_stages = [s for s in profile_stages if s.name in {"ftra", "stpa", "opa"}]
    else:
        span.set_attribute("governance.governed", True)
        profile_stages.extend(claimed_domains)
        
    def read_only_sort_key(s: Stage) -> tuple[int, str]:
        if s.name == "ftra": return (0, s.name)
        if s.name == "stpa": return (1, s.name)
        if s.name == "opa": return (2, s.name)
        if s.name == "confidence": return (3, s.name)
        return (4, "")  # domain tiers: stable sort keeps order_stages() (phase, order, name)
        
    read_only = [s for s in profile_stages if not getattr(s, "mutating", False)]
    read_only.sort(key=read_only_sort_key)
    
    mutating = [s for s in profile_stages if getattr(s, "mutating", False)]
    
    violations: list[Violation] = []
    tier_failures: list[GovernanceTierFailure] = []
    committed_stages: list[str] = []
    current_ctx = ctx
    
    ftra_result: FtraBoundaryResult | None = None
    opa_verdict: OpaVerdict | None = None

    async def run_stage(stage: Stage, stage_ctx: StageContext) -> list[Violation]:
        if id(stage) in claim_failures:
            return [claim_failures[id(stage)]]
        return await stage.run(stage_ctx)

    async def commit_stage(scope: ReservationScope, stage: Stage, stage_ctx: StageContext) -> list[Violation]:
        if id(stage) in claim_failures:
            return [claim_failures[id(stage)]]
        return await scope.commit(stage, stage_ctx)
    
    # b. Read-only stages
    for stage in read_only:
        stage_violations = await run_stage(stage, current_ctx)

        # update ctx context
        if stage.name == "stpa":
            current_ctx = dataclasses.replace(current_ctx, stpa_violation_count=len(stage_violations))
        elif stage.name == "opa":
            if hasattr(stage, "decoded_verdict"):
                opa_verdict = getattr(stage, "decoded_verdict")
                current_ctx = dataclasses.replace(current_ctx, opa_verdict=opa_verdict)
        elif stage.name == "ftra":
            if hasattr(stage, "result"):
                ftra_result = getattr(stage, "result")
        
        if stage_violations:
            violations.extend(stage_violations)
            
        hard_violations = [v for v in stage_violations if v.kind == ViolationKind.HARD]
        if hard_violations:
            # Stop at the first HARD violation
            break
            
    # Check if there are ANY violations from read-only stages
    has_violations = len(violations) > 0
    
    # c. Mutating stages run ONLY if (b) produced zero violations
    if not has_violations:
        if profile == Profile.DRY_RUN:
            # DRY_RUN never calls a mutating stage's commit(); it calls the
            # side-effect-free preview() so verify() reports the refusal a live
            # commit would produce.  Nothing is committed, so nothing to roll back.
            for stage in mutating:
                preview = getattr(stage, "preview", None)
                if id(stage) in claim_failures:
                    stage_violations = [claim_failures[id(stage)]]
                elif preview is None:
                    # Can't predict this commit: say so rather than report ALLOW.
                    stage_violations = [Violation(
                        tier=stage.name,
                        code="PREVIEW_UNAVAILABLE",
                        message=f"{stage.name} cannot be previewed; dry run cannot vouch for it",
                        kind=ViolationKind.HARD,
                    )]
                else:
                    stage_violations = await preview(current_ctx)
                if stage_violations:
                    violations.extend(stage_violations)
                    tier_failures.append(GovernanceTierFailure(
                        tier=stage.name,
                        control_id=stage_violations[0].code,
                        rule_description=stage_violations[0].message,
                    ))
                    break
        else:
            # Commit mutating stages in order.  The scope records every receipt
            # (even one returned alongside violations) and, if this coroutine
            # is cancelled, undoes them on exit.
            if scope is None:  # unreachable after _check_scope; never commit unowned
                raise ValueError(f"profile {profile} requires a ReservationScope")
            for stage in mutating:
                stage_violations = await commit_stage(scope, stage, current_ctx)
                if stage_violations:
                    violations.extend(stage_violations)
                    # e. A CBF/domain commit is a violation whenever it reports not committed
                    tier_failures.append(GovernanceTierFailure(
                        tier=stage.name,
                        control_id=stage_violations[0].code,
                        rule_description=stage_violations[0].message
                    ))
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
    )
