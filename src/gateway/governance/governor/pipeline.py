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

import asyncio
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
    ``CommitReceipt`` on itself; ``run_pipeline`` holds receipts locally.
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
    # rollback).  The caller owns undoing these if it later refuses the action.
    commits: tuple[tuple[Stage, CommitReceipt], ...] = ()


# Stage names must be members of proof/model.py TIERS
PROFILE_STAGES: Mapping[Profile, frozenset[str]] = {
    Profile.FULL: frozenset({"ftra", "stpa", "confidence", "cbf", "opa", "fiscal", "consensus", "causal", "fria"}),
    Profile.DRY_RUN: frozenset({"ftra", "stpa", "confidence", "cbf", "opa", "fiscal", "consensus", "causal", "fria"}),
    Profile.POST_HITL: frozenset({"opa", "cbf", "fiscal"}),  # decision 1: fiscal re-checked post-approval
}

# Profiles under which every registered domain tier runs, whatever its name.
PROFILE_RUNS_ALL_DOMAIN_TIERS: frozenset[Profile] = frozenset({Profile.FULL, Profile.DRY_RUN})



async def rollback_lifo(
    committed: Sequence[tuple[Stage, CommitReceipt]], ctx: StageContext
) -> list[Violation]:
    """Undo each ``(stage, receipt)`` commit in reverse order.  Fails closed.

    D6: every rollback is attempted even if an earlier one fails, so one faulty
    stage cannot strand reservations held by the others.  Each failure yields a
    HARD ``ROLLBACK_FAILED`` violation so the action is denied, never retried.

    Cancellation-safe: the rollbacks run in a shielded task.  If the caller is
    cancelled meanwhile, every rollback still runs to completion before the
    ``CancelledError`` is re-raised.  The only other exception this raises is a
    non-``Exception`` ``BaseException`` escaping a rollback, re-raised only
    after all the other rollbacks have been attempted.
    """
    task = asyncio.ensure_future(_rollback_each(tuple(committed), ctx))
    interrupted: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if task.cancelled():
                raise  # the rollback task itself was cancelled (e.g. loop shutdown)
            interrupted = exc  # our caller was cancelled: finish rolling back first
    failures, escaped = task.result()
    if escaped is not None:
        raise escaped
    if interrupted is not None:
        raise interrupted
    return failures


async def _rollback_each(
    committed: tuple[tuple[Stage, CommitReceipt], ...], ctx: StageContext
) -> tuple[list[Violation], BaseException | None]:
    """Attempt every rollback (LIFO), catching ``BaseException`` per rollback."""
    failures: list[Violation] = []
    escaped: BaseException | None = None
    for stage, receipt in reversed(committed):
        try:
            await stage.rollback(ctx, receipt)
        except BaseException as exc:
            logger.exception("stage %s rollback FAILED", stage.name)
            failures.append(Violation(
                tier=stage.name,
                code="ROLLBACK_FAILED",
                message=(
                    f"rollback of {stage.name} failed: {type(exc).__name__} — "
                    "resource state may be inconsistent; manual reconciliation required"
                ),
                kind=ViolationKind.HARD,
            ))
            if escaped is None and not isinstance(exc, Exception):
                escaped = exc
    return failures, escaped


def _claims_failure(stage: Stage, exc: Exception) -> Violation:
    return Violation(
        tier=stage.name,
        code="TIER_EXCEPTION",
        message=f"Exception in claims_action: {type(exc).__name__}: {exc}",
        kind=ViolationKind.HARD,
    )


async def run_pipeline(stages: Sequence[Stage], ctx: StageContext, *, profile: Profile) -> PipelineResult:
    span = trace.get_current_span()
    
    # a. Select stages whose name in PROFILE_STAGES[profile]
    allowed_stage_names = PROFILE_STAGES[profile]
    
    profile_stages = []
    claimed_domains = []
    # A domain tier whose claims() raised is treated as claiming the action and
    # fails closed where it would have run.  Kept per request (keyed by stage
    # identity), never on the stage: stages are shared across requests.
    claim_failures: dict[int, Violation] = {}

    for s in stages:
        is_domain_tier = hasattr(s, "claims")
        # PROFILE_STAGES names kernel stages.  Domain tiers carry plugin-chosen
        # names (e.g. "dose_barrier"), so filtering them by name would silently
        # skip them (fail-open).  Every claiming domain tier runs under the
        # profiles in PROFILE_RUNS_ALL_DOMAIN_TIERS; POST_HITL keeps its scope.
        if s.name not in allowed_stage_names and not (
            is_domain_tier and profile in PROFILE_RUNS_ALL_DOMAIN_TIERS
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
    # Per-request receipts.  Kept local: stages are shared across requests.
    commits: list[tuple[Stage, CommitReceipt]] = []
    current_ctx = ctx
    
    ftra_result: FtraBoundaryResult | None = None
    opa_verdict: OpaVerdict | None = None

    async def run_stage(stage: Stage, stage_ctx: StageContext) -> list[Violation]:
        if id(stage) in claim_failures:
            return [claim_failures[id(stage)]]
        return await stage.run(stage_ctx)

    async def commit_stage(
        stage: Stage, stage_ctx: StageContext
    ) -> tuple[list[Violation], CommitReceipt | None]:
        if id(stage) in claim_failures:
            return [claim_failures[id(stage)]], None
        return await stage.commit(stage_ctx)
    
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
            # commit mutating stages in order
            for stage in mutating:
                try:
                    stage_violations, receipt = await commit_stage(stage, current_ctx)
                except BaseException:
                    # Cancellation (or any escape) mid-commit: undo every commit
                    # already made, then propagate.  By contract the raising
                    # commit itself mutated nothing.
                    await rollback_lifo(commits, current_ctx)
                    raise
                if receipt is not None:
                    # Recorded even alongside violations: a commit that mutated
                    # state and then refused must still be undone.
                    commits.append((stage, receipt))
                if stage_violations:
                    violations.extend(stage_violations)
                    # e. A CBF/domain commit is a violation whenever it reports not committed
                    tier_failures.append(GovernanceTierFailure(
                        tier=stage.name,
                        control_id=stage_violations[0].code,
                        rule_description=stage_violations[0].message
                    ))
                    violations.extend(await rollback_lifo(commits, current_ctx))
                    commits = []
                    break
                committed_stages.append(stage.name)

    return PipelineResult(
        violations=tuple(violations),
        tier_failures=tuple(tier_failures),
        opa_verdict=opa_verdict,
        ftra=ftra_result,
        committed_stages=tuple(committed_stages),
        commits=tuple(commits),
    )
