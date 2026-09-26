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

from src.gateway.governance.contracts import GovernanceTierFailure, Violation, ViolationKind

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
    name: str
    mutating: bool

    async def run(self, ctx: StageContext) -> list[Violation]: ...

    async def rollback(self, ctx: StageContext) -> None: ...  # no-op default for read-only stages


@dataclass(frozen=True)
class PipelineResult:
    violations: tuple[Violation, ...]
    tier_failures: tuple[GovernanceTierFailure, ...]
    opa_verdict: OpaVerdict | None
    ftra: FtraBoundaryResult | None
    committed_stages: tuple[str, ...]


# Stage names must be members of proof/model.py TIERS
PROFILE_STAGES: Mapping[Profile, frozenset[str]] = {
    Profile.FULL: frozenset({"ftra", "stpa", "confidence", "cbf", "opa", "fiscal", "consensus", "causal", "fria"}),
    Profile.DRY_RUN: frozenset({"ftra", "stpa", "confidence", "cbf", "opa", "fiscal", "consensus", "causal", "fria"}),
    Profile.POST_HITL: frozenset({"opa", "cbf", "fiscal"}),  # decision 1: fiscal re-checked post-approval
}

# Profiles under which every registered domain tier runs, whatever its name.
PROFILE_RUNS_ALL_DOMAIN_TIERS: frozenset[Profile] = frozenset({Profile.FULL, Profile.DRY_RUN})



async def rollback_lifo(committed: Sequence[Stage], ctx: StageContext) -> list[Violation]:
    """Roll back committed stages in reverse order.  Never raises.  Fails closed.

    D6: every rollback is attempted even if an earlier one fails, so one faulty
    stage cannot strand reservations held by the others.  Each failure yields a
    HARD ``ROLLBACK_FAILED`` violation so the action is denied, never retried.
    """
    failures: list[Violation] = []
    for stage in reversed(committed):
        try:
            await stage.rollback(ctx)
        except Exception as exc:
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
    return failures


async def run_pipeline(stages: Sequence[Stage], ctx: StageContext, *, profile: Profile) -> PipelineResult:
    span = trace.get_current_span()
    
    # a. Select stages whose name in PROFILE_STAGES[profile]
    allowed_stage_names = PROFILE_STAGES[profile]
    
    profile_stages = []
    claimed_domains = []
    
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
            if getattr(s, "claims")(ctx):
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
    
    # b. Read-only stages
    for stage in read_only:
        stage_violations = await stage.run(current_ctx)
        
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
            # DRY_RUN never calls a mutating stage's run()
            pass
        else:
            # run mutating in order
            for stage in mutating:
                stage_violations = await stage.run(current_ctx)
                if stage_violations:
                    violations.extend(stage_violations)
                    # e. A CBF/domain commit is a violation whenever it reports not committed
                    tier_failures.append(GovernanceTierFailure(
                        tier=stage.name,
                        control_id=stage_violations[0].code,
                        rule_description=stage_violations[0].message
                    ))
                    
                    committed = [s for s in mutating if s.name in committed_stages]
                    violations.extend(await rollback_lifo(committed, current_ctx))
                    break
                else:
                    committed_stages.append(stage.name)
                    
    return PipelineResult(
        violations=tuple(violations),
        tier_failures=tuple(tier_failures),
        opa_verdict=opa_verdict,
        ftra=ftra_result,
        committed_stages=tuple(committed_stages)
    )
