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

"""Production stage selection must equal the formal model's, tier by tier.

The proof (``proof/model.py``) and the pipeline
(``src/gateway/governance/governor/pipeline.py``) each define which stages run
under which profile. Neither imports the other; this test is the bridge.
"""

import pytest

from proof.model import (
    PLUGIN_TIER_PHASE,
    POST_HITL_READ_ONLY_TIERS,
    PROFILE_STAGES as PROOF_PROFILES,
    PROFILES,
    TIER_PHASE,
    TIERS,
    post_hitl_runs_every_phase2_tier,
    runs_under_profile,
)
from src.gateway.governance.governor.pipeline import (
    POST_HITL_READ_ONLY_STAGES,
    Profile,
    stage_runs_under,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ALL_PHASES = TIER_PHASE | PLUGIN_TIER_PHASE


def test_profile_names_match() -> None:
    assert {p.value for p in Profile} == set(PROFILES)


@pytest.mark.parametrize("profile", list(Profile))
@pytest.mark.parametrize(("tier", "phase"), sorted(_ALL_PHASES.items()))
def test_production_predicate_matches_proof(profile: Profile, tier: str, phase: int) -> None:
    """Every (profile, tier, phase), kernel or plugin-named, selects identically."""
    assert stage_runs_under(profile, name=tier, mutating=phase == 2) == runs_under_profile(
        profile.value, tier, phase
    )


def test_full_and_dry_run_run_every_tier() -> None:
    assert PROOF_PROFILES["FULL"] == frozenset(TIERS)
    assert PROOF_PROFILES["DRY_RUN"] == frozenset(TIERS)


def test_post_hitl_read_only_sets_agree_and_are_proof_tiers() -> None:
    assert POST_HITL_READ_ONLY_STAGES == POST_HITL_READ_ONLY_TIERS
    assert POST_HITL_READ_ONLY_STAGES <= frozenset(TIERS)


def test_post_hitl_kernel_scope_is_opa_plus_phase2() -> None:
    assert PROOF_PROFILES["POST_HITL"] == frozenset({"opa", "cbf", "fiscal"})


def test_post_hitl_claim_holds() -> None:
    assert post_hitl_runs_every_phase2_tier()


def test_post_hitl_skips_read_only_plugin_tiers() -> None:
    """Fail-closed scope, not fail-open: a phase-1 plugin tier is not re-run."""
    assert not stage_runs_under(Profile.POST_HITL, name="clinical_consensus", mutating=False)


# ── Phase-2 gate and the pending-approval outcome (proof claims 8 and 9) ───────

from proof.model import (  # noqa: E402
    VIOLATION_KINDS,
    _kind_sets,
    hard_preview_denies_before_hitl,
    no_commit_under_pending_findings,
    pending_approval_outcome,
    phase2_mode as proof_phase2_mode,
)
from src.gateway.governance.classification_engine import (  # noqa: E402
    ClassificationContext,
    ClassificationEngine,
)
from src.gateway.governance.contracts import Violation, ViolationKind  # noqa: E402
from src.gateway.governance.decisions import GovernanceDecision  # noqa: E402
from src.gateway.governance.governor.pipeline import (  # noqa: E402
    StageContext,
    phase2_mode,
    run_pipeline,
)
from src.gateway.governance.governor.reservation import ReservationScope  # noqa: E402
from src.gateway.governance.narrower import NarrowerRegistry  # noqa: E402

_KIND_SETS = list(_kind_sets())
_PENDING = [k for k in _KIND_SETS if "HITL" in k and "HARD" not in k]


def _violations(tier: str, kinds: frozenset[str]) -> list[Violation]:
    return [
        Violation(tier=tier, code=f"{tier.upper()}_{k}", message=k, kind=ViolationKind[k])
        for k in sorted(kinds)
    ]


class _Phase1Probe:
    """A read-only stage that reports exactly the given kinds.

    Named ``opa`` because OPA is the read-only stage every profile runs,
    POST_HITL included (``POST_HITL_READ_ONLY_STAGES``).
    """

    name, mutating = "opa", False

    def __init__(self, kinds: frozenset[str]) -> None:
        self._kinds = kinds

    async def run(self, ctx: StageContext) -> list[Violation]:
        return _violations(self.name, self._kinds)


class _BarrierProbe:
    """A claiming phase-2 tier whose preview reports the given kinds; never commits."""

    name, mutating = "barrier_probe", True

    def __init__(self, kinds: frozenset[str]) -> None:
        self._kinds = kinds

    def claims(self, ctx: StageContext) -> bool:
        return True

    async def preview(self, ctx: StageContext) -> list[Violation]:
        return _violations(self.name, self._kinds)

    async def commit(self, ctx: StageContext):  # pragma: no cover - must never run
        raise AssertionError("phase 2 committed while approval was pending")

    async def rollback(self, ctx: StageContext, receipt) -> None:  # pragma: no cover
        raise AssertionError("nothing was committed")


def test_violation_kinds_match() -> None:
    assert {k.name for k in ViolationKind} == set(VIOLATION_KINDS)


@pytest.mark.parametrize("profile", list(Profile))
@pytest.mark.parametrize("kinds", _KIND_SETS, ids=lambda k: "+".join(sorted(k)) or "clean")
def test_production_phase2_gate_matches_proof(profile: Profile, kinds: frozenset[str]) -> None:
    assert phase2_mode(profile, [ViolationKind[k] for k in kinds]).value == proof_phase2_mode(
        profile.value, kinds
    )


def test_phase2_claims_hold() -> None:
    assert no_commit_under_pending_findings()
    assert hard_preview_denies_before_hitl()


@pytest.mark.parametrize("profile", [Profile.DRY_RUN, Profile.FULL, Profile.POST_HITL])
@pytest.mark.parametrize("phase1", _PENDING, ids=lambda k: "+".join(sorted(k)))
@pytest.mark.parametrize("preview", _KIND_SETS, ids=lambda k: "+".join(sorted(k)) or "pass")
async def test_pending_approval_outcome_matches_proof(
    profile: Profile, phase1: frozenset[str], preview: frozenset[str]
) -> None:
    """The real pipeline + classifier decide what the model decides, and commit nothing."""
    stages = [_Phase1Probe(phase1), _BarrierProbe(preview)]
    ctx = StageContext(action="act", params={}, profile=profile)
    if profile == Profile.DRY_RUN:
        result = await run_pipeline(stages, ctx, profile=profile)
    else:
        async with ReservationScope() as scope:
            result = await run_pipeline(stages, ctx, profile=profile, scope=scope)
        assert result.commits == () and result.committed_stages == ()

    classification = ClassificationEngine(NarrowerRegistry(narrowers=[])).classify(
        ClassificationContext(
            violations=list(result.violations),
            confidence=1.0,
            opa_decision=None,
            policy_ambiguous=False,
            params={},
        ),
        "act",
    )
    decided = {GovernanceDecision.DENY: "DENIED"}.get(
        classification.decision, classification.decision.value
    )
    assert (decided, result.barrier_preview.value) == pending_approval_outcome(phase1, preview)
