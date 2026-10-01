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
