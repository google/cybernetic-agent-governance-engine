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

from dataclasses import FrozenInstanceError

import pytest

from proof.model import TIERS
from src.gateway.governance.governor import (
    OpaVerdict,
    PipelineResult,
    Profile,
    StageContext,
)
from src.gateway.governance.governor.errors import GovernanceError as NewGovernanceError
from src.gateway.governance.governor.governor import (
    GovernanceError as OldGovernanceError,
)
from src.gateway.governance.governor.pipeline import (
    POST_HITL_READ_ONLY_STAGES,
    stage_runs_under,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_profile_and_verdict_values():
    assert Profile.FULL == "FULL"
    assert Profile.POST_HITL == "POST_HITL"
    assert Profile.DRY_RUN == "DRY_RUN"

    assert OpaVerdict.ALLOW == "ALLOW"
    assert OpaVerdict.DENY == "DENY"
    assert OpaVerdict.MANUAL_REVIEW == "MANUAL_REVIEW"


def test_stage_context_frozen():
    ctx = StageContext(action="test", params={}, profile=Profile.FULL)
    with pytest.raises(FrozenInstanceError):
        ctx.action = "new_action"


def test_pipeline_result_frozen():
    res = PipelineResult(
        violations=(),
        tier_failures=(),
        opa_verdict=None,
        ftra=None,
        committed_stages=(),
    )
    with pytest.raises(FrozenInstanceError):
        res.opa_verdict = OpaVerdict.ALLOW


def test_profile_stages_match_proof_tiers():
    from proof.model import TIER_PHASE

    proof_tiers = frozenset(TIERS)
    assert POST_HITL_READ_ONLY_STAGES.issubset(proof_tiers)

    def selected(profile: Profile) -> frozenset[str]:
        return frozenset(
            t
            for t in TIERS
            if stage_runs_under(profile, name=t, mutating=TIER_PHASE[t] == 2)
        )

    assert selected(Profile.FULL) == proof_tiers
    assert selected(Profile.DRY_RUN) == proof_tiers
    assert selected(Profile.POST_HITL) == frozenset({"opa", "cbf", "fiscal"})


def test_governance_error_identity_preserved():
    # Verify that except GovernanceError identity is preserved
    assert NewGovernanceError is OldGovernanceError
