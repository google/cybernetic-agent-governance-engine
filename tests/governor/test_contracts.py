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

import pytest
from dataclasses import FrozenInstanceError

from proof.model import TIERS
from src.gateway.governance.governor import (
    OpaVerdict,
    PipelineResult,
    Profile,
    StageContext,
)
from src.gateway.governance.governor.pipeline import PROFILE_STAGES
from src.gateway.governance.governor.errors import GovernanceError as NewGovernanceError
from src.gateway.governance.symbolic_governor import GovernanceError as OldGovernanceError

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
    proof_tiers = frozenset(TIERS)
    
    # EVERY name must be a member of proof/model.py TIERS
    for profile, stages in PROFILE_STAGES.items():
        assert stages.issubset(proof_tiers), f"Profile {profile} has invalid stages"
        
    assert PROFILE_STAGES[Profile.FULL] == proof_tiers
    assert PROFILE_STAGES[Profile.DRY_RUN] == proof_tiers
    assert PROFILE_STAGES[Profile.POST_HITL] == frozenset({"opa", "cbf", "fiscal"})


def test_governance_error_identity_preserved():
    # Verify that except GovernanceError identity is preserved
    assert NewGovernanceError is OldGovernanceError
