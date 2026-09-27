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
from unittest.mock import AsyncMock, MagicMock

from src.gateway.governance.contracts import CommitReceipt, GovernanceTierPlugin
from src.gateway.governance.governor.pipeline import StageContext
from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage, order_stages
from src.gateway.governance.contracts import Violation, ViolationKind

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.fixture
def mock_tier():
    tier = MagicMock(spec=GovernanceTierPlugin)
    tier.tier_name = "test_tier"
    tier.phase = 1
    tier.order = 10
    tier.claims_action.return_value = True
    tier.evaluate = AsyncMock(return_value=[])
    tier.commit = AsyncMock(return_value=([], None))
    tier.rollback = AsyncMock()
    return tier

@pytest.fixture
def ctx():
    from src.gateway.governance.governor.pipeline import Profile
    return StageContext(
        action="execute_trade",
        params={"amount": 100},
        profile=Profile.FULL,
    )

def test_domain_tier_stage_init(mock_tier):
    mock_tier.phase = 2
    stage = DomainTierStage(mock_tier)
    assert stage.name == "test_tier"
    assert stage.mutating is True

def test_claims_success(mock_tier, ctx):
    stage = DomainTierStage(mock_tier)
    assert stage.claims(ctx) is True
    mock_tier.claims_action.assert_called_once_with("execute_trade", {"amount": 100})

def test_claims_exception_propagates_and_leaves_no_state(mock_tier, ctx):
    """The stage is shared across requests: it must not latch a claims failure.

    run_pipeline turns the exception into a per-request HARD violation
    (tests/governor/test_pipeline.py).
    """
    mock_tier.claims_action.side_effect = Exception("Claims failed")
    stage = DomainTierStage(mock_tier)
    before = dict(vars(stage))

    with pytest.raises(Exception, match="Claims failed"):
        stage.claims(ctx)
    assert vars(stage) == before

@pytest.mark.asyncio
async def test_run_phase_1_success(mock_tier, ctx):
    mock_tier.phase = 1
    stage = DomainTierStage(mock_tier)
    
    violations = await stage.run(ctx)
    assert violations == []
    mock_tier.evaluate.assert_called_once_with("execute_trade", {"amount": 100})
    mock_tier.commit.assert_not_called()

@pytest.mark.asyncio
async def test_run_phase_2_is_read_only(mock_tier, ctx):
    mock_tier.phase = 2
    stage = DomainTierStage(mock_tier)

    violations = await stage.run(ctx)
    assert violations == []
    mock_tier.evaluate.assert_called_once_with("execute_trade", {"amount": 100})
    mock_tier.commit.assert_not_called()

@pytest.mark.asyncio
async def test_commit_phase_2_returns_receipt(mock_tier, ctx):
    mock_tier.phase = 2
    receipt = CommitReceipt(tier="test_tier", magnitude=100.0)
    mock_tier.commit = AsyncMock(return_value=([], receipt))
    stage = DomainTierStage(mock_tier)

    assert await stage.commit(ctx) == ([], receipt)
    mock_tier.commit.assert_called_once_with("execute_trade", {"amount": 100})
    mock_tier.evaluate.assert_not_called()

@pytest.mark.asyncio
async def test_commit_exception_fails_closed_without_receipt(mock_tier, ctx):
    mock_tier.phase = 2
    mock_tier.commit = AsyncMock(side_effect=RuntimeError("commit failed"))
    stage = DomainTierStage(mock_tier)

    violations, receipt = await stage.commit(ctx)
    assert receipt is None
    assert [(v.code, v.kind) for v in violations] == [("TIER_EXCEPTION", ViolationKind.HARD)]
    assert "commit failed" in violations[0].message

@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [[], None, ([], "not-a-receipt"), ("x", None)])
async def test_commit_malformed_result_fails_closed(mock_tier, ctx, bad):
    """An old-style or malformed commit result is a HARD denial, never an ALLOW."""
    mock_tier.phase = 2
    mock_tier.commit = AsyncMock(return_value=bad)
    stage = DomainTierStage(mock_tier)

    violations, receipt = await stage.commit(ctx)
    assert receipt is None
    assert [(v.code, v.kind) for v in violations] == [("TIER_EXCEPTION", ViolationKind.HARD)]

@pytest.mark.asyncio
async def test_commit_malformed_violations_keeps_receipt_for_rollback(mock_tier, ctx):
    mock_tier.phase = 2
    receipt = CommitReceipt(tier="test_tier", magnitude=1.0)
    mock_tier.commit = AsyncMock(return_value=("not-a-list", receipt))
    stage = DomainTierStage(mock_tier)

    violations, kept = await stage.commit(ctx)
    assert kept is receipt
    assert violations[0].code == "TIER_EXCEPTION"

@pytest.mark.asyncio
async def test_run_exception(mock_tier, ctx):
    mock_tier.evaluate.side_effect = Exception("Eval failed")
    stage = DomainTierStage(mock_tier)
    
    violations = await stage.run(ctx)
    assert len(violations) == 1
    assert violations[0].code == "TIER_EXCEPTION"
    assert "Eval failed" in violations[0].message
    assert violations[0].kind == ViolationKind.HARD

@pytest.mark.asyncio
async def test_rollback_forwards_receipt(mock_tier, ctx):
    mock_tier.phase = 2
    stage = DomainTierStage(mock_tier)
    receipt = CommitReceipt(tier="test_tier", magnitude=7.0)

    await stage.rollback(ctx, receipt)
    mock_tier.rollback.assert_called_once_with("execute_trade", {"amount": 100}, receipt)

def test_order_stages():
    t1 = MagicMock(spec=GovernanceTierPlugin)
    t1.phase = 2; t1.order = 10; t1.tier_name = "b"
    t2 = MagicMock(spec=GovernanceTierPlugin)
    t2.phase = 1; t2.order = 20; t2.tier_name = "a"
    t3 = MagicMock(spec=GovernanceTierPlugin)
    t3.phase = 1; t3.order = 10; t3.tier_name = "z"
    
    stages = order_stages([t1, t2, t3])
    assert len(stages) == 3
    # Sort order: phase, order, tier_name
    assert stages[0].tier == t3  # phase=1, order=10, name=z
    assert stages[1].tier == t2  # phase=1, order=20, name=a
    assert stages[2].tier == t1  # phase=2, order=10, name=b
