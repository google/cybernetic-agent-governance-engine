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

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.pipeline import StageContext
from src.gateway.governance.governor.stages.domain_tiers import (
    DomainTierStage,
    order_stages,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _read_only_mock(name: str = "test_tier", order: int = 10) -> MagicMock:
    tier = MagicMock(spec=ReadOnlyTier)
    tier.tier_name = name
    tier.phase = 1
    tier.order = order
    tier.claims_action.return_value = True
    tier.evaluate = AsyncMock(return_value=[])
    return tier


def _mutating_mock(name: str = "test_tier", order: int = 10) -> MagicMock:
    tier = MagicMock(spec=MutatingTier)
    tier.tier_name = name
    tier.phase = 2
    tier.order = order
    tier.claims_action.return_value = True
    tier.evaluate = AsyncMock(return_value=[])
    tier.commit = AsyncMock(return_value=([], None))
    tier.rollback = AsyncMock()
    tier.confirm = AsyncMock()
    return tier


@pytest.fixture
def mock_tier():
    return _read_only_mock()


@pytest.fixture
def mutating_tier():
    return _mutating_mock()


@pytest.fixture
def ctx():
    from src.gateway.governance.governor.pipeline import Profile

    return StageContext(
        action="execute_trade",
        params={"amount": 100},
        profile=Profile.FULL,
    )


def test_domain_tier_stage_init(mock_tier, mutating_tier):
    stage = DomainTierStage(mutating_tier)
    assert stage.name == "test_tier"
    assert stage.mutating is True
    assert DomainTierStage(mock_tier).mutating is False


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
    stage = DomainTierStage(mock_tier)

    violations = await stage.run(ctx)
    assert violations == []
    mock_tier.evaluate.assert_called_once_with("execute_trade", {"amount": 100})


@pytest.mark.asyncio
async def test_read_only_stage_cannot_commit(mock_tier, ctx):
    stage = DomainTierStage(mock_tier)
    with pytest.raises(TypeError, match="cannot commit"):
        await stage.commit(ctx)


@pytest.mark.asyncio
async def test_run_phase_2_is_read_only(mutating_tier, ctx):
    stage = DomainTierStage(mutating_tier)

    violations = await stage.run(ctx)
    assert violations == []
    mutating_tier.evaluate.assert_called_once_with("execute_trade", {"amount": 100})
    mutating_tier.commit.assert_not_called()


@pytest.mark.asyncio
async def test_commit_phase_2_returns_receipt(mutating_tier, ctx):
    receipt = CommitReceipt(tier="test_tier", magnitude=100.0)
    mutating_tier.commit = AsyncMock(return_value=([], receipt))
    stage = DomainTierStage(mutating_tier)

    assert await stage.commit(ctx) == ([], receipt)
    mutating_tier.commit.assert_called_once_with("execute_trade", {"amount": 100})
    mutating_tier.evaluate.assert_not_called()


@pytest.mark.asyncio
async def test_commit_exception_fails_closed_without_receipt(mutating_tier, ctx):
    mutating_tier.commit = AsyncMock(side_effect=RuntimeError("commit failed"))
    stage = DomainTierStage(mutating_tier)

    violations, receipt = await stage.commit(ctx)
    assert receipt is None
    assert [(v.code, v.kind) for v in violations] == [
        ("TIER_EXCEPTION", ViolationKind.HARD)
    ]
    assert "commit failed" in violations[0].message


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [[], None, ([], "not-a-receipt"), ("x", None)])
async def test_commit_malformed_result_fails_closed(mutating_tier, ctx, bad):
    """An old-style or malformed commit result is a HARD denial, never an ALLOW."""
    mutating_tier.commit = AsyncMock(return_value=bad)
    stage = DomainTierStage(mutating_tier)

    violations, receipt = await stage.commit(ctx)
    assert receipt is None
    assert [(v.code, v.kind) for v in violations] == [
        ("TIER_EXCEPTION", ViolationKind.HARD)
    ]


@pytest.mark.asyncio
async def test_commit_malformed_violations_keeps_receipt_for_rollback(
    mutating_tier, ctx
):
    receipt = CommitReceipt(tier="test_tier", magnitude=1.0)
    mutating_tier.commit = AsyncMock(return_value=("not-a-list", receipt))
    stage = DomainTierStage(mutating_tier)

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
async def test_rollback_forwards_receipt(mutating_tier, ctx):
    stage = DomainTierStage(mutating_tier)
    receipt = CommitReceipt(tier="test_tier", magnitude=7.0)

    await stage.rollback(ctx, receipt)
    mutating_tier.rollback.assert_called_once_with(
        "execute_trade", {"amount": 100}, receipt
    )
    mutating_tier.confirm.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_forwards_receipt(mutating_tier, ctx):
    stage = DomainTierStage(mutating_tier)
    receipt = CommitReceipt(tier="test_tier", magnitude=7.0)

    await stage.confirm(ctx, receipt)
    mutating_tier.confirm.assert_called_once_with(
        "execute_trade", {"amount": 100}, receipt
    )
    mutating_tier.rollback.assert_not_called()


def test_order_stages():
    t1 = _mutating_mock("b", order=10)
    t2 = _read_only_mock("a", order=20)
    t3 = _read_only_mock("z", order=10)

    stages = order_stages([t1, t2, t3])
    assert len(stages) == 3
    # Sort order: phase, order, tier_name
    assert stages[0].tier == t3  # phase=1, order=10, name=z
    assert stages[1].tier == t2  # phase=1, order=20, name=a
    assert stages[2].tier == t1  # phase=2, order=10, name=b
