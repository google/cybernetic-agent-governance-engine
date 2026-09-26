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

"""DRY_RUN must predict live refusals without mutating any state.

``verify()`` is what agents and the /verify endpoint use to preview a
decision.  An optimistic ALLOW for an action live execution would DENY is a
fail-open prediction, so each test here asserts both halves: the refusal is
reported, and nothing is committed or reserved.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Profile, StageContext, run_pipeline
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.safety.resource_guard import FiscalLimitGuard

pytestmark = [pytest.mark.unit, pytest.mark.local]

TRADE = {"amount": 100.0, "symbol": "AAPL", "agent_id": "agent-1"}


def _cbf(verdict: str) -> MagicMock:
    cbf = MagicMock()
    cbf.verify_action = AsyncMock(return_value=verdict)
    cbf.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE"))
    return cbf


async def _dry_run(tiers: list[Any], action: str = "execute_trade", params: dict | None = None):
    ctx = StageContext(action=action, params=params or TRADE, profile=Profile.DRY_RUN)
    return await run_pipeline(order_stages(tiers), ctx, profile=Profile.DRY_RUN)


@pytest.mark.asyncio
async def test_dry_run_reports_cbf_refusal_without_committing() -> None:
    cbf = _cbf("UNSAFE: projected cash below barrier")
    result = await _dry_run([CBFTierPlugin(cbf)])

    assert [(v.tier, v.code, v.kind) for v in result.violations] == [
        ("cbf", "CBF_BARRIER_VIOLATED", ViolationKind.HARD)
    ]
    assert result.violations[0].message == "UNSAFE: projected cash below barrier"
    cbf.verify_action.assert_awaited_once()
    cbf.atomic_verify_and_commit.assert_not_called()
    assert result.committed_stages == ()


@pytest.mark.asyncio
async def test_dry_run_allows_when_barrier_safe() -> None:
    cbf = _cbf("SAFE")
    result = await _dry_run([CBFTierPlugin(cbf)])
    assert result.violations == ()
    cbf.atomic_verify_and_commit.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["", "safe", "SAFE ", "UNKNOWN", "None"])
async def test_barrier_preview_fails_closed_on_non_safe_verdict(verdict: str) -> None:
    result = await _dry_run([CBFTierPlugin(_cbf(verdict))])
    assert [v.code for v in result.violations] == ["CBF_BARRIER_VIOLATED"]


@pytest.mark.asyncio
async def test_barrier_preview_exception_is_hard_violation() -> None:
    cbf = _cbf("SAFE")
    cbf.verify_action = AsyncMock(side_effect=ConnectionError("redis down"))
    result = await _dry_run([CBFTierPlugin(cbf)])
    assert [(v.code, v.kind) for v in result.violations] == [("TIER_EXCEPTION", ViolationKind.HARD)]
    assert "ConnectionError" in result.violations[0].message


@pytest.mark.asyncio
async def test_dry_run_reports_healthcare_dose_barrier_refusal() -> None:
    """The preview is kernel-level, so non-finance barrier tiers are covered too."""
    cbf = _cbf("UNSAFE: cumulative dose exceeds ceiling")
    result = await _dry_run([DoseBarrierTier(cbf)], action="administer_dose", params={"dose_mg": 10})
    assert [v.code for v in result.violations] == ["DOSE_BARRIER_VIOLATED"]
    cbf.atomic_verify_and_commit.assert_not_called()


# ── Fiscal ─────────────────────────────────────────────────────────────────


class _Redis:
    """Async-client stub; records every write so tests can assert none happened."""

    def __init__(self, spent_cents: int | None = 0, fail: bool = False) -> None:
        self.spent_cents, self.fail, self.writes = spent_cents, fail, []

    async def get(self, key: str) -> bytes | None:
        if self.fail:
            raise ConnectionError("redis down")
        return None if self.spent_cents is None else str(self.spent_cents).encode()

    def __getattr__(self, name: str):  # any write-path call is recorded
        async def _write(*args, **kwargs):
            self.writes.append(name)
        return _write


def _guard(redis: _Redis, cap: float = 1_000.0) -> FiscalLimitGuard:
    guard = FiscalLimitGuard(redis, daily_cap_usd=cap)
    guard._is_async_client = lambda: True  # type: ignore[method-assign]
    return guard


@pytest.mark.asyncio
async def test_dry_run_reports_fiscal_limit_without_reserving() -> None:
    redis = _Redis(spent_cents=95_000)  # $950 of $1000 spent; $100 trade exceeds
    result = await _dry_run([FiscalTierPlugin(_guard(redis))])
    assert [v.code for v in result.violations] == ["FISCAL_LIMIT_EXCEEDED"]
    assert redis.writes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("spent_cents", "amount", "accepted"),
    [(90_000, 100.0, True), (90_001, 100.0, False), (None, 1_000.0, True), (0, 1_000.01, False)],
)
async def test_would_accept_matches_reserve_cap_rule(spent_cents, amount, accepted) -> None:
    """Same boundary as reserve(): current + amount > cap rejects."""
    redis = _Redis(spent_cents=spent_cents)
    assert await _guard(redis).would_accept(amount) is accepted
    assert redis.writes == []


@pytest.mark.asyncio
async def test_would_accept_fails_closed_on_redis_error() -> None:
    """remaining_usd() reports full headroom on Redis error; would_accept must not."""
    assert await _guard(_Redis(fail=True)).would_accept(1.0) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [0.0, -5.0, float("nan"), float("inf")])
async def test_would_accept_rejects_invalid_amounts(amount: float) -> None:
    assert await _guard(_Redis()).would_accept(amount) is False


# ── Pipeline contract ──────────────────────────────────────────────────────


class _NoPreviewStage:
    name, mutating = "opaque_commit", True

    def claims(self, ctx: StageContext) -> bool:
        return True

    async def run(self, ctx: StageContext) -> list[Violation]:
        raise AssertionError("DRY_RUN must never call run() on a mutating stage")

    async def rollback(self, ctx: StageContext) -> None:
        raise AssertionError("nothing was committed")


@pytest.mark.asyncio
async def test_mutating_stage_without_preview_blocks_dry_run() -> None:
    """A commit that can't be previewed must not be reported as ALLOW."""
    ctx = StageContext(action="execute_trade", params=TRADE, profile=Profile.DRY_RUN)
    result = await run_pipeline([_NoPreviewStage()], ctx, profile=Profile.DRY_RUN)
    assert [(v.code, v.kind) for v in result.violations] == [("PREVIEW_UNAVAILABLE", ViolationKind.HARD)]
