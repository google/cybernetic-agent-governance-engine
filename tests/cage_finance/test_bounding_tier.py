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

"""Tests for BoundingContractTierPlugin integration."""

from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest

from src.cage_finance.safety.bounding.models import ContractSeverity
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
from src.cage_finance.tiers.bounding_tier import BoundingContractTierPlugin
from src.gateway.governance.contracts import ViolationKind

# Hermetic: validates bounding tier integration in-memory.
pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestBoundingContractTierPlugin:
    """Tests for bounding tier integration."""

    def test_tier_metadata(self):
        """Tier has correct phase/order for early Phase 1 evaluation."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }
        registry = BoundingContractRegistry(thresholds)
        tier = BoundingContractTierPlugin(registry)

        assert tier.tier_name == "bounding"
        assert tier.phase == 1  # Phase 1 tier
        assert tier.order == 2  # Order 2 (after FTRA, before CBF)

    def test_claims_execute_trade_bounded_only(self):
        """Tier only claims execute_trade_bounded action."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }
        registry = BoundingContractRegistry(thresholds)
        tier = BoundingContractTierPlugin(registry)

        assert tier.claims_action("execute_trade_bounded", {}) is True
        assert tier.claims_action("execute_trade", {}) is False
        assert tier.claims_action("get_quote", {}) is False

    @pytest.mark.asyncio
    async def test_evaluate_pass_returns_no_violations(self):
        """Tier evaluation returns empty violations list when all contracts pass."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }
        registry = BoundingContractRegistry(thresholds)
        tier = BoundingContractTierPlugin(registry)

        params = {
            "symbol": "AAPL",
            "amount": 10000.0,  # Under limit
            "side": "buy",
            "venue": "NYSE",
        }

        violations = await tier.evaluate("execute_trade_bounded", params)

        assert len(violations) == 0

    @pytest.mark.asyncio
    async def test_evaluate_fail_returns_violations(self):
        """Tier evaluation returns violations when contracts fail."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }
        registry = BoundingContractRegistry(thresholds)
        tier = BoundingContractTierPlugin(registry)

        params = {
            "symbol": "AAPL",
            "amount": 100000.0,  # Over limit
            "side": "buy",
            "venue": "NYSE",
        }

        violations = await tier.evaluate("execute_trade_bounded", params)

        assert len(violations) == 1
        assert violations[0].tier == "bounding"
        assert violations[0].code == "BOUNDING_B1_HARD_BLOCK"
        assert violations[0].kind == ViolationKind.HARD  # HARD_BLOCK → ViolationKind.HARD

    @pytest.mark.asyncio
    async def test_hard_block_kind_is_hard(self):
        """HARD_BLOCK severity violations have kind=HARD."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }
        registry = BoundingContractRegistry(thresholds)
        tier = BoundingContractTierPlugin(registry)

        params = {
            "symbol": "AAPL",
            "amount": 100000.0,
            "side": "buy",
            "venue": "NYSE",
        }

        violations = await tier.evaluate("execute_trade_bounded", params)

        assert violations[0].kind == ViolationKind.HARD

    @pytest.mark.asyncio
    async def test_hitl_escalate_kind_is_hitl(self):
        """HITL_ESCALATE severity violations have kind=HITL (parks in DeferQueue)."""
        # Note: B6 uses confidence from trade params, but BoundedTradeRequest doesn't have that field
        # Use B3 (liquidity depth) instead, which is also HITL_ESCALATE
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B3"],  # B3 = HITL_ESCALATE (liquidity depth)
                "min_liquidity_depth_ratio": 2000.0,  # Unreachable threshold (> 1000 ratio from stub) → escalate
            },
        }
        # Use stub market data provider that returns insufficient depth
        from src.cage_finance.safety.bounding.providers import StubMarketDataProvider

        market_data_provider = StubMarketDataProvider()
        registry = BoundingContractRegistry(
            thresholds, market_data_provider=market_data_provider
        )
        tier = BoundingContractTierPlugin(registry)

        params = {
            "symbol": "AAPL",
            "amount": 10000.0,
            "side": "buy",
            "venue": "NYSE",
        }

        violations = await tier.evaluate("execute_trade_bounded", params)

        assert len(violations) == 1
        assert violations[0].code == "BOUNDING_B3_HITL_ESCALATE"
        assert violations[0].kind == ViolationKind.HITL  # HITL_ESCALATE → ViolationKind.HITL

    @pytest.mark.asyncio
    async def test_invalid_params_returns_violation(self):
        """Invalid parameters return violation rather than raising exception."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }
        registry = BoundingContractRegistry(thresholds)
        tier = BoundingContractTierPlugin(registry)

        # Missing required field "symbol"
        params = {
            "amount": 10000.0,
            "side": "buy",
            "venue": "NYSE",
        }

        violations = await tier.evaluate("execute_trade_bounded", params)

        assert len(violations) == 1
        assert violations[0].tier == "bounding"
        assert violations[0].code == "INVALID_REQUEST_PARAMS"
        assert violations[0].kind == ViolationKind.HARD

    def test_is_read_only(self):
        """Bounding is a ReadOnlyTier: it defines no commit, rollback or confirm."""
        from src.gateway.governance.contracts import ReadOnlyTier

        tier = BoundingContractTierPlugin(BoundingContractRegistry({"bounding": {}}))
        assert isinstance(tier, ReadOnlyTier)
        assert not any(hasattr(tier, hook) for hook in ("commit", "rollback", "confirm"))


def _b10_tier(capability: dict | Exception) -> BoundingContractTierPlugin:
    provider = MagicMock()
    if isinstance(capability, Exception):
        provider.verify_rollback_window.side_effect = capability
    else:
        provider.verify_rollback_window.return_value = capability
    registry = BoundingContractRegistry(
        {"bounding": {"enabled_contracts": ["B10"], "b10_min_rollback_window_seconds": 60}},
        rollback_provider=provider,
    )
    return BoundingContractTierPlugin(registry)


_B10_PARAMS = {
    "symbol": "AAPL",
    "amount": 1000.0,
    "side": "buy",
    "venue": "NYSE",
    "rollback_window_seconds": 300,
}
_OPEN = {"supported": True, "api_available": True, "max_window_seconds": 600}


class TestB10ClosedWindowIsHitl:
    """A closed rollback window parks the request; it is never an override."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "capability",
        [
            RuntimeError("settlement provider down"),
            {**_OPEN, "supported": False},
            {**_OPEN, "api_available": False},
            {**_OPEN, "max_window_seconds": 120},
        ],
        ids=["provider_unavailable", "unsupported", "api_down", "window_over_capability"],
    )
    async def test_closed_window_is_a_hitl_violation(self, capability):
        violations = await _b10_tier(capability).evaluate("execute_trade_bounded", _B10_PARAMS)
        assert len(violations) == 1
        assert violations[0].code == "B10_ROLLBACK_WINDOW_CLOSED"
        assert violations[0].kind == ViolationKind.HITL

    @pytest.mark.asyncio
    async def test_window_below_minimum_is_a_hitl_violation(self):
        params = {**_B10_PARAMS, "rollback_window_seconds": 30}
        violations = await _b10_tier(_OPEN).evaluate("execute_trade_bounded", params)
        assert [(v.code, v.kind) for v in violations] == [
            ("B10_ROLLBACK_WINDOW_CLOSED", ViolationKind.HITL)
        ]

    @pytest.mark.asyncio
    async def test_open_window_admits(self):
        assert await _b10_tier(_OPEN).evaluate("execute_trade_bounded", _B10_PARAMS) == []

    @pytest.mark.asyncio
    async def test_tier_keeps_no_per_request_state(self):
        """The removed override was per-request state on a shared tier."""
        tier = _b10_tier({**_OPEN, "supported": False})
        before = dict(vars(tier))
        await tier.evaluate("execute_trade_bounded", _B10_PARAMS)
        assert vars(tier) == before


@pytest.fixture
def defer_redis(monkeypatch: pytest.MonkeyPatch):
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    from src.gateway.governance import defer_queue as defer_queue_mod

    redis = fakeredis.FakeRedis(decode_responses=True)

    @asynccontextmanager
    async def _queue():
        yield defer_queue_mod.DeferQueue(redis)

    monkeypatch.setattr(defer_queue_mod, "open_defer_queue", _queue)
    return defer_queue_mod


@pytest.mark.asyncio
async def test_closed_window_parks_an_approval_token(defer_redis) -> None:
    """End to end: B10's closed window yields REQUIRE_APPROVAL with a parked token."""
    from src.gateway.governance.env_posture import DeploymentPosture
    from src.gateway.governance.governor.assembly import GovernorComponents
    from src.gateway.governance.governor.governor import SymbolicGovernor
    from tests.fixtures.governor import allow_opa, default_classifier

    governor = SymbolicGovernor(
        GovernorComponents(
            opa=allow_opa(),
            core_stages=(),
            classifier=default_classifier(),
            posture=DeploymentPosture.TEST,
            domain_tiers=(_b10_tier({**_OPEN, "supported": False}),),
        )
    )
    result = await governor.validate_action("execute_trade_bounded", dict(_B10_PARAMS))
    assert result["verdict"] == "REQUIRE_APPROVAL"
    assert result["deferred_id"]
    async with defer_redis.open_defer_queue() as queue:
        assert await queue.get(result["deferred_id"]) is not None
