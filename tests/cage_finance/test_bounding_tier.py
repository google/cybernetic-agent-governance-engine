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

import pytest

from src.cage_finance.safety.bounding.models import ContractSeverity
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
from src.cage_finance.tiers.bounding_tier import BoundingContractTierPlugin


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
        assert violations[0].recoverable is False  # HARD_BLOCK → not recoverable

    @pytest.mark.asyncio
    async def test_hard_block_not_recoverable(self):
        """HARD_BLOCK severity violations are not recoverable."""
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

        assert violations[0].recoverable is False

    @pytest.mark.asyncio
    async def test_hitl_escalate_recoverable(self):
        """HITL_ESCALATE severity violations are recoverable (parks in DeferQueue)."""
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
        assert violations[0].recoverable is True  # HITL_ESCALATE → recoverable

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
        assert violations[0].recoverable is False

    @pytest.mark.asyncio
    async def test_commit_returns_empty(self):
        """Bounding tier has no commit phase (evaluation only)."""
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
            "amount": 10000.0,
            "side": "buy",
            "venue": "NYSE",
        }

        violations = await tier.commit("execute_trade_bounded", params)

        assert len(violations) == 0

    @pytest.mark.asyncio
    async def test_rollback_noop(self):
        """Bounding tier rollback is a no-op (stateless)."""
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
            "amount": 10000.0,
            "side": "buy",
            "venue": "NYSE",
        }

        # Should not raise
        await tier.rollback("execute_trade_bounded", params)
