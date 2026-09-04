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

"""Tests for bounding contract registry and orchestration."""

from unittest.mock import MagicMock

import pytest

from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractSeverity,
)
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
from src.gateway.governance.ftra.bounding_contract import (
    BoundingContractConfig,
    BoundingContractEnforcer,
)


class TestBoundingContractRegistry:
    """Tests for BoundingContractRegistry orchestration."""

    def test_registry_initialization(self):
        """Registry initializes with enabled contracts from thresholds."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1", "B6", "B7"],
                "max_single_order_usd": 50000.0,
            }
        }

        registry = BoundingContractRegistry(thresholds)

        assert registry.enabled_contracts == ["B1", "B6", "B7"]
        assert registry.thresholds == thresholds

    def test_evaluate_all_b1_pass(self):
        """Registry evaluates B1 contract successfully."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }

        registry = BoundingContractRegistry(thresholds)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=10000.0,  # Under limit
            side="buy",
            venue="NYSE",
        )

        results, override = registry.evaluate_all(request)

        assert len(results) == 1
        assert results[0].contract_id == "B1"
        assert results[0].admitted is True
        assert override is None

    def test_evaluate_all_b1_fail(self):
        """Registry evaluates B1 contract failure."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1"],
                "max_single_order_usd": 50000.0,
            }
        }

        registry = BoundingContractRegistry(thresholds)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=100000.0,  # Over limit
            side="buy",
            venue="NYSE",
        )

        results, override = registry.evaluate_all(request)

        assert len(results) == 1
        assert results[0].contract_id == "B1"
        assert results[0].admitted is False
        assert results[0].severity == ContractSeverity.HARD_BLOCK
        assert override is None

    def test_evaluate_all_fail_fast_stops_on_hard_block(self):
        """Registry stops evaluation after first HARD_BLOCK failure."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B1", "B6", "B7"],
                "max_single_order_usd": 50000.0,
            }
        }

        registry = BoundingContractRegistry(thresholds)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=100000.0,  # Exceeds B1 limit
            side="buy",
            venue="NYSE",
        )

        results, _override = registry.evaluate_all(request)

        # Should stop after B1 fails (fail-fast optimization)
        assert len(results) == 1
        assert results[0].contract_id == "B1"
        assert results[0].admitted is False

    def test_evaluate_b10_classification_override(self):
        """Registry propagates B10 classification override when it fails."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B10"],
                "b10_min_rollback_window_seconds": 60,
            }
        }

        # Mock rollback provider that indicates no rollback support
        mock_rollback_provider = MagicMock()
        mock_rollback_provider.verify_rollback_window.return_value = {
            "supported": False,  # No rollback support
            "max_window_seconds": 0,
            "api_available": False,
        }

        registry = BoundingContractRegistry(
            thresholds, rollback_provider=mock_rollback_provider
        )

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=10000.0,
            side="buy",
            venue="LEGACY_EXCHANGE",
            rollback_window_seconds=300,
        )

        results, override = registry.evaluate_all(request)

        assert len(results) == 1
        assert results[0].contract_id == "B10"
        assert results[0].admitted is False
        assert override == "IRREVERSIBLE_TERMINAL"  # Critical!

    def test_evaluate_unknown_contract_raises(self):
        """Registry raises ValueError for unknown contract ID."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B99"],  # Invalid contract ID
            }
        }

        registry = BoundingContractRegistry(thresholds)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=10000.0,
            side="buy",
            venue="NYSE",
        )

        with pytest.raises(ValueError, match="Unknown contract ID: B99"):
            registry.evaluate_all(request)

    def test_evaluate_missing_provider_raises(self):
        """Registry raises ValueError when required provider is missing."""
        thresholds = {
            "bounding": {
                "enabled_contracts": ["B3"],  # Requires MarketDataProvider
                "min_liquidity_depth_ratio": 10.0,
            }
        }

        registry = BoundingContractRegistry(thresholds)  # No provider

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=10000.0,
            side="buy",
            venue="NYSE",
        )

        with pytest.raises(ValueError, match="Contract B3 requires MarketDataProvider"):
            registry.evaluate_all(request)
