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

"""Finance consensus config fail-closed tests."""

from unittest.mock import MagicMock

import pytest

from src.cage_finance.tiers.consensus_tier import (
    build_finance_consensus_contribution,
    build_finance_consensus_gate,
)
from src.gateway.governance.consensus.engine import ConsensusGate

pytestmark = [pytest.mark.local, pytest.mark.unit]


class TestFinanceConsensusContextSignature:
    """Verify the finance-configured ConsensusGate works with context and magnitude."""

    @pytest.mark.asyncio
    async def test_check_consensus_with_context_dict(self):
        """check_consensus accepts the context-based signature."""
        gate = build_finance_consensus_gate()
        gate.threshold = 1000.0
        gate._registry = MagicMock()

        result = await gate.check_consensus(
            "execute_trade",
            context={"amount": 100.0, "symbol": "AAPL"},
            magnitude=100.0,
        )
        assert result["status"] == "SKIPPED"
        assert result["reason"] == "Below threshold"

    @pytest.mark.asyncio
    async def test_check_consensus_magnitude_overrides_context_amount(self):
        """When magnitude is provided, it takes precedence for threshold check."""
        gate = build_finance_consensus_gate()
        gate.threshold = 1000.0
        gate._registry = MagicMock()

        result = await gate.check_consensus(
            "execute_trade",
            context={"amount": 50000.0, "symbol": "AAPL"},
            magnitude=100.0,
        )
        assert result["status"] == "SKIPPED"

    @pytest.mark.asyncio
    async def test_check_consensus_falls_back_to_context_amount(self):
        """When magnitude is None, falls back to finance magnitude_extractor (params['amount'])."""
        gate = build_finance_consensus_gate()
        gate.threshold = 1000.0
        gate._registry = MagicMock()

        result = await gate.check_consensus(
            "execute_trade",
            context={"amount": 100.0, "symbol": "AAPL"},
        )
        assert result["status"] == "SKIPPED"

    def test_finance_critics_loaded_from_yaml(self):
        """Finance ConsensusContribution loads Risk Manager and Compliance Officer."""
        contrib = build_finance_consensus_contribution()
        roles = [c.role for c in contrib.critics]
        assert roles == ["Risk Manager", "Compliance Officer"]
        assert "HIGH_VALUE_TRADE" in contrib.high_stakes_actions

    @pytest.mark.asyncio
    async def test_unconfigured_gate_fails_closed_above_threshold(self):
        """An unconfigured ConsensusGate() fails closed with DENY when triggered."""
        gate = ConsensusGate(
            threshold=100.0, magnitude_extractor=lambda p: float(p.get("amount", 0.0))
        )
        result = await gate.check_consensus("execute_trade", context={"amount": 500.0})
        assert result["status"] == "DENY"
        assert result["decision"] == "DENY"
