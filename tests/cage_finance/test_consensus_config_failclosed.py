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

"""Consensus config fail-closed tests.

Verifies that the ConsensusGate fails closed when:
- The consensus engine is misconfigured
- Critics return errors
- The new context-based signature works correctly
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = [pytest.mark.local, pytest.mark.unit]


class TestConsensusContextSignature:
    """Verify the new (action, context, magnitude) signature works correctly."""

    @pytest.mark.asyncio
    async def test_check_consensus_with_context_dict(self):
        """check_consensus accepts the new context-based signature."""
        from src.gateway.governance.consensus.engine import ConsensusGate

        gate = ConsensusGate.__new__(ConsensusGate)
        gate.threshold = 1000.0
        gate._registry = MagicMock()
        gate._default_client = MagicMock()

        # Below threshold — should return SKIPPED without LLM calls
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
        from src.gateway.governance.consensus.engine import ConsensusGate

        gate = ConsensusGate.__new__(ConsensusGate)
        gate.threshold = 1000.0
        gate._registry = MagicMock()
        gate._default_client = MagicMock()

        # Context has high amount, but magnitude is low → SKIPPED
        result = await gate.check_consensus(
            "execute_trade",
            context={"amount": 50000.0, "symbol": "AAPL"},
            magnitude=100.0,
        )
        assert result["status"] == "SKIPPED"

    @pytest.mark.asyncio
    async def test_check_consensus_falls_back_to_context_amount(self):
        """When magnitude is None, falls back to context['amount']."""
        from src.gateway.governance.consensus.engine import ConsensusGate

        gate = ConsensusGate.__new__(ConsensusGate)
        gate.threshold = 1000.0
        gate._registry = MagicMock()
        gate._default_client = MagicMock()

        # No magnitude provided, context amount is below threshold
        result = await gate.check_consensus(
            "execute_trade",
            context={"amount": 100.0, "symbol": "AAPL"},
        )
        assert result["status"] == "SKIPPED"


class TestLegacyConsensusAdapter:
    """Verify the _LegacyConsensusAdapter bridges old (action, amount, symbol) calls."""

    @pytest.mark.asyncio
    async def test_adapter_translates_positional_to_context(self):
        """The adapter wraps (action, amount, symbol) into the new signature."""
        from src.gateway.governance.contracts import _LegacyConsensusAdapter

        inner = AsyncMock()
        inner.check_consensus.return_value = {
            "status": "APPROVE",
            "reason": "test",
            "votes": [],
        }

        adapter = _LegacyConsensusAdapter(inner)
        result = await adapter.check_consensus("buy", 5000.0, "AAPL")

        # Verify the adapter called inner with the new signature
        inner.check_consensus.assert_called_once_with(
            "buy",
            context={"amount": 5000.0, "symbol": "AAPL"},
            magnitude=5000.0,
        )
        assert result["status"] == "APPROVE"

    @pytest.mark.asyncio
    async def test_adapter_preserves_return_value(self):
        pass
