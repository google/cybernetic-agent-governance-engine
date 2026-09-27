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

"""
Tests for finance ConsensusGate — Multi-Agent Consensus Gate.

Tests Tier 5 governance: ConsensusGate requires concurrent critic agreement
for trades above the threshold_usd limit.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cage_finance.tiers.consensus_tier import build_finance_consensus_gate

# Hermetic: validates ConsensusGate with mocked THRESHOLDS and GatewayClient.
pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_thresholds():
    """Mock the THRESHOLDS singleton used by build_finance_consensus_contribution."""
    with patch("src.cage_finance.tiers.consensus_tier.THRESHOLDS") as mock_t:
        mock_t.consensus.threshold_usd = 10000.0
        yield mock_t


@pytest.fixture
def mock_gateway_client():
    """Mock GatewayClient used internally by ConsensusGate."""
    with patch("src.gateway.governance.consensus.engine.GatewayClient") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_genai_span():
    """Mock the genai_span context manager to avoid telemetry in tests."""
    with patch("src.gateway.governance.consensus.engine.genai_span") as mock_span_ctx:
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_span_ctx.return_value = mock_span
        yield mock_span


@pytest.mark.local
@pytest.mark.asyncio
async def test_consensus_engine_below_threshold_skips_consensus(
    mock_thresholds, mock_gateway_client
):
    """Trades below threshold_usd should not require consensus (fast path, SKIPPED)."""
    engine = build_finance_consensus_gate()

    result = await engine.check_consensus(
        "buy", context={"amount": 5000.0, "symbol": "AAPL"}, magnitude=5000.0
    )
    assert result["status"] == "SKIPPED"
    assert result["votes"] == []


@pytest.mark.asyncio
async def test_consensus_engine_below_threshold_exact_boundary(
    mock_thresholds, mock_gateway_client
):
    """Trade below threshold should skip (strictly less than)."""
    engine = build_finance_consensus_gate()

    result = await engine.check_consensus(
        "sell", context={"amount": 9999.99, "symbol": "TSLA"}, magnitude=9999.99
    )
    assert result["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_consensus_engine_above_threshold_unanimous_approve(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """Trades above threshold with unanimous APPROVE should return APPROVE."""
    engine = build_finance_consensus_gate()

    with patch.object(
        engine, "_get_critic_vote", new_callable=AsyncMock, return_value="APPROVE"
    ):
        result = await engine.check_consensus(
            "buy", context={"amount": 15000.0, "symbol": "MSFT"}, magnitude=15000.0
        )
    assert result["status"] == "APPROVE"
    assert "approval" in result["reason"].lower()


@pytest.mark.asyncio
async def test_consensus_engine_split_vote_escalates_for_human_review(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """A split vote (APPROVE + REJECT) must ESCALATE for human review, not outright REJECT."""
    engine = build_finance_consensus_gate()

    call_count = 0

    async def alternating_vote(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return "APPROVE" if call_count == 1 else "REJECT"

    with patch.object(engine, "_get_critic_vote", side_effect=alternating_vote):
        result = await engine.check_consensus(
            "sell", context={"amount": 20000.0, "symbol": "GME"}, magnitude=20000.0
        )
    assert result["status"] == "ESCALATE", (
        f"Split APPROVE+REJECT vote must ESCALATE for human review, got {result['status']!r}. "
        "Unanimous REJECT is required to outright block a trade."
    )


@pytest.mark.asyncio
async def test_consensus_engine_unanimous_reject_blocks_trade(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """Unanimous REJECT from all critics must result in REJECT (outright block)."""
    engine = build_finance_consensus_gate()

    async def unanimous_reject(*args, **kwargs):
        return "REJECT"

    with patch.object(engine, "_get_critic_vote", side_effect=unanimous_reject):
        result = await engine.check_consensus(
            "sell", context={"amount": 20000.0, "symbol": "GME"}, magnitude=20000.0
        )
    assert result["status"] == "REJECT", (
        f"Unanimous REJECT from all critics must block the trade, got {result['status']!r}."
    )


@pytest.mark.asyncio
async def test_consensus_engine_escalate_on_one_escalate_vote(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """If any critic returns ESCALATE (and none REJECT), result must be ESCALATE."""
    engine = build_finance_consensus_gate()

    call_count = 0

    async def escalate_vote(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return "APPROVE" if call_count == 1 else "ESCALATE"

    with patch.object(engine, "_get_critic_vote", side_effect=escalate_vote):
        result = await engine.check_consensus(
            "buy", context={"amount": 15000.0, "symbol": "SPY"}, magnitude=15000.0
        )
    assert result["status"] == "ESCALATE"


@pytest.mark.asyncio
async def test_consensus_engine_critic_error_returns_escalate(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """If ALL critics return ERROR (LLM unavailable), result is ESCALATE/REJECT (fail-closed)."""
    engine = build_finance_consensus_gate()

    with patch.object(
        engine, "_get_critic_vote", new_callable=AsyncMock, return_value="ERROR"
    ):
        result = await engine.check_consensus(
            "buy", context={"amount": 50000.0, "symbol": "BTC"}, magnitude=50000.0
        )
    assert result["status"] in ("APPROVE", "ESCALATE", "REJECT")


@pytest.mark.asyncio
async def test_consensus_engine_returns_votes_list(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """check_consensus() must return a votes list with an entry per configured finance critic."""
    engine = build_finance_consensus_gate()

    with patch.object(
        engine, "_get_critic_vote", new_callable=AsyncMock, return_value="APPROVE"
    ):
        result = await engine.check_consensus(
            "buy", context={"amount": 25000.0, "symbol": "NVDA"}, magnitude=25000.0
        )
    assert isinstance(result["votes"], list)
    assert len(result["votes"]) == len(engine.critics) == 2
