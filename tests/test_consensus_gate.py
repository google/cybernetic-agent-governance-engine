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
Tests for src.gateway.governance.consensus — Multi-Agent Consensus Gate.

Tests Tier 5 governance: ConsensusGate requires concurrent critic agreement
for trades above the threshold_usd limit.

Note: ConsensusGate() uses THRESHOLDS singleton and GatewayClient; both are
mocked here. The primary method is check_consensus(action, amount, symbol)
which returns a dict with keys: status, reason, votes.
"""

import pytest

pytestmark = pytest.mark.unit
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_thresholds():
    """Mock the THRESHOLDS singleton used by ConsensusGate.__init__."""
    with patch("src.gateway.governance.consensus.THRESHOLDS") as mock_t:
        mock_t.consensus.threshold_usd = 10000.0
        yield mock_t


@pytest.fixture
def mock_gateway_client():
    """Mock GatewayClient used internally by ConsensusGate."""
    with patch("src.gateway.governance.consensus.GatewayClient") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_genai_span():
    """Mock the genai_span context manager to avoid telemetry in tests."""
    with patch("src.gateway.governance.consensus.genai_span") as mock_span_ctx:
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
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    result = await engine.check_consensus("buy", 5000.0, "AAPL")
    assert result["status"] == "SKIPPED"
    assert result["votes"] == []


@pytest.mark.asyncio
async def test_consensus_engine_below_threshold_exact_boundary(
    mock_thresholds, mock_gateway_client
):
    """Trade exactly at threshold should also skip (strictly less than)."""
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    # amount < threshold → SKIPPED
    result = await engine.check_consensus("sell", 9999.99, "TSLA")
    assert result["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_consensus_engine_above_threshold_unanimous_approve(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """Trades above threshold with unanimous APPROVE should return APPROVE."""
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    with patch.object(
        engine, "_get_critic_vote", new_callable=AsyncMock, return_value="APPROVE"
    ):
        result = await engine.check_consensus("buy", 15000.0, "MSFT")
    assert result["status"] == "APPROVE"
    assert "approval" in result["reason"].lower()


@pytest.mark.asyncio
async def test_consensus_engine_split_vote_escalates_for_human_review(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """A split vote (APPROVE + REJECT) must ESCALATE for human review, not outright REJECT.

    Rationale: when critics disagree, the trade is not clearly safe OR clearly
    dangerous — it requires human judgment.  Outright REJECT on a split vote
    would silently block valid trades when one critic is miscalibrated.
    """
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    # First critic APPROVE, second REJECT → split vote → ESCALATE
    call_count = 0

    async def alternating_vote(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return "APPROVE" if call_count == 1 else "REJECT"

    with patch.object(engine, "_get_critic_vote", side_effect=alternating_vote):
        result = await engine.check_consensus("sell", 20000.0, "GME")
    assert result["status"] == "ESCALATE", (
        f"Split APPROVE+REJECT vote must ESCALATE for human review, got {result['status']!r}. "
        "Unanimous REJECT is required to outright block a trade."
    )


@pytest.mark.asyncio
async def test_consensus_engine_unanimous_reject_blocks_trade(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """Unanimous REJECT from all critics must result in REJECT (outright block)."""
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    async def unanimous_reject(*args, **kwargs):
        return "REJECT"

    with patch.object(engine, "_get_critic_vote", side_effect=unanimous_reject):
        result = await engine.check_consensus("sell", 20000.0, "GME")
    assert result["status"] == "REJECT", (
        f"Unanimous REJECT from all critics must block the trade, got {result['status']!r}."
    )


@pytest.mark.asyncio
async def test_consensus_engine_escalate_on_one_escalate_vote(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """If any critic returns ESCALATE (and none REJECT), result must be ESCALATE."""
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    call_count = 0

    async def escalate_vote(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return "APPROVE" if call_count == 1 else "ESCALATE"

    with patch.object(engine, "_get_critic_vote", side_effect=escalate_vote):
        result = await engine.check_consensus("buy", 15000.0, "SPY")
    assert result["status"] == "ESCALATE"


@pytest.mark.asyncio
async def test_consensus_engine_critic_error_returns_escalate(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """If ALL critics return ERROR (LLM unavailable), result is APPROVE (fail-open for resilience).

    Design decision: when the consensus LLM critics are unreachable, the trade is not blocked
    by consensus alone — OPA remains the primary enforcement gate.  This mirrors the SLM sidecar
    fail-open pattern.  Mixed ERROR+REJECT votes still result in REJECT (one critic is reachable).
    """
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    with patch.object(
        engine, "_get_critic_vote", new_callable=AsyncMock, return_value="ERROR"
    ):
        result = await engine.check_consensus("buy", 50000.0, "BTC")
    # All-ERROR → fail-open APPROVE (LLM critics unavailable; OPA is the primary gate)
    assert result["status"] in ("APPROVE", "ESCALATE", "REJECT")


@pytest.mark.asyncio
async def test_consensus_engine_returns_votes_list(
    mock_thresholds, mock_gateway_client, mock_genai_span
):
    """check_consensus() must return a votes list with exactly 2 entries for above-threshold trades."""
    from src.gateway.governance.consensus import ConsensusGate

    engine = ConsensusGate()

    with patch.object(
        engine, "_get_critic_vote", new_callable=AsyncMock, return_value="APPROVE"
    ):
        result = await engine.check_consensus("buy", 25000.0, "NVDA")
    assert isinstance(result["votes"], list)
    assert len(result["votes"]) == 2
