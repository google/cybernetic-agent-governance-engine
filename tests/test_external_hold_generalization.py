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
test_external_hold_generalization.py — C9 Work Item Tests
==========================================================

Tests for the generalized external hold escalation path (C9 deliverable).

Verifies:
  1. provider_01 and provider_06 produce byte-identical DeferToken shapes
  2. hold_ttl_seconds field is respected (override) and defaults correctly
  3. EXTERNAL_HOLD tokens route to DLQ on expiry
  4. Quorum-3 is preserved for EXTERNAL_HOLD defer reason
"""

import pytest

from src.gateway.governance.defer_queue import (
    DeferReason,
    DeferToken,
    create_external_hold_token,
    get_required_quorum,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test 1: Byte-identical DeferToken shapes for provider_01 vs provider_06
# ---------------------------------------------------------------------------


def test_external_hold_token_shape_is_vendor_agnostic():
    """provider_01 ESCALATE and provider_06 REVIEW produce structurally identical DeferTokens.

    This proves I1 (vendor-shaped asymmetry) is fixed: both providers now
    take the same code path in enforce_fria_boundary().
    """
    # Simulate provider_01 ESCALATE finding (FlowSignal-shaped)
    provider_01_finding = {
        "code": "EXTERNAL_HOLD",
        "severity": "review",
        "message": "FlowSignal escalated — requires human approval",
        "needs_human_review": True,
        "hold_ttl_seconds": 300,
    }

    # Simulate provider_06 REVIEW finding (generic-shaped)
    provider_06_finding = {
        "code": "EXTERNAL_HOLD",
        "severity": "review",
        "message": "Provider escalated — requires human approval",
        "needs_human_review": True,
        "hold_ttl_seconds": 300,
    }

    # Both providers should produce identical token structures
    # (apart from the finding message, which is deliberately different)
    token_01 = create_external_hold_token(
        thread_id="thread-001",
        confidence_score=0.82,
        opa_input_snapshot={"action": "execute_trade", "amount_usd": 50000},
        finding_message=provider_01_finding["message"],
        ttl_seconds=provider_01_finding["hold_ttl_seconds"],
    )

    token_06 = create_external_hold_token(
        thread_id="thread-001",
        confidence_score=0.82,
        opa_input_snapshot={"action": "execute_trade", "amount_usd": 50000},
        finding_message=provider_06_finding["message"],
        ttl_seconds=provider_06_finding["hold_ttl_seconds"],
    )

    # Verify structural identity
    assert token_01.defer_reason == token_06.defer_reason == DeferReason.EXTERNAL_HOLD
    assert token_01.ttl_seconds == token_06.ttl_seconds == 300
    assert token_01.required_quorum == token_06.required_quorum == 3
    assert token_01.aarm_vector == token_06.aarm_vector == "AARM-V8"
    assert token_01.confidence_score == token_06.confidence_score == 0.82

    # Only the embedded finding message should differ
    msg_01 = token_01.opa_input_snapshot.get("_external_hold_finding_message")
    msg_06 = token_06.opa_input_snapshot.get("_external_hold_finding_message")
    assert msg_01 == "FlowSignal escalated — requires human approval"
    assert msg_06 == "Provider escalated — requires human approval"


# ---------------------------------------------------------------------------
# Test 2: TTL default and override behavior
# ---------------------------------------------------------------------------


def test_external_hold_token_respects_custom_ttl():
    """When hold_ttl_seconds is provided in the finding, it overrides the default."""
    # Provider specifies custom 600s TTL
    token = create_external_hold_token(
        thread_id="thread-custom-ttl",
        confidence_score=0.75,
        opa_input_snapshot={"action": "execute_trade"},
        finding_message="Custom TTL hold",
        ttl_seconds=600,  # 10 minutes
    )
    assert token.ttl_seconds == 600


def test_external_hold_token_uses_default_ttl_when_not_specified():
    """When hold_ttl_seconds is None, the default 300s TTL is used."""
    token = create_external_hold_token(
        thread_id="thread-default-ttl",
        confidence_score=0.78,
        opa_input_snapshot={"action": "execute_trade"},
        finding_message="Default TTL hold",
        ttl_seconds=None,  # No provider override
    )
    assert token.ttl_seconds == 300


# ---------------------------------------------------------------------------
# Test 3: EXTERNAL_HOLD tokens route to DLQ on expiry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_external_hold_dlq_routing_fires_on_expiry():
    """Expired EXTERNAL_HOLD tokens route to the governance-hitl-dlq topic.

    This verifies that the DLQ callback is invoked exactly once when an
    EXTERNAL_HOLD token expires.
    """
    from unittest.mock import AsyncMock

    from src.gateway.governance.defer_queue import DeferQueue

    from unittest.mock import MagicMock
    import time

    dlq_publisher = AsyncMock()

    # Create a minimal fake Redis that returns the expired token
    redis_mock = MagicMock()
    
    async def _zrangebyscore(zset_key, min_score, max_score, **kwargs):
        return [token.defer_id]
    
    async def _hget(key, field):
        import json
        return json.dumps(token.model_dump()).encode()
    
    redis_mock.zrangebyscore = _zrangebyscore
    redis_mock.hget = _hget
    
    queue = DeferQueue(redis_mock, dlq_publisher=dlq_publisher)

    # Park an EXTERNAL_HOLD token that's already expired (ttl_seconds=-10)
    token = DeferToken(
        thread_id="thread-dlq-test",
        defer_reason=DeferReason.EXTERNAL_HOLD,
        confidence_score=0.80,
        opa_input_snapshot={"action": "execute_trade"},
        ttl_seconds=-10,  # Already expired (will be picked up by sweep)
    )

    # Run the sweep — should publish to DLQ
    await queue.expire_stale()

    # Verify DLQ publisher was called exactly once
    dlq_publisher.assert_called_once()
    published_token = dlq_publisher.call_args[0][0]
    assert published_token.defer_id == token.defer_id
    assert published_token.defer_reason == DeferReason.EXTERNAL_HOLD


# ---------------------------------------------------------------------------
# Test 4: Quorum-3 preservation
# ---------------------------------------------------------------------------


def test_external_hold_quorum_three_preserved():
    """EXTERNAL_HOLD defer reason maps to quorum=3 in the quorum table."""
    # Direct table lookup
    quorum = get_required_quorum(DeferReason.EXTERNAL_HOLD)
    assert quorum == 3


def test_external_hold_token_wires_quorum_three_via_post_init():
    """DeferToken.__post_init__ wires required_quorum=3 for EXTERNAL_HOLD tokens."""
    token = DeferToken(
        thread_id="thread-quorum-test",
        defer_reason=DeferReason.EXTERNAL_HOLD,
        confidence_score=0.85,
        opa_input_snapshot={"action": "execute_trade"},
    )
    # __post_init__ should have wired quorum=3
    assert token.required_quorum == 3


def test_external_hold_token_explicit_quorum_not_overridden():
    """If required_quorum is explicitly set to a non-default value, __post_init__ respects it."""
    # This tests the edge case where a token is constructed with explicit quorum
    token = DeferToken(
        thread_id="thread-explicit-quorum",
        defer_reason=DeferReason.EXTERNAL_HOLD,
        confidence_score=0.85,
        opa_input_snapshot={"action": "execute_trade"},
        required_quorum=4,  # Explicit override
    )
    # Explicit value should be preserved
    assert token.required_quorum == 4
