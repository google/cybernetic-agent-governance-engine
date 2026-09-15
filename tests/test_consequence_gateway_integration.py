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
Integration tests for ConsequenceGateway blocking actuation.

Verifies that invalid or consumed consequence authority tokens block execution
before actuation reaches the ExecutionActuator (ADR-008 Phase 2).
"""

import hashlib
import time

import fakeredis.aioredis
import pytest

from src.gateway.governance.consequence_authority_store import (
    ConsequenceAuthorityStore,
)
from src.gateway.governance.consequence_gateway import (
    ConsequenceDecision,
    ConsequenceGateway,
)
from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from tests.test_consequence_gateway import _make_mock_signer_with_keypair

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_signer():
    """Mock KMSGovernanceSigner for test token signing."""
    signer_obj, _ = _make_mock_signer_with_keypair("ec_p256")
    return signer_obj


@pytest.fixture
async def consequence_store():
    """Fresh ConsequenceAuthorityStore for each test."""
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return ConsequenceAuthorityStore(fake_redis)


@pytest.mark.asyncio
async def test_consequence_gateway_blocks_invalid_token(consequence_store, mock_signer):
    """ConsequenceGateway blocks execution when token is invalid."""
    gateway = ConsequenceGateway(store=consequence_store, signer=mock_signer)

    action_payload = {
        "symbol": "AAPL",
        "amount": 100.0,
        "transaction_id": "test-123",
    }

    # Invalid token (malformed JWS)
    invalid_token = "invalid.token.signature"

    evaluation = await gateway.evaluate(invalid_token, action_payload)

    assert evaluation.decision == ConsequenceDecision.BLOCK
    assert evaluation.reason_code == "TOKEN_INVALID"


@pytest.mark.asyncio
async def test_consequence_gateway_blocks_consumed_token(
    consequence_store, mock_signer
):
    """ConsequenceGateway blocks replay of consumed tokens."""
    gateway = ConsequenceGateway(store=consequence_store, signer=mock_signer)

    action_payload = {
        "symbol": "AAPL",
        "amount": 100.0,
        "transaction_id": "test-123",
    }

    # Mint a valid consequence token
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    token_jws = ConsequenceToken.mint(
        signer=mock_signer,
        rec="test-receipt",
        tid="thread-123",
        sub="agent_001",
        act=action_digest,
        ver="1",
        ttl_seconds=300,
    )

    # First consumption should succeed
    eval1 = await gateway.evaluate(token_jws, action_payload)
    assert eval1.decision == ConsequenceDecision.EXECUTE
    assert eval1.reason_code == "OK"

    # Second consumption (replay) should be blocked
    eval2 = await gateway.evaluate(token_jws, action_payload)
    assert eval2.decision == ConsequenceDecision.BLOCK
    assert eval2.reason_code == "ALREADY_CONSUMED"


@pytest.mark.asyncio
async def test_consequence_gateway_blocks_action_binding_mismatch(
    consequence_store, mock_signer
):
    """ConsequenceGateway blocks when action payload doesn't match token."""
    gateway = ConsequenceGateway(store=consequence_store, signer=mock_signer)

    original_payload = {
        "symbol": "AAPL",
        "amount": 100.0,
        "transaction_id": "test-123",
    }

    # Token bound to original payload
    action_digest = hashlib.sha256(jcs_canonicalize_plan(original_payload)).hexdigest()

    token_jws = ConsequenceToken.mint(
        signer=mock_signer,
        rec="test-receipt",
        tid="thread-123",
        sub="agent_001",
        act=action_digest,
        ver="1",
        ttl_seconds=300,
    )

    # Attempt execution with different payload (TOCTOU attack)
    modified_payload = {
        "symbol": "AAPL",
        "amount": 500.0,  # Modified amount
        "transaction_id": "test-123",
    }

    evaluation = await gateway.evaluate(token_jws, modified_payload)

    assert evaluation.decision == ConsequenceDecision.BLOCK
    assert evaluation.reason_code == "ACTION_BINDING_MISMATCH"


@pytest.mark.asyncio
async def test_consequence_gateway_blocks_expired_token(consequence_store, mock_signer):
    """ConsequenceGateway blocks expired tokens."""
    gateway = ConsequenceGateway(store=consequence_store, signer=mock_signer)

    action_payload = {
        "symbol": "AAPL",
        "amount": 100.0,
        "transaction_id": "test-123",
    }

    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    # Mint token with 1-second TTL
    token_jws = ConsequenceToken.mint(
        signer=mock_signer,
        rec="test-receipt",
        tid="thread-123",
        sub="agent_001",
        act=action_digest,
        ver="1",
        ttl_seconds=1,  # Very short TTL
    )

    # Wait for token to expire
    time.sleep(2)

    evaluation = await gateway.evaluate(token_jws, action_payload)

    assert evaluation.decision == ConsequenceDecision.BLOCK
    assert evaluation.reason_code == "TOKEN_INVALID"
    assert "expired" in evaluation.detail.lower() or "ttl" in evaluation.detail.lower()


@pytest.mark.asyncio
async def test_consequence_gateway_success_path(consequence_store, mock_signer):
    """ConsequenceGateway permits valid, unconsumed tokens."""
    gateway = ConsequenceGateway(store=consequence_store, signer=mock_signer)

    action_payload = {
        "symbol": "AAPL",
        "amount": 100.0,
        "transaction_id": "test-123",
    }

    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    token_jws = ConsequenceToken.mint(
        signer=mock_signer,
        rec="test-receipt",
        tid="thread-123",
        sub="agent_001",
        act=action_digest,
        ver="1",
        ttl_seconds=300,
    )

    evaluation = await gateway.evaluate(token_jws, action_payload)

    assert evaluation.decision == ConsequenceDecision.EXECUTE
    assert evaluation.reason_code == "OK"
    assert evaluation.detail == ""
