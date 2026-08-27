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
Unit tests for ConsequenceGateway — Post-FRIA consequence evaluation gateway.

Covers all branches of the 6-step evaluation sequence:
  1. JWS signature verification (via ConsequenceToken.verify)
  2. TTL / expiry check
  3. Recompute JCS digest of the action payload
  4. Compare recomputed digest to the `act` claim
  5. Atomic single-use consumption (ConsequenceAuthorityStore)
  6. Emit EXECUTE / HOLD / BLOCK decision with reason code

Test cases:
  - Happy path: valid token + matching payload → EXECUTE / "OK"
  - Invalid/tampered/expired token → BLOCK / "TOKEN_INVALID"
  - alg: none token → BLOCK / "TOKEN_INVALID"
  - Action payload mutated after minting → BLOCK / "ACTION_BINDING_MISMATCH" (TOCTOU)
  - Replay: evaluate() twice with same token+payload → first EXECUTE, second BLOCK / "ALREADY_CONSUMED"
  - Binding mismatch: same rec consumed under different binding → BLOCK / "AUTHORITY_RECORD_BINDING_MISMATCH"
  - Redis failure (mock consume_once to raise) → BLOCK / "REDIS_ERROR", never EXECUTE
  - Concurrency: asyncio.gather() several evaluate() calls → exactly one EXECUTE
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip(
    "fakeredis", reason="fakeredis required for consequence_gateway tests"
)

import fakeredis.aioredis  # type: ignore[import]

from src.gateway.governance.consequence_authority_store import (
    ConsequenceAuthorityStore,
)
from src.gateway.governance.consequence_gateway import (
    ConsequenceDecision,
    ConsequenceEvaluation,
    ConsequenceGateway,
)
from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Helpers (copied from test_consequence_token.py for real keypair mocking)
# ---------------------------------------------------------------------------


def _make_signer(
    kms_client=None, key_version_name="", public_key_pem=b"", provider=None
):
    """Construct a KMSGovernanceSigner directly without touching env vars."""
    from src.gateway.governance.kms_signer import KMSGovernanceSigner

    return KMSGovernanceSigner(
        kms_client=kms_client,
        key_version_name=key_version_name,
        public_key_pem=public_key_pem,
        provider=provider,
    )


def _generate_keypair(algorithm="ec_p256"):
    """Generate a real keypair for testing.

    Returns:
        Tuple of (private_key, public_key_pem_bytes)
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if algorithm == "ec_p256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def _sign_with_private_key(private_key, message, digest_algorithm="sha256"):
    """Sign a message with a private key using the appropriate algorithm."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        # ECDSA: hash then sign
        hash_fn = getattr(hashlib, digest_algorithm)
        digest = hash_fn(message).digest()
        hash_alg = getattr(hashes, digest_algorithm.upper())()
        return private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hash_alg)))
    else:
        raise ValueError(f"Unknown private key type: {type(private_key)}")


def _make_mock_signer_with_keypair(algorithm="ec_p256"):
    """Create a mock signer with a real keypair for authentic sign/verify."""
    private_key, public_pem = _generate_keypair(algorithm)

    mock_client = MagicMock()
    key_name = "projects/test-proj/locations/us/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"

    # Map algorithm to JOSE alg and digest
    alg_map = {
        "ec_p256": ("ES256", "sha256"),
    }
    jose_alg, digest_alg = alg_map[algorithm]

    # Mock get_crypto_key_version for jose_alg property and _detect_hash_width
    mock_version = MagicMock()
    if algorithm == "ec_p256":
        mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    # Create provider - it will auto-detect hash width from the mocked algorithm
    from src.gateway.governance.kms_signer import GCPKMSProvider

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)

    # Create signer
    signer = _make_signer(
        kms_client=mock_client,
        key_version_name=key_name,
        public_key_pem=public_pem,
        provider=provider,
    )

    # Patch sign_raw to use the real private key
    def mock_sign_raw(message: bytes) -> bytes:
        return _sign_with_private_key(private_key, message, digest_alg)

    signer.sign_raw = mock_sign_raw

    return signer, jose_alg


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def redis_client() -> fakeredis.aioredis.FakeRedis:
    """A fresh in-memory async fakeredis instance per test."""
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
async def store(
    redis_client: fakeredis.aioredis.FakeRedis,
) -> ConsequenceAuthorityStore:
    """ConsequenceAuthorityStore with default 90s TTL."""
    return ConsequenceAuthorityStore(redis_client=redis_client, ttl_seconds=90)


@pytest.fixture
def signer():
    """Mock signer with real keypair (ES256)."""
    signer_obj, _ = _make_mock_signer_with_keypair("ec_p256")
    return signer_obj


@pytest.fixture
def gateway(store: ConsequenceAuthorityStore, signer) -> ConsequenceGateway:
    """ConsequenceGateway instance with fakeredis store and mock signer."""
    return ConsequenceGateway(store=store, signer=signer)


@pytest.fixture
def action_payload() -> dict:
    """Sample action payload for testing."""
    return {
        "action": "deploy_model",
        "model_id": "gemini-1.5-pro",
        "timestamp": 1234567890,
        "parameters": {"temperature": 0.7},
    }


# ---------------------------------------------------------------------------
# Test 1: Happy path — valid token + matching payload → EXECUTE / "OK"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_execute(
    gateway: ConsequenceGateway,
    signer,
    action_payload: dict,
) -> None:
    """Valid token with matching action payload returns EXECUTE / OK."""
    # Compute action digest
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    # Mint token
    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-001",
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # Evaluate
    result = await gateway.evaluate(token=token, action_payload=action_payload)

    assert result.decision == ConsequenceDecision.EXECUTE
    assert result.reason_code == "OK"
    assert result.detail == ""


# ---------------------------------------------------------------------------
# Test 2: Invalid token → BLOCK / "TOKEN_INVALID"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_token_block(
    gateway: ConsequenceGateway,
    action_payload: dict,
) -> None:
    """Malformed token returns BLOCK / TOKEN_INVALID."""
    # Not even a valid JWS structure (only 2 segments)
    invalid_token = "invalid.token"

    result = await gateway.evaluate(token=invalid_token, action_payload=action_payload)

    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "TOKEN_INVALID"
    assert "Malformed token" in result.detail


@pytest.mark.asyncio
async def test_expired_token_block(
    gateway: ConsequenceGateway,
    signer,
    action_payload: dict,
) -> None:
    """Expired token returns BLOCK / TOKEN_INVALID."""
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    # Mint with 0 TTL (immediately expired)
    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-002",
        act=action_digest,
        ver="v1",
        ttl_seconds=0,
        signer=signer,
    )

    # Wait 1 second to ensure expiry
    await asyncio.sleep(1)

    result = await gateway.evaluate(token=token, action_payload=action_payload)

    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "TOKEN_INVALID"
    assert "expired" in result.detail.lower()


@pytest.mark.asyncio
async def test_tampered_signature_block(
    gateway: ConsequenceGateway,
    signer,
    action_payload: dict,
) -> None:
    """Token with tampered signature returns BLOCK / TOKEN_INVALID."""
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-003",
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # Tamper with the signature (last segment)
    parts = token.split(".")
    tampered_sig = (
        base64.urlsafe_b64encode(b"tampered_signature").decode("ascii").rstrip("=")
    )
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    result = await gateway.evaluate(token=tampered_token, action_payload=action_payload)

    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "TOKEN_INVALID"
    assert "signature" in result.detail.lower() or "invalid" in result.detail.lower()


# ---------------------------------------------------------------------------
# Test 3: alg: none token → BLOCK / "TOKEN_INVALID"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alg_none_token_block(
    gateway: ConsequenceGateway,
    action_payload: dict,
) -> None:
    """Token with alg: none is rejected with BLOCK / TOKEN_INVALID."""
    # Craft a token with alg: none
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": "actor-123",
        "tid": "thread-456",
        "rec": "rec-004",
        "act": "a" * 64,
        "ver": "v1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
        "jti": "rec-004",
    }

    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode())
        .decode("ascii")
        .rstrip("=")
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode())
        .decode("ascii")
        .rstrip("=")
    )
    # alg: none token has no signature (or empty signature)
    alg_none_token = f"{header_b64}.{payload_b64}."

    result = await gateway.evaluate(token=alg_none_token, action_payload=action_payload)

    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "TOKEN_INVALID"
    assert "alg: none" in result.detail.lower() or "rejected" in result.detail.lower()


# ---------------------------------------------------------------------------
# Test 4: Action payload mutated after minting → BLOCK / "ACTION_BINDING_MISMATCH"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_action_binding_mismatch_toctou(
    gateway: ConsequenceGateway,
    signer,
) -> None:
    """Action payload mutated after token minting returns BLOCK / ACTION_BINDING_MISMATCH (TOCTOU)."""
    original_payload = {"action": "deploy_model", "model_id": "gemini-1.5-pro"}
    action_digest = hashlib.sha256(jcs_canonicalize_plan(original_payload)).hexdigest()

    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-005",
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # Mutate the payload before evaluation (TOCTOU attack simulation)
    mutated_payload = {"action": "deploy_model", "model_id": "evil-model"}

    result = await gateway.evaluate(token=token, action_payload=mutated_payload)

    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "ACTION_BINDING_MISMATCH"


# ---------------------------------------------------------------------------
# Test 5: Replay — evaluate() twice with same token → first EXECUTE, second BLOCK / "ALREADY_CONSUMED"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_already_consumed(
    gateway: ConsequenceGateway,
    signer,
    action_payload: dict,
) -> None:
    """Second evaluation with same token+payload returns BLOCK / ALREADY_CONSUMED."""
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-006",
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # First evaluation: should succeed
    result1 = await gateway.evaluate(token=token, action_payload=action_payload)
    assert result1.decision == ConsequenceDecision.EXECUTE
    assert result1.reason_code == "OK"

    # Second evaluation with same token: should be blocked (replay)
    result2 = await gateway.evaluate(token=token, action_payload=action_payload)
    assert result2.decision == ConsequenceDecision.BLOCK
    assert result2.reason_code == "ALREADY_CONSUMED"


# ---------------------------------------------------------------------------
# Test 6: Binding mismatch — same rec consumed under different binding → BLOCK / "AUTHORITY_RECORD_BINDING_MISMATCH"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_binding_mismatch_substitution_attack(
    gateway: ConsequenceGateway,
    signer,
    action_payload: dict,
) -> None:
    """Same rec consumed under different binding returns BLOCK / AUTHORITY_RECORD_BINDING_MISMATCH."""
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    # Mint first token
    token1 = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-007",
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # Consume with first binding
    result1 = await gateway.evaluate(token=token1, action_payload=action_payload)
    assert result1.decision == ConsequenceDecision.EXECUTE

    # Mint second token with SAME rec but DIFFERENT binding (different actor)
    token2 = ConsequenceToken.mint(
        sub="actor-999",  # Different actor → different binding
        tid="thread-456",
        rec="rec-007",  # Same rec
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # Try to consume with second binding: should be blocked (substitution attack)
    result2 = await gateway.evaluate(token=token2, action_payload=action_payload)
    assert result2.decision == ConsequenceDecision.BLOCK
    assert result2.reason_code == "AUTHORITY_RECORD_BINDING_MISMATCH"


# ---------------------------------------------------------------------------
# Test 7: Redis failure → BLOCK / "REDIS_ERROR"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_error_fail_closed(
    store: ConsequenceAuthorityStore,
    signer,
    action_payload: dict,
) -> None:
    """Redis error during consumption returns BLOCK / REDIS_ERROR (fail-closed)."""
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-008",
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # Mock consume_once to raise an exception (simulate Redis connection error)
    mock_store = AsyncMock(spec=ConsequenceAuthorityStore)
    mock_store.consume_once.side_effect = RuntimeError("Redis connection timeout")

    gateway_with_failing_redis = ConsequenceGateway(store=mock_store, signer=signer)

    result = await gateway_with_failing_redis.evaluate(
        token=token, action_payload=action_payload
    )

    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "REDIS_ERROR"
    assert "Redis connection timeout" in result.detail


# ---------------------------------------------------------------------------
# Test 8: Concurrency — asyncio.gather() multiple evaluate() calls → exactly one EXECUTE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrency_exactly_one_execute(
    gateway: ConsequenceGateway,
    signer,
    action_payload: dict,
) -> None:
    """Multiple concurrent evaluate() calls with same token → exactly one EXECUTE."""
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-009",
        act=action_digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    # Run 10 concurrent evaluations with the same token
    results = await asyncio.gather(
        *[
            gateway.evaluate(token=token, action_payload=action_payload)
            for _ in range(10)
        ]
    )

    # Exactly one should EXECUTE, the rest should BLOCK
    execute_count = sum(1 for r in results if r.decision == ConsequenceDecision.EXECUTE)
    block_count = sum(1 for r in results if r.decision == ConsequenceDecision.BLOCK)

    assert execute_count == 1, f"Expected exactly 1 EXECUTE, got {execute_count}"
    assert block_count == 9, f"Expected 9 BLOCK, got {block_count}"

    # All blocked results should be ALREADY_CONSUMED or AUTHORITY_RECORD_BINDING_MISMATCH
    blocked_results = [r for r in results if r.decision == ConsequenceDecision.BLOCK]
    for blocked in blocked_results:
        assert blocked.reason_code in (
            "ALREADY_CONSUMED",
            "AUTHORITY_RECORD_BINDING_MISMATCH",
        )
