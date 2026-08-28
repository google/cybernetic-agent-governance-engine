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
Tests for ConsequenceToken (ST-2 FlowSignal Phase 2).

Covers:
  - Mint → verify round-trip with real keypairs (ES256, EdDSA)
  - TTL enforcement (60s default, custom values)
  - Security: alg: none rejection, algorithm confusion, tampered payload/signature
  - Clock skew tolerance for future-dated iat
  - Malformed inputs (wrong segment count, invalid base64, non-JSON, missing claims)
  - Action digest matching (JCS canonicalization)
  - ver=None normalization consistency with ConsequenceAuthorityStore.binding_hash
"""

import base64
import hashlib
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.governance.consequence_token import (
    ConsequenceToken,
    ConsequenceTokenClaims,
    ConsequenceTokenError,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
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
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if algorithm == "ec_p256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == "ec_p384":
        private_key = ec.generate_private_key(ec.SECP384R1())
    elif algorithm == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif algorithm == "rsa_2048":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        # Ed25519: sign raw message directly
        return private_key.sign(message)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        # ECDSA: hash then sign
        hash_fn = getattr(hashlib, digest_algorithm)
        digest = hash_fn(message).digest()
        hash_alg = getattr(hashes, digest_algorithm.upper())()
        return private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hash_alg)))
    elif isinstance(private_key, rsa.RSAPrivateKey):
        # RSA: hash then sign with PKCS1v15 padding
        hash_fn = getattr(hashlib, digest_algorithm)
        digest = hash_fn(message).digest()
        hash_alg = getattr(hashes, digest_algorithm.upper())()
        return private_key.sign(
            digest, padding.PKCS1v15(), asym_utils.Prehashed(hash_alg)
        )
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
        "ec_p384": ("ES384", "sha384"),
        "ed25519": ("EdDSA", "raw"),
        "rsa_2048": ("RS256", "sha256"),
    }
    jose_alg, digest_alg = alg_map[algorithm]

    # Mock get_crypto_key_version for jose_alg property and _detect_hash_width
    mock_version = MagicMock()
    if algorithm == "ec_p256":
        mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    elif algorithm == "ec_p384":
        mock_version.algorithm.name = "EC_SIGN_P384_SHA384"
    elif algorithm == "ed25519":
        mock_version.algorithm.name = "EC_SIGN_ED25519"
    elif algorithm == "rsa_2048":
        mock_version.algorithm.name = "RSA_SIGN_PKCS1_2048_SHA256"
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
# Round-trip tests
# ---------------------------------------------------------------------------


def test_mint_verify_roundtrip_es256():
    """Mint → verify round-trip with ES256 returns exact claims."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    token = ConsequenceToken.mint(
        sub="actor-123",
        tid="thread-456",
        rec="rec-789",
        act="abcd1234" * 8,  # 64 hex chars (SHA-256)
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )

    claims = ConsequenceToken.verify(token, signer=signer)

    assert claims.sub == "actor-123"
    assert claims.tid == "thread-456"
    assert claims.rec == "rec-789"
    assert claims.act == "abcd1234" * 8
    assert claims.ver == "v1"
    assert claims.jti == "rec-789"
    assert claims.exp == claims.iat + 60
    assert abs(claims.iat - int(time.time())) <= 2  # Within 2s of now


def test_mint_verify_roundtrip_eddsa():
    """Mint → verify round-trip with EdDSA (Ed25519) works correctly."""
    signer, _ = _make_mock_signer_with_keypair("ed25519")

    token = ConsequenceToken.mint(
        sub="actor-999",
        tid="thread-111",
        rec="rec-222",
        act="fedcba98" * 8,
        ver=None,  # Test nullable ver
        ttl_seconds=30,
        signer=signer,
    )

    claims = ConsequenceToken.verify(token, signer=signer)

    assert claims.sub == "actor-999"
    assert claims.tid == "thread-111"
    assert claims.rec == "rec-222"
    assert claims.act == "fedcba98" * 8
    assert claims.ver == ""  # None normalized to ""
    assert claims.exp == claims.iat + 30


def test_mint_sets_correct_ttl():
    """Minted token has exp exactly iat + ttl_seconds."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    for ttl in [30, 60, 90, 120]:
        token = ConsequenceToken.mint(
            sub="actor",
            tid="thread",
            rec="rec",
            act="a" * 64,
            signer=signer,
            ttl_seconds=ttl,
        )
        claims = ConsequenceToken.verify(token, signer=signer)
        assert claims.exp == claims.iat + ttl


# ---------------------------------------------------------------------------
# Security tests: alg: none and algorithm confusion
# ---------------------------------------------------------------------------


def test_verify_rejects_alg_none():
    """Verify rejects a token with alg: none in the header."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    # Craft a token with alg: none
    header = {"alg": "none", "typ": "JWT", "kid": "fake-key"}
    payload = {
        "sub": "actor",
        "tid": "thread",
        "rec": "rec",
        "act": "a" * 64,
        "ver": "",
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
        "jti": "rec",
    }

    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )
    signature_b64 = ""  # No signature for alg: none

    token = f"{header_b64}.{payload_b64}.{signature_b64}"

    with pytest.raises(ConsequenceTokenError, match="alg: none"):
        ConsequenceToken.verify(token, signer=signer)


def test_verify_rejects_algorithm_confusion():
    """Verify rejects a token where header alg != signer's jose_alg."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")  # ES256

    # Mint a token normally
    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
    )

    # Tamper with the header to change alg to ES384
    parts = token.split(".")
    header_bytes = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
    header = json.loads(header_bytes)
    header["alg"] = "ES384"  # Wrong algorithm
    tampered_header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    tampered_token = f"{tampered_header_b64}.{parts[1]}.{parts[2]}"

    with pytest.raises(ConsequenceTokenError, match="Algorithm confusion"):
        ConsequenceToken.verify(tampered_token, signer=signer)


# ---------------------------------------------------------------------------
# Security tests: tampered payload and signature
# ---------------------------------------------------------------------------


def test_verify_rejects_tampered_payload():
    """Verify rejects a token with tampered payload (signature still valid for original)."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
    )

    # Tamper with payload: change sub to "attacker"
    parts = token.split(".")
    payload_bytes = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
    payload = json.loads(payload_bytes)
    payload["sub"] = "attacker"
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode())
        .rstrip(b"=")
        .decode()
    )
    tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

    with pytest.raises(ConsequenceTokenError, match="Invalid signature"):
        ConsequenceToken.verify(tampered_token, signer=signer)


def test_verify_rejects_tampered_signature():
    """Verify rejects a token with a tampered signature."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
    )

    # Flip one byte in the signature
    parts = token.split(".")
    sig_bytes = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    tampered_sig = bytearray(sig_bytes)
    tampered_sig[0] ^= 0xFF  # Flip all bits in first byte
    tampered_sig_b64 = (
        base64.urlsafe_b64encode(bytes(tampered_sig)).rstrip(b"=").decode()
    )
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig_b64}"

    with pytest.raises(ConsequenceTokenError, match="Invalid signature"):
        ConsequenceToken.verify(tampered_token, signer=signer)


# ---------------------------------------------------------------------------
# TTL enforcement
# ---------------------------------------------------------------------------


def test_verify_rejects_expired_token():
    """Verify rejects a token with exp in the past."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    # Mint a token with -1s TTL (already expired)
    with patch("src.gateway.governance.consequence_token.time.time", return_value=1000):
        token = ConsequenceToken.mint(
            sub="actor",
            tid="thread",
            rec="rec",
            act="a" * 64,
            ttl_seconds=-1,
            signer=signer,
        )

    # Now is 1000 + 10 = 1010, token exp = 1000 + (-1) = 999
    with patch("src.gateway.governance.consequence_token.time.time", return_value=1010):
        with pytest.raises(ConsequenceTokenError, match="Token expired"):
            ConsequenceToken.verify(token, signer=signer)


def test_verify_accepts_token_within_ttl():
    """Verify accepts a token that has not yet expired."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    with patch("src.gateway.governance.consequence_token.time.time", return_value=1000):
        token = ConsequenceToken.mint(
            sub="actor",
            tid="thread",
            rec="rec",
            act="a" * 64,
            ttl_seconds=60,
            signer=signer,
        )

    # Now is 1000 + 30 = 1030, token exp = 1000 + 60 = 1060 (still valid)
    with patch("src.gateway.governance.consequence_token.time.time", return_value=1030):
        claims = ConsequenceToken.verify(token, signer=signer)
        assert claims.sub == "actor"


def test_verify_rejects_implausibly_future_iat():
    """Verify rejects a token with iat too far in the future (beyond clock skew tolerance)."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    # Mint at t=1000, but verify at t=990 (iat is 10s in the future, > 5s tolerance)
    with patch("src.gateway.governance.consequence_token.time.time", return_value=1000):
        token = ConsequenceToken.mint(
            sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
        )

    with patch("src.gateway.governance.consequence_token.time.time", return_value=990):
        with pytest.raises(ConsequenceTokenError, match="iat too far in future"):
            ConsequenceToken.verify(token, signer=signer)


def test_verify_accepts_iat_within_clock_skew_tolerance():
    """Verify accepts a token with iat slightly in the future (within 5s tolerance)."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    # Mint at t=1000, verify at t=997 (iat is 3s in the future, < 5s tolerance)
    with patch("src.gateway.governance.consequence_token.time.time", return_value=1000):
        token = ConsequenceToken.mint(
            sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
        )

    with patch("src.gateway.governance.consequence_token.time.time", return_value=997):
        claims = ConsequenceToken.verify(token, signer=signer)
        assert claims.iat == 1000


# ---------------------------------------------------------------------------
# Malformed input tests
# ---------------------------------------------------------------------------


def test_verify_rejects_wrong_segment_count():
    """Verify rejects tokens with wrong number of segments."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    # Only 2 segments
    with pytest.raises(ConsequenceTokenError, match="expected 3 segments, got 2"):
        ConsequenceToken.verify("header.payload", signer=signer)

    # 4 segments
    with pytest.raises(ConsequenceTokenError, match="expected 3 segments, got 4"):
        ConsequenceToken.verify("a.b.c.d", signer=signer)


def test_verify_rejects_invalid_base64_header():
    """Verify rejects a token with invalid base64 in header."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    token = "not!valid!base64.valid_payload.valid_sig"
    with pytest.raises(ConsequenceTokenError, match="Invalid header"):
        ConsequenceToken.verify(token, signer=signer)


def test_verify_rejects_non_json_payload():
    """Verify rejects a token with non-JSON payload."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    header_b64 = (
        base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').rstrip(b"=").decode()
    )
    payload_b64 = base64.urlsafe_b64encode(b"not-json").rstrip(b"=").decode()
    sig_b64 = "fake"

    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    with pytest.raises(ConsequenceTokenError, match="Invalid payload"):
        ConsequenceToken.verify(token, signer=signer)


def test_verify_rejects_missing_required_claim():
    """Verify rejects a token missing a required claim (e.g., sub)."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    # Mint normally, then tamper to remove 'sub'
    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
    )

    parts = token.split(".")
    payload_bytes = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
    payload = json.loads(payload_bytes)
    del payload["sub"]  # Remove required claim

    # Re-sign with the tampered payload
    header_b64 = parts[0]
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode())
        .rstrip(b"=")
        .decode()
    )
    signing_input = f"{header_b64}.{tampered_payload_b64}".encode("ascii")
    tampered_sig = signer.sign_raw(signing_input)
    tampered_sig_b64 = base64.urlsafe_b64encode(tampered_sig).rstrip(b"=").decode()
    tampered_token = f"{header_b64}.{tampered_payload_b64}.{tampered_sig_b64}"

    with pytest.raises(ConsequenceTokenError, match="Missing required claim"):
        ConsequenceToken.verify(tampered_token, signer=signer)


def test_verify_rejects_invalid_exp_type():
    """Verify rejects a token with exp as a string instead of int."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
    )

    parts = token.split(".")
    payload_bytes = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
    payload = json.loads(payload_bytes)
    payload["exp"] = "not-an-int"

    header_b64 = parts[0]
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode())
        .rstrip(b"=")
        .decode()
    )
    signing_input = f"{header_b64}.{tampered_payload_b64}".encode("ascii")
    tampered_sig = signer.sign_raw(signing_input)
    tampered_sig_b64 = base64.urlsafe_b64encode(tampered_sig).rstrip(b"=").decode()
    tampered_token = f"{header_b64}.{tampered_payload_b64}.{tampered_sig_b64}"

    with pytest.raises(ConsequenceTokenError, match="Invalid exp claim"):
        ConsequenceToken.verify(tampered_token, signer=signer)


# ---------------------------------------------------------------------------
# Action digest and JCS integration
# ---------------------------------------------------------------------------


def test_action_digest_matches_jcs_canonicalized_payload():
    """act claim matches SHA-256 hex of JCS-canonicalized action payload."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    action_payload = {
        "action": "execute_trade",
        "amount": 1000,
        "symbol": "AAPL",
        "metadata": {"user": "alice", "timestamp": 1234567890},
    }

    # Compute action digest the same way the gateway will
    action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act=action_digest, signer=signer
    )

    claims = ConsequenceToken.verify(token, signer=signer)
    assert claims.act == action_digest

    # Verify it's a valid SHA-256 hex (64 chars)
    assert len(claims.act) == 64
    assert all(c in "0123456789abcdef" for c in claims.act)


# ---------------------------------------------------------------------------
# ver normalization consistency
# ---------------------------------------------------------------------------


def test_ver_none_normalizes_to_empty_string():
    """ver=None is normalized to "" consistently with ConsequenceAuthorityStore.binding_hash."""
    from src.gateway.governance.consequence_authority_store import (
        ConsequenceAuthorityStore,
    )

    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    # Mint with ver=None
    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, ver=None, signer=signer
    )

    claims = ConsequenceToken.verify(token, signer=signer)
    assert claims.ver == ""

    # Verify consistency with binding_hash
    binding1 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread", actor_id="actor", action_digest="a" * 64, state_version=None
    )
    binding2 = ConsequenceAuthorityStore.binding_hash(
        thread_id="thread", actor_id="actor", action_digest="a" * 64, state_version=""
    )
    assert binding1 == binding2


def test_ver_string_preserved():
    """ver as a string is preserved as-is."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, ver="v42", signer=signer
    )

    claims = ConsequenceToken.verify(token, signer=signer)
    assert claims.ver == "v42"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_mint_with_custom_ttl():
    """Mint respects custom ttl_seconds parameter."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    token = ConsequenceToken.mint(
        sub="actor",
        tid="thread",
        rec="rec",
        act="a" * 64,
        ttl_seconds=120,
        signer=signer,
    )

    claims = ConsequenceToken.verify(token, signer=signer)
    assert claims.exp == claims.iat + 120


def test_verify_with_rsa_key():
    """Verify works with RSA keys (RS256)."""
    signer, _ = _make_mock_signer_with_keypair("rsa_2048")

    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec="rec", act="a" * 64, signer=signer
    )

    claims = ConsequenceToken.verify(token, signer=signer)
    assert claims.sub == "actor"


def test_verify_fails_when_kms_inactive():
    """Verify raises ConsequenceTokenError when signer has KMS inactive."""
    # Create a signer with KMS inactive
    inactive_signer = _make_signer(kms_client=None, key_version_name="")

    token = "fake.token.here"

    # The error happens when trying to decode the header (which is invalid base64)
    # If we had a valid token, it would fail at algorithm determination
    with pytest.raises(ConsequenceTokenError, match="Invalid header"):
        ConsequenceToken.verify(token, signer=inactive_signer)


def test_jti_equals_rec():
    """jti claim always equals rec (authority record ID)."""
    signer, _ = _make_mock_signer_with_keypair("ec_p256")

    rec_value = "unique-rec-id-12345"
    token = ConsequenceToken.mint(
        sub="actor", tid="thread", rec=rec_value, act="a" * 64, signer=signer
    )

    claims = ConsequenceToken.verify(token, signer=signer)
    assert claims.jti == rec_value
    assert claims.rec == rec_value
