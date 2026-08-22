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

"""Unit tests for JWKS multi-key support (Finding #9)."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ec_key_pair():
    """Generate an EC P-256 key pair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, public_pem


@pytest.fixture
def rsa_key_pair():
    """Generate an RSA 2048 key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, public_pem


@pytest.fixture
def ed25519_key_pair():
    """Generate an Ed25519 key pair for testing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, public_pem


# ---------------------------------------------------------------------------
# Tests for pem_to_jwk
# ---------------------------------------------------------------------------


class TestPemToJwk:
    """Tests for the pem_to_jwk function."""

    def test_ec_p256_key(self, ec_key_pair):
        """Test conversion of EC P-256 key to JWK."""
        from src.gateway.governance.jwks import pem_to_jwk

        _, _, pem = ec_key_pair
        jwk = pem_to_jwk(pem)

        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk
        assert "kid" in jwk
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "ES256"

    def test_rsa_key(self, rsa_key_pair):
        """Test conversion of RSA key to JWK."""
        from src.gateway.governance.jwks import pem_to_jwk

        _, _, pem = rsa_key_pair
        jwk = pem_to_jwk(pem)

        assert jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk
        assert "kid" in jwk
        assert jwk["use"] == "sig"
        assert jwk["alg"] in ("RS256", "RS384", "RS512")

    def test_ed25519_key(self, ed25519_key_pair):
        """Test conversion of Ed25519 key to JWK."""
        from src.gateway.governance.jwks import pem_to_jwk

        _, _, pem = ed25519_key_pair
        jwk = pem_to_jwk(pem)

        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk
        assert "kid" in jwk
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "EdDSA"

    def test_custom_kid(self, ec_key_pair):
        """Test that custom kid is used when provided."""
        from src.gateway.governance.jwks import pem_to_jwk

        _, _, pem = ec_key_pair
        custom_kid = "my-custom-key-id"
        jwk = pem_to_jwk(pem, kid=custom_kid)

        assert jwk["kid"] == custom_kid

    def test_kid_is_deterministic(self, ec_key_pair):
        """Test that kid is deterministic for the same key."""
        from src.gateway.governance.jwks import pem_to_jwk

        _, _, pem = ec_key_pair
        jwk1 = pem_to_jwk(pem)
        jwk2 = pem_to_jwk(pem)

        assert jwk1["kid"] == jwk2["kid"]


# ---------------------------------------------------------------------------
# Tests for JWKSet
# ---------------------------------------------------------------------------


class TestJWKSet:
    """Tests for the JWKSet class."""

    def test_add_key(self, ec_key_pair):
        """Test adding a key to the JWKSet."""
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        _, _, pem = ec_key_pair

        kid = jwks.add_key(pem)

        assert len(jwks) == 1
        assert jwks.get_key(kid) is not None
        assert jwks.get_pem(kid) == pem

    def test_multiple_keys(self, ec_key_pair, rsa_key_pair):
        """Test adding multiple keys to the JWKSet."""
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        _, _, ec_pem = ec_key_pair
        _, _, rsa_pem = rsa_key_pair

        ec_kid = jwks.add_key(ec_pem)
        rsa_kid = jwks.add_key(rsa_pem)

        assert len(jwks) == 2
        assert jwks.get_key(ec_kid)["kty"] == "EC"
        assert jwks.get_key(rsa_kid)["kty"] == "RSA"

    def test_max_keys_eviction(self, ec_key_pair):
        """Test that oldest keys are evicted when max is reached."""
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet(max_keys=2)

        # Generate 3 different keys
        kids = []
        for _i in range(3):
            private_key = ec.generate_private_key(ec.SECP256R1())
            pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            kid = jwks.add_key(pem)
            kids.append(kid)
            time.sleep(0.01)  # Ensure different timestamps

        assert len(jwks) == 2
        # First key should have been evicted
        assert jwks.get_key(kids[0]) is None
        assert jwks.get_key(kids[1]) is not None
        assert jwks.get_key(kids[2]) is not None

    def test_key_expiration(self, ec_key_pair):
        """Test that expired keys are removed."""
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        _, _, pem = ec_key_pair

        # Add key with very short expiration
        kid = jwks.add_key(pem, grace_period_s=0.01)

        # Key should be present initially
        assert jwks.get_key(kid) is not None

        # Wait for expiration
        time.sleep(0.02)

        # Key should be expired and removed
        assert jwks.get_key(kid) is None

    def test_rotate_key(self, ec_key_pair):
        """Test key rotation with grace period."""
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        _, _, old_pem = ec_key_pair

        # Add initial key
        old_kid = jwks.add_key(old_pem)

        # Generate new key
        new_private = ec.generate_private_key(ec.SECP256R1())
        new_pem = new_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Rotate to new key
        new_kid = jwks.rotate_key(new_pem, grace_period_s=3600)

        # Both keys should be present
        assert jwks.get_key(old_kid) is not None
        assert jwks.get_key(new_kid) is not None

    def test_to_dict(self, ec_key_pair, rsa_key_pair):
        """Test JWKSet export to dictionary."""
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        _, _, ec_pem = ec_key_pair
        _, _, rsa_pem = rsa_key_pair

        jwks.add_key(ec_pem)
        jwks.add_key(rsa_pem)

        jwks_dict = jwks.to_dict()

        assert "keys" in jwks_dict
        assert len(jwks_dict["keys"]) == 2

    def test_remove_key(self, ec_key_pair):
        """Test key removal."""
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        _, _, pem = ec_key_pair

        kid = jwks.add_key(pem)
        assert len(jwks) == 1

        result = jwks.remove_key(kid)
        assert result is True
        assert len(jwks) == 0

        # Removing non-existent key returns False
        result = jwks.remove_key("non-existent")
        assert result is False


# ---------------------------------------------------------------------------
# Tests for JWT kid extraction
# ---------------------------------------------------------------------------


class TestJWTKidExtraction:
    """Tests for extracting kid from JWT headers."""

    def test_extract_kid_from_valid_jwt(self):
        """Test extracting kid from a valid JWT header."""
        from src.gateway.governance.jwks import extract_kid_from_jwt

        # Create a mock JWT with kid in header
        header = {"alg": "ES256", "typ": "JWT", "kid": "test-key-id"}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        payload_b64 = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        kid = extract_kid_from_jwt(token)

        assert kid == "test-key-id"

    def test_extract_kid_missing(self):
        """Test extracting kid when not present in header."""
        from src.gateway.governance.jwks import extract_kid_from_jwt

        # Create a mock JWT without kid
        header = {"alg": "ES256", "typ": "JWT"}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        payload_b64 = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        kid = extract_kid_from_jwt(token)

        assert kid is None

    def test_extract_kid_invalid_token(self):
        """Test extracting kid from invalid token format."""
        from src.gateway.governance.jwks import extract_kid_from_jwt

        # Not a JWT (wrong number of parts)
        assert extract_kid_from_jwt("not-a-jwt") is None
        assert extract_kid_from_jwt("only.two") is None

        # Invalid base64
        assert extract_kid_from_jwt("!!!.payload.sig") is None


# ---------------------------------------------------------------------------
# Tests for verification key lookup
# ---------------------------------------------------------------------------


class TestVerificationKeyLookup:
    """Tests for get_verification_key_for_jwt."""

    def test_lookup_with_kid(self, ec_key_pair):
        """Test key lookup with kid in JWT header."""
        from src.gateway.governance.jwks import (
            JWKSet,
            _compute_kid,
            extract_kid_from_jwt,
            get_verification_key_for_jwt,
        )

        _, _, pem = ec_key_pair

        # Create JWKSet with the key
        jwks = JWKSet()
        kid = jwks.add_key(pem)

        # Create a mock JWT with this kid
        header = {"alg": "ES256", "typ": "JWT", "kid": kid}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        payload_b64 = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Mock the global JWKS
        with patch("src.gateway.governance.jwks.get_jwks", return_value=jwks):
            result_pem = get_verification_key_for_jwt(token)

        assert result_pem == pem

    def test_lookup_single_key_no_kid(self, ec_key_pair):
        """Test key lookup when JWT has no kid but JWKSet has single key."""
        from src.gateway.governance.jwks import (
            JWKSet,
            get_verification_key_for_jwt,
        )

        _, _, pem = ec_key_pair

        # Create JWKSet with single key
        jwks = JWKSet()
        jwks.add_key(pem)

        # Create a mock JWT without kid
        header = {"alg": "ES256", "typ": "JWT"}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        payload_b64 = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Mock the global JWKS
        with patch("src.gateway.governance.jwks.get_jwks", return_value=jwks):
            result_pem = get_verification_key_for_jwt(token)

        assert result_pem == pem

    def test_lookup_multiple_keys_no_kid(self, ec_key_pair, rsa_key_pair):
        """Test key lookup fails when JWT has no kid and JWKSet has multiple keys."""
        from src.gateway.governance.jwks import (
            JWKSet,
            get_verification_key_for_jwt,
        )

        _, _, ec_pem = ec_key_pair
        _, _, rsa_pem = rsa_key_pair

        # Create JWKSet with multiple keys
        jwks = JWKSet()
        jwks.add_key(ec_pem)
        jwks.add_key(rsa_pem)

        # Create a mock JWT without kid
        header = {"alg": "ES256", "typ": "JWT"}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        payload_b64 = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Mock the global JWKS
        with patch("src.gateway.governance.jwks.get_jwks", return_value=jwks):
            result_pem = get_verification_key_for_jwt(token)

        # Should return None because we can't determine which key to use
        assert result_pem is None
