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
Unit tests for DPoP validator.

Tests RFC 9449 proof-of-possession validation and mTLS certificate binding.
"""

import base64
import json
import time
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.gateway.server.dpop_validator import DPoPValidator, TokenBindingError

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestDPoPValidator:
    """Test suite for DPoP validator."""

    @pytest.fixture
    def validator(self):
        """Create DPoP validator instance."""
        return DPoPValidator(max_age_seconds=60)

    @pytest.fixture
    def test_keypair(self):
        """Generate test RSA keypair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @pytest.fixture
    def test_cert_pem(self, test_keypair):
        """Generate test X.509 certificate."""
        private_key, public_key = test_keypair

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Client"),
                x509.NameAttribute(NameOID.COMMON_NAME, "testclient.example.com"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def _create_dpop_jwt(
        self, private_key, public_key, htm: str, htu: str, iat: int, jti: str
    ) -> str:
        """Create a test DPoP JWT."""
        # Build JWK from public key
        public_numbers = public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": self._base64url_encode(
                public_numbers.n.to_bytes(
                    (public_numbers.n.bit_length() + 7) // 8, "big"
                )
            ),
            "e": self._base64url_encode(
                public_numbers.e.to_bytes(
                    (public_numbers.e.bit_length() + 7) // 8, "big"
                )
            ),
        }

        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": jwk,
        }

        payload = {
            "htm": htm,
            "htu": htu,
            "iat": iat,
            "jti": jti,
        }

        # Create unsigned JWT (signature validation not implemented in this basic version)
        header_b64 = self._base64url_encode(json.dumps(header).encode("utf-8"))
        payload_b64 = self._base64url_encode(json.dumps(payload).encode("utf-8"))
        signature_b64 = self._base64url_encode(b"fake_signature")  # Placeholder

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def _base64url_encode(self, data: bytes) -> str:
        """Encode bytes to base64url."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @pytest.mark.asyncio
    async def test_valid_dpop_proof(self, validator, test_keypair, test_cert_pem):
        """Test happy-path: valid DPoP proof bound to matching client certificate."""
        private_key, public_key = test_keypair

        current_time = int(time.time())
        dpop_proof = self._create_dpop_jwt(
            private_key=private_key,
            public_key=public_key,
            htm="POST",
            htu="https://api.example.com/resource",
            iat=current_time,
            jti="unique-token-id-123",
        )

        result = await validator.validate_token_binding(
            dpop_proof=dpop_proof,
            client_cert_pem=test_cert_pem,
            expected_uri="https://api.example.com/resource",
            http_method="POST",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_mismatched_public_key(self, validator, test_keypair, test_cert_pem):
        """Test fail-closed: reject DPoP proof with different public key."""
        # Generate different keypair for DPoP proof
        different_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        different_public_key = different_private_key.public_key()

        current_time = int(time.time())
        dpop_proof = self._create_dpop_jwt(
            private_key=different_private_key,
            public_key=different_public_key,
            htm="POST",
            htu="https://api.example.com/resource",
            iat=current_time,
            jti="unique-token-id-456",
        )

        with pytest.raises(TokenBindingError, match="Public key mismatch"):
            await validator.validate_token_binding(
                dpop_proof=dpop_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )

    @pytest.mark.asyncio
    async def test_expired_proof(self, validator, test_keypair, test_cert_pem):
        """Test fail-closed: reject expired DPoP proof (timestamp skew > 60s)."""
        private_key, public_key = test_keypair

        # Create proof with timestamp 120 seconds in the past
        old_time = int(time.time()) - 120
        dpop_proof = self._create_dpop_jwt(
            private_key=private_key,
            public_key=public_key,
            htm="POST",
            htu="https://api.example.com/resource",
            iat=old_time,
            jti="unique-token-id-789",
        )

        with pytest.raises(TokenBindingError, match="DPoP proof expired"):
            await validator.validate_token_binding(
                dpop_proof=dpop_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )

    @pytest.mark.asyncio
    async def test_uri_mismatch(self, validator, test_keypair, test_cert_pem):
        """Test fail-closed: reject DPoP proof with mismatched URI (htu claim)."""
        private_key, public_key = test_keypair

        current_time = int(time.time())
        dpop_proof = self._create_dpop_jwt(
            private_key=private_key,
            public_key=public_key,
            htm="POST",
            htu="https://attacker.example.com/evil",
            iat=current_time,
            jti="unique-token-id-999",
        )

        with pytest.raises(TokenBindingError, match="URI mismatch"):
            await validator.validate_token_binding(
                dpop_proof=dpop_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )

    @pytest.mark.asyncio
    async def test_http_method_mismatch(self, validator, test_keypair, test_cert_pem):
        """Test fail-closed: reject DPoP proof with mismatched HTTP method."""
        private_key, public_key = test_keypair

        current_time = int(time.time())
        dpop_proof = self._create_dpop_jwt(
            private_key=private_key,
            public_key=public_key,
            htm="GET",
            htu="https://api.example.com/resource",
            iat=current_time,
            jti="unique-token-id-111",
        )

        with pytest.raises(TokenBindingError, match="HTTP method mismatch"):
            await validator.validate_token_binding(
                dpop_proof=dpop_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )

    @pytest.mark.asyncio
    async def test_jti_replay_protection(self, validator, test_keypair, test_cert_pem):
        """Test fail-closed: reject replayed JTI."""
        private_key, public_key = test_keypair

        current_time = int(time.time())
        dpop_proof = self._create_dpop_jwt(
            private_key=private_key,
            public_key=public_key,
            htm="POST",
            htu="https://api.example.com/resource",
            iat=current_time,
            jti="replay-token-id",
        )

        # First use should succeed
        await validator.validate_token_binding(
            dpop_proof=dpop_proof,
            client_cert_pem=test_cert_pem,
            expected_uri="https://api.example.com/resource",
            http_method="POST",
        )

        # Second use with same JTI should fail
        with pytest.raises(TokenBindingError, match="JTI replay detected"):
            await validator.validate_token_binding(
                dpop_proof=dpop_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )

    @pytest.mark.asyncio
    async def test_malformed_jwt(self, validator, test_cert_pem):
        """Test fail-closed: reject malformed JWT structure."""
        malformed_proof = "invalid.jwt"

        with pytest.raises(TokenBindingError, match="Invalid DPoP JWT format"):
            await validator.validate_token_binding(
                dpop_proof=malformed_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )

    @pytest.mark.asyncio
    async def test_missing_required_claims(
        self, validator, test_keypair, test_cert_pem
    ):
        """Test fail-closed: reject JWT missing required claims."""
        _private_key, public_key = test_keypair
        public_numbers = public_key.public_numbers()

        jwk = {
            "kty": "RSA",
            "n": self._base64url_encode(
                public_numbers.n.to_bytes(
                    (public_numbers.n.bit_length() + 7) // 8, "big"
                )
            ),
            "e": self._base64url_encode(
                public_numbers.e.to_bytes(
                    (public_numbers.e.bit_length() + 7) // 8, "big"
                )
            ),
        }

        header = {"typ": "dpop+jwt", "alg": "RS256", "jwk": jwk}
        payload = {"htm": "POST"}  # Missing htu, iat, jti

        header_b64 = self._base64url_encode(json.dumps(header).encode("utf-8"))
        payload_b64 = self._base64url_encode(json.dumps(payload).encode("utf-8"))
        signature_b64 = self._base64url_encode(b"fake_signature")

        dpop_proof = f"{header_b64}.{payload_b64}.{signature_b64}"

        with pytest.raises(TokenBindingError, match="Missing required DPoP claim"):
            await validator.validate_token_binding(
                dpop_proof=dpop_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )

    @pytest.mark.asyncio
    async def test_future_timestamp(self, validator, test_keypair, test_cert_pem):
        """Test fail-closed: reject DPoP proof with timestamp in the future."""
        private_key, public_key = test_keypair

        # Create proof with timestamp 10 seconds in the future
        future_time = int(time.time()) + 10
        dpop_proof = self._create_dpop_jwt(
            private_key=private_key,
            public_key=public_key,
            htm="POST",
            htu="https://api.example.com/resource",
            iat=future_time,
            jti="future-token-id",
        )

        with pytest.raises(TokenBindingError, match="timestamp is in the future"):
            await validator.validate_token_binding(
                dpop_proof=dpop_proof,
                client_cert_pem=test_cert_pem,
                expected_uri="https://api.example.com/resource",
                http_method="POST",
            )
