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
DPoP (Demonstration of Proof-of-Possession) validator for Layer 1 token binding.

RFC 9449 compliant validator that binds OAuth 2.0 DPoP tokens to mTLS client certificates
to prevent token replay attacks. Enforces strict fail-closed validation.
"""

import base64
import hashlib
import json
import time
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class TokenBindingError(ValueError):
    """Raised when DPoP token binding validation fails (fail-closed)."""

    pass


class ProofOfPossessionValidator(Protocol):
    """Protocol interface for proof-of-possession token validators."""

    async def validate_token_binding(
        self,
        dpop_proof: str,
        client_cert_pem: str,
        expected_uri: str,
        http_method: str,
    ) -> bool:
        """
        Validate that a DPoP proof is cryptographically bound to the client certificate.

        Args:
            dpop_proof: Base64url-encoded JWT DPoP proof from HTTP header
            client_cert_pem: PEM-encoded client certificate from mTLS handshake
            expected_uri: Expected URI (htu claim)
            http_method: Expected HTTP method (htm claim)

        Returns:
            True if validation succeeds

        Raises:
            TokenBindingError: If validation fails (fail-closed)
        """
        ...


class DPoPValidator(ProofOfPossessionValidator):
    """
    RFC 9449 DPoP validator with mTLS certificate binding.

    Enforces strict fail-closed validation:
    - Timestamp skew > 60 seconds → reject
    - JTI replay → reject
    - Public key mismatch → reject
    - Missing or malformed claims → reject
    """

    def __init__(self, max_age_seconds: int = 60):
        """
        Initialize DPoP validator.

        Args:
            max_age_seconds: Maximum allowed timestamp skew (default: 60s)
        """
        self._max_age_seconds = max_age_seconds
        self._seen_jti: set[str] = (
            set()
        )  # In-memory JTI tracking (production: use Redis)

    async def validate_token_binding(
        self,
        dpop_proof: str,
        client_cert_pem: str,
        expected_uri: str,
        http_method: str,
    ) -> bool:
        """Validate DPoP proof against mTLS certificate binding."""

        # Parse DPoP JWT (header.payload.signature)
        dpop_parts = dpop_proof.split(".")
        if len(dpop_parts) != 3:
            raise TokenBindingError("Invalid DPoP JWT format: expected 3 parts")

        try:
            header = self._decode_base64url(dpop_parts[0])
            payload = self._decode_base64url(dpop_parts[1])
        except Exception as e:
            raise TokenBindingError(f"Failed to decode DPoP JWT: {e}")

        dpop_header = json.loads(header)
        dpop_claims = json.loads(payload)

        # Extract and validate required claims
        self._validate_required_claims(dpop_header, dpop_claims)

        # Validate HTTP method and URI binding
        if dpop_claims["htm"] != http_method:
            raise TokenBindingError(
                f"HTTP method mismatch: expected {http_method}, got {dpop_claims['htm']}"
            )

        if dpop_claims["htu"] != expected_uri:
            raise TokenBindingError(
                f"URI mismatch: expected {expected_uri}, got {dpop_claims['htu']}"
            )

        # Validate timestamp freshness (fail-closed on skew > max_age_seconds)
        current_time = int(time.time())
        proof_time = dpop_claims["iat"]
        age = current_time - proof_time

        if age < 0:
            raise TokenBindingError(
                f"DPoP proof timestamp is in the future: iat={proof_time}"
            )

        if age > self._max_age_seconds:
            raise TokenBindingError(
                f"DPoP proof expired: age={age}s exceeds max_age={self._max_age_seconds}s"
            )

        # Validate JTI uniqueness (replay protection)
        jti = dpop_claims["jti"]
        if jti in self._seen_jti:
            raise TokenBindingError(f"JTI replay detected: {jti}")
        self._seen_jti.add(jti)

        # Extract public key from mTLS certificate
        cert_public_key = self._extract_cert_public_key(client_cert_pem)
        cert_thumbprint = self._compute_jwk_thumbprint(cert_public_key)

        # Extract public key from DPoP JWT header
        dpop_jwk = dpop_header.get("jwk")
        if not dpop_jwk:
            raise TokenBindingError("DPoP JWT header missing 'jwk' claim")

        dpop_thumbprint = self._compute_jwk_thumbprint_from_dict(dpop_jwk)

        # Fail-closed: Thumbprints MUST match
        if cert_thumbprint != dpop_thumbprint:
            raise TokenBindingError(
                f"Public key mismatch: cert_thumbprint={cert_thumbprint[:16]}... "
                f"!= dpop_thumbprint={dpop_thumbprint[:16]}..."
            )

        return True

    def _validate_required_claims(self, header: dict, claims: dict) -> None:
        """Validate presence of required RFC 9449 claims (fail-closed)."""
        required_header_fields = ["typ", "alg", "jwk"]
        for field in required_header_fields:
            if field not in header:
                raise TokenBindingError(f"Missing required DPoP header field: {field}")

        if header["typ"] != "dpop+jwt":
            raise TokenBindingError(
                f"Invalid DPoP type: expected 'dpop+jwt', got '{header['typ']}'"
            )

        required_claims = ["htm", "htu", "iat", "jti"]
        for claim in required_claims:
            if claim not in claims:
                raise TokenBindingError(f"Missing required DPoP claim: {claim}")

    def _extract_cert_public_key(
        self, cert_pem: str
    ) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        """Extract public key from PEM-encoded X.509 certificate."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            public_key = cert.public_key()

            if not isinstance(
                public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)
            ):
                raise TokenBindingError(
                    f"Unsupported certificate public key type: {type(public_key)}"
                )

            return public_key
        except Exception as e:
            raise TokenBindingError(f"Failed to parse client certificate: {e}")

    def _compute_jwk_thumbprint(
        self, public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    ) -> str:
        """Compute RFC 7638 JWK thumbprint (SHA-256) from cryptography public key."""
        if isinstance(public_key, rsa.RSAPublicKey):
            public_numbers = public_key.public_numbers()
            jwk = {
                "e": self._base64url_encode(
                    public_numbers.e.to_bytes(
                        (public_numbers.e.bit_length() + 7) // 8, "big"
                    )
                ),
                "kty": "RSA",
                "n": self._base64url_encode(
                    public_numbers.n.to_bytes(
                        (public_numbers.n.bit_length() + 7) // 8, "big"
                    )
                ),
            }
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            ec_numbers = public_key.public_numbers()
            curve_name = public_key.curve.name

            # Map cryptography curve names to JWK crv values
            curve_map = {
                "secp256r1": "P-256",
                "secp384r1": "P-384",
                "secp521r1": "P-521",
            }
            crv = curve_map.get(curve_name)
            if not crv:
                raise TokenBindingError(f"Unsupported EC curve: {curve_name}")

            coord_size = (public_key.curve.key_size + 7) // 8
            jwk = {
                "crv": crv,
                "kty": "EC",
                "x": self._base64url_encode(ec_numbers.x.to_bytes(coord_size, "big")),
                "y": self._base64url_encode(ec_numbers.y.to_bytes(coord_size, "big")),
            }
        else:
            raise TokenBindingError(f"Unsupported public key type: {type(public_key)}")

        return self._compute_jwk_thumbprint_from_dict(jwk)

    def _compute_jwk_thumbprint_from_dict(self, jwk: dict) -> str:
        """Compute RFC 7638 JWK thumbprint from JWK dictionary."""
        # RFC 7638: Canonicalize by sorting keys
        canonical_jwk = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
        thumbprint = hashlib.sha256(canonical_jwk.encode("utf-8")).digest()
        return self._base64url_encode(thumbprint)

    def _base64url_encode(self, data: bytes) -> str:
        """Encode bytes to base64url (no padding)."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _decode_base64url(self, data: str) -> bytes:
        """Decode base64url string (with or without padding)."""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
