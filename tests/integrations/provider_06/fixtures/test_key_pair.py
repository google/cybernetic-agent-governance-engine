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
Deterministic Test Key Pair Generator for Provider 06 Agent Integrity.

⚠️ TEST-ONLY: This key pair is STRICTLY for automated testing and must NEVER
be used in production environments. The private key is publicly committed and
provides zero cryptographic security.

Generates a reproducible Ed25519 key pair from a fixed SHA-256 seed to ensure:
- Byte-identical test fixture generation across machines/environments
- Stable mock endpoint signing for cryptographic verification tests
- No runtime dependency on external key management services

The test key is identified by kid="test-key-1" in the JWKS manifest.

Security Model:
    - Private key: Committed to source control for mock endpoint signing
    - Public key: Exported as RFC 7517 JWK for trust anchor resolution tests
    - Seed: Fixed constant `hashlib.sha256(b"cage-provider-06-test-key-1").digest()[:32]`

Usage:
    >>> private_key, public_key_jwk = generate_test_key_pair()
    >>> # Use private_key in mock_endpoint.py for signing receipts
    >>> # Use public_key_jwk in key_manifest.json for verification
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Test key identifier (matches key_manifest.json)
TEST_KEY_ID = "test-key-1"

# Fixed seed for deterministic key generation
# SHA-256 output is 32 bytes, matching Ed25519 private key seed requirement
TEST_KEY_SEED = hashlib.sha256(b"cage-provider-06-test-key-1").digest()[:32]


def generate_test_key_pair() -> tuple[Ed25519PrivateKey, dict[str, str]]:
    """
    Generate deterministic Ed25519 test key pair from fixed seed.

    Returns:
        Tuple of (private_key, public_key_jwk) where:
            - private_key: Ed25519PrivateKey for mock endpoint signing
            - public_key_jwk: RFC 7517 JWK dict for JWKS manifest

    Example:
        >>> private_key, jwk = generate_test_key_pair()
        >>> assert jwk["kid"] == "test-key-1"
        >>> assert jwk["kty"] == "OKP"
        >>> assert jwk["crv"] == "Ed25519"
    """
    # Generate private key from fixed seed (deterministic)
    private_key = Ed25519PrivateKey.from_private_bytes(TEST_KEY_SEED)

    # Extract public key bytes
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    # Encode as base64url (RFC 7517 requirement)
    # Remove padding '=' characters for JWK format
    x_value = base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("=")

    # Construct RFC 7517 JWK structure for Ed25519
    public_key_jwk = {
        "kid": TEST_KEY_ID,  # Key Identifier
        "kty": "OKP",  # Key Type: Octet Key Pair
        "crv": "Ed25519",  # Curve: Edwards-Curve 25519
        "x": x_value,  # Public key coordinate (base64url, no padding)
    }

    return private_key, public_key_jwk


def get_test_private_key() -> Ed25519PrivateKey:
    """
    Get deterministic test private key for mock endpoint signing.

    ⚠️ TEST-ONLY: Never use this key in production.

    Returns:
        Ed25519PrivateKey derived from fixed seed
    """
    return Ed25519PrivateKey.from_private_bytes(TEST_KEY_SEED)


def get_test_public_key_jwk() -> dict[str, str]:
    """
    Get test public key as RFC 7517 JWK for JWKS manifest.

    Returns:
        JWK dictionary matching key_manifest.json entry
    """
    _, public_key_jwk = generate_test_key_pair()
    return public_key_jwk


if __name__ == "__main__":
    # Generate and display test key pair for verification
    private_key, public_key_jwk = generate_test_key_pair()

    print("=" * 70)
    print("Provider 06 Test Key Pair (Deterministic Ed25519)")
    print("=" * 70)
    print()
    print("⚠️  WARNING: TEST-ONLY KEY — DO NOT USE IN PRODUCTION")
    print()
    print("Key Identifier (kid):", public_key_jwk["kid"])
    print("Key Type (kty):", public_key_jwk["kty"])
    print("Curve (crv):", public_key_jwk["crv"])
    print()
    print("Public Key JWK (x parameter):")
    print(public_key_jwk["x"])
    print()
    print("Full JWK (for key_manifest.json):")
    import json

    print(json.dumps(public_key_jwk, indent=2))
    print()
    print("=" * 70)
