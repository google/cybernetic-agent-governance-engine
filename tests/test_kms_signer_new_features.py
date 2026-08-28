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
Tests for new KMSGovernanceSigner features added in ST-1 (FlowSignal Phase 2).

Covers:
  - key_id property
  - jose_alg property (JOSE algorithm mapping)
  - verify_raw() method (raw signature verification)
  - Ed25519 verification path fix in _kms_verify()
"""

from unittest.mock import MagicMock, patch

import pytest

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
    import hashlib

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


# ---------------------------------------------------------------------------
# key_id property
# ---------------------------------------------------------------------------


def test_key_id_returns_configured_identifier_when_kms_active():
    """key_id property returns the configured key resource identifier when KMS is active."""
    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_client, key_version_name=key_name)

    assert signer.key_id == key_name


def test_key_id_raises_when_kms_inactive():
    """key_id property raises RuntimeError when KMS is not active."""
    signer = _make_signer(kms_client=None, key_version_name="")

    with pytest.raises(RuntimeError, match="KMS is not active"):
        _ = signer.key_id


# ---------------------------------------------------------------------------
# jose_alg property
# ---------------------------------------------------------------------------


def test_jose_alg_raises_when_kms_inactive():
    """jose_alg property raises RuntimeError when KMS is not active."""
    signer = _make_signer(kms_client=None, key_version_name="")

    with pytest.raises(RuntimeError, match="KMS is not active"):
        _ = signer.jose_alg


def test_jose_alg_returns_es256_for_p256_sha256():
    """jose_alg returns 'ES256' for EC_SIGN_P256_SHA256 keys."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    # Mock get_crypto_key_version to return EC_SIGN_P256_SHA256
    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(provider=provider, key_version_name=key_name)

    assert signer.jose_alg == "ES256"


def test_jose_alg_returns_es384_for_p384_sha384():
    """jose_alg returns 'ES384' for EC_SIGN_P384_SHA384 keys."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P384_SHA384"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(provider=provider, key_version_name=key_name)

    assert signer.jose_alg == "ES384"


def test_jose_alg_returns_eddsa_for_ed25519():
    """jose_alg returns 'EdDSA' for EC_SIGN_ED25519 keys."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_ED25519"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(provider=provider, key_version_name=key_name)

    assert signer.jose_alg == "EdDSA"


def test_jose_alg_returns_ps256_for_rsa_pss_sha256():
    """jose_alg returns 'PS256' for RSA_SIGN_PSS_*_SHA256 keys."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "RSA_SIGN_PSS_2048_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(provider=provider, key_version_name=key_name)

    assert signer.jose_alg == "PS256"


def test_jose_alg_returns_rs256_for_rsa_pkcs1_sha256():
    """jose_alg returns 'RS256' for RSA_SIGN_PKCS1_*_SHA256 keys."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "RSA_SIGN_PKCS1_2048_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(provider=provider, key_version_name=key_name)

    assert signer.jose_alg == "RS256"


# ---------------------------------------------------------------------------
# verify_raw() method
# ---------------------------------------------------------------------------


def test_verify_raw_raises_when_kms_inactive():
    """verify_raw() raises RuntimeError when KMS is not active (fail-closed)."""
    signer = _make_signer(kms_client=None, key_version_name="")

    with pytest.raises(RuntimeError, match="KMS is not active"):
        signer.verify_raw(b"test message", b"fake_signature")


def test_verify_raw_raises_when_no_public_key():
    """verify_raw() raises RuntimeError when no public key is loaded."""
    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(
        kms_client=mock_client, key_version_name=key_name, public_key_pem=b""
    )

    with pytest.raises(RuntimeError, match="no public key is loaded"):
        signer.verify_raw(b"test message", b"fake_signature")


def test_verify_raw_roundtrip_ec_p256():
    """verify_raw() returns True for a valid signature (ECDSA P-256 round-trip)."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("ec_p256")
    message = b"test message for signing"

    # Sign with the private key
    signature = _sign_with_private_key(private_key, message, "sha256")

    # Create a mock provider that returns the real signature
    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    # Verify the signature
    assert signer.verify_raw(message, signature) is True


def test_verify_raw_returns_false_for_tampered_message():
    """verify_raw() returns False when the message has been tampered with."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("ec_p256")
    message = b"original message"
    tampered_message = b"tampered message"

    signature = _sign_with_private_key(private_key, message, "sha256")

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    # Verify with tampered message should fail
    assert signer.verify_raw(tampered_message, signature) is False


def test_verify_raw_returns_false_for_corrupt_signature():
    """verify_raw() returns False for a corrupt/tampered signature."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("ec_p256")
    message = b"test message"

    signature = _sign_with_private_key(private_key, message, "sha256")
    # Corrupt the signature
    corrupt_signature = bytes([b ^ 0xFF for b in signature[:32]]) + signature[32:]

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    assert signer.verify_raw(message, corrupt_signature) is False


def test_verify_raw_roundtrip_ed25519():
    """verify_raw() returns True for Ed25519 signature (regression test for defect #4)."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("ed25519")
    message = b"test message for Ed25519"

    # Sign with Ed25519 (raw message, no pre-hash)
    signature = _sign_with_private_key(private_key, message)

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_ED25519"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    # Verify Ed25519 signature
    assert signer.verify_raw(message, signature) is True


def test_verify_raw_roundtrip_ec_p384():
    """verify_raw() returns True for ECDSA P-384 signature."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("ec_p384")
    message = b"test message for P-384"

    signature = _sign_with_private_key(private_key, message, "sha384")

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P384_SHA384"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    assert signer.verify_raw(message, signature) is True


def test_verify_raw_roundtrip_rsa_pkcs1():
    """verify_raw() returns True for RSA PKCS1v15 signature."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("rsa_2048")
    message = b"test message for RSA"

    signature = _sign_with_private_key(private_key, message, "sha256")

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "RSA_SIGN_PKCS1_2048_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    assert signer.verify_raw(message, signature) is True


# ---------------------------------------------------------------------------
# Ed25519 verification fix in _kms_verify()
# ---------------------------------------------------------------------------


def test_kms_verify_ed25519_roundtrip():
    """_kms_verify() correctly verifies Ed25519 signatures (via verify())."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("ed25519")
    plan_bytes = b'{"action":"test","signed_at":1234567890}'

    # Sign with Ed25519
    signature = _sign_with_private_key(private_key, plan_bytes)
    signature_hex = signature.hex()

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_ED25519"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    # Verify via _kms_verify (which is called by verify())
    result = signer._kms_verify(plan_bytes, signature_hex)
    assert result is True


def test_kms_verify_ed25519_rejects_tampered_signature():
    """_kms_verify() returns False for a tampered Ed25519 signature."""
    from src.gateway.governance.kms_signer import GCPKMSProvider

    private_key, public_pem = _generate_keypair("ed25519")
    plan_bytes = b'{"action":"test"}'

    signature = _sign_with_private_key(private_key, plan_bytes)
    # Corrupt the signature
    corrupt_signature = bytes([b ^ 0xFF for b in signature[:16]]) + signature[16:]
    signature_hex = corrupt_signature.hex()

    mock_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_ED25519"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = _make_signer(
        provider=provider, key_version_name=key_name, public_key_pem=public_pem
    )

    result = signer._kms_verify(plan_bytes, signature_hex)
    assert result is False
