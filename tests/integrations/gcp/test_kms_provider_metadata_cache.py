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

"""Cloud KMS key metadata is read once, not once per signature.

``GCPKMSProvider`` caches the key version's algorithm and
``KMSGovernanceSigner.public_jwk`` caches the parsed public key, so minting a
routing seal makes no ``GetCryptoKeyVersion`` call and parses no PEM.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from src.gateway.governance import jwks as jwks_mod
from src.gateway.governance import kms_signer as ks
from src.gateway.governance import routing_seal as rs
from src.integrations.gcp.kms_provider import GCPKMSProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]

_KEY = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
_ACTION = "execute_trade"
_PARAMS = {"symbol": "ACME", "amount": 10.0}
_RECORD_HASH = "a" * 64


def _client(algorithm: str = "EC_SIGN_P256_SHA256") -> MagicMock:
    client = MagicMock()
    client.get_crypto_key_version.return_value.algorithm.name = algorithm
    return client


def _ec_key() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, pem


def _signing_client(key: ec.EllipticCurvePrivateKey, pem: bytes) -> MagicMock:
    """Cloud KMS client double backed by a real P-256 key (DER, as KMS returns)."""
    client = _client("EC_SIGN_P256_SHA256")
    client.get_public_key.return_value.pem = pem.decode()
    client.asymmetric_sign.side_effect = lambda request: SimpleNamespace(
        signature=key.sign(
            request.digest.sha256, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
        )
    )
    return client


def _count_pem_parses(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    parsed: list[bytes] = []
    real_pem_to_jwk = jwks_mod.pem_to_jwk

    def counting_pem_to_jwk(pem_bytes: bytes, kid: str | None = None) -> dict:
        parsed.append(pem_bytes)
        return real_pem_to_jwk(pem_bytes, kid)

    monkeypatch.setattr(jwks_mod, "pem_to_jwk", counting_pem_to_jwk)
    return parsed


# ---------------------------------------------------------------------------
# GCPKMSProvider: algorithm metadata cache
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("algorithm", "jose_alg", "digest", "rsa_pss"),
    [
        ("EC_SIGN_P256_SHA256", "ES256", "sha256", False),
        ("EC_SIGN_P384_SHA384", "ES384", "sha384", False),
        ("EC_SIGN_ED25519", "EdDSA", "raw", False),
        ("RSA_SIGN_PSS_2048_SHA256", "PS256", "sha256", True),
        ("RSA_SIGN_PSS_3072_SHA256", "PS256", "sha256", True),
        ("RSA_SIGN_PSS_4096_SHA256", "PS256", "sha256", True),
        ("RSA_SIGN_PSS_3072_SHA384", "PS384", "sha384", True),
        ("RSA_SIGN_PSS_4096_SHA512", "PS512", "sha512", True),
        ("RSA_SIGN_PKCS1_2048_SHA256", "RS256", "sha256", False),
        ("RSA_SIGN_PKCS1_3072_SHA256", "RS256", "sha256", False),
        ("RSA_SIGN_PKCS1_4096_SHA256", "RS256", "sha256", False),
        ("RSA_SIGN_PKCS1_3072_SHA384", "RS384", "sha384", False),
        ("RSA_SIGN_PKCS1_4096_SHA512", "RS512", "sha512", False),
        # Unmapped algorithms keep the ES256 fallback.
        ("EC_SIGN_SECP256K1_SHA256", "ES256", "sha256", False),
    ],
)
def test_algorithm_metadata_mapping(
    algorithm: str, jose_alg: str, digest: str, rsa_pss: bool
) -> None:
    provider = GCPKMSProvider(key_version_name=_KEY, kms_client=_client(algorithm))

    assert provider.jose_alg == jose_alg
    assert provider.digest_algorithm == digest
    assert provider.expects_raw_message is (digest == "raw")
    assert provider.uses_rsa_pss is rsa_pss


def test_metadata_is_fetched_once_across_reads() -> None:
    client = _client("RSA_SIGN_PSS_2048_SHA256")
    provider = GCPKMSProvider(key_version_name=_KEY, kms_client=client)

    for _ in range(100):
        assert provider.jose_alg == "PS256"
        assert provider.uses_rsa_pss is True
        assert provider.digest_algorithm == "sha256"

    client.get_crypto_key_version.assert_called_once_with(name=_KEY)


def test_failed_startup_lookup_is_retried_once_on_first_use() -> None:
    client = _client("EC_SIGN_P384_SHA384")
    version = client.get_crypto_key_version.return_value
    client.get_crypto_key_version.side_effect = [
        RuntimeError("metadata server not ready"),
        version,
    ]

    provider = GCPKMSProvider(key_version_name=_KEY, kms_client=client)
    assert client.get_crypto_key_version.call_count == 1

    assert provider.digest_algorithm == "sha384"
    assert provider.jose_alg == "ES384"
    assert provider.expects_raw_message is False
    assert client.get_crypto_key_version.call_count == 2


def test_concurrent_first_use_fetches_once() -> None:
    client = _client("EC_SIGN_P256_SHA256")
    version = client.get_crypto_key_version.return_value

    def lookup(*, name: str) -> object:
        # Mock counts the call before running side_effect: call 1 is startup.
        if client.get_crypto_key_version.call_count == 1:
            raise RuntimeError("cold start")
        time.sleep(0.05)  # hold the lock while the other threads queue on it
        return version

    client.get_crypto_key_version.side_effect = lookup
    provider = GCPKMSProvider(key_version_name=_KEY, kms_client=client)

    workers = 8
    barrier = threading.Barrier(workers)
    results: list[str] = []

    def read_alg() -> None:
        barrier.wait()
        results.append(provider.jose_alg)

    threads = [threading.Thread(target=read_alg) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert results == ["ES256"] * workers
    assert client.get_crypto_key_version.call_count == 2


def test_unresolved_algorithm_fails_closed_when_enforcing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.get_crypto_key_version.side_effect = RuntimeError("PERMISSION_DENIED")
    provider = GCPKMSProvider(key_version_name=_KEY, kms_client=client)

    monkeypatch.setenv("CAGE_ENV", "production")
    with pytest.raises(RuntimeError, match="Cannot determine the digest width"):
        _ = provider.digest_algorithm
    with pytest.raises(RuntimeError, match="Cannot determine the digest width"):
        _ = provider.expects_raw_message
    with pytest.raises(RuntimeError, match="Failed to determine JOSE algorithm"):
        _ = provider.jose_alg
    assert provider.uses_rsa_pss is False


def test_unresolved_algorithm_defaults_to_sha256_when_permissive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_ENV", "test")
    client = MagicMock()
    client.get_crypto_key_version.side_effect = RuntimeError("unavailable")
    provider = GCPKMSProvider(key_version_name=_KEY, kms_client=client)

    assert provider.digest_algorithm == "sha256"
    assert provider.expects_raw_message is False


# ---------------------------------------------------------------------------
# KMSGovernanceSigner.public_jwk and seal minting
# ---------------------------------------------------------------------------


def test_public_jwk_is_derived_once_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, pem = _ec_key()
    signer = ks.KMSGovernanceSigner(
        provider=GCPKMSProvider(key_version_name=_KEY, kms_client=_client()),
        key_version_name=_KEY,
        public_key_pem=pem,
    )
    parsed = _count_pem_parses(monkeypatch)

    jwk = signer.public_jwk
    for _ in range(10):
        assert signer.public_jwk is jwk

    assert parsed == [pem]
    assert dict(jwk) == jwks_mod.pem_to_jwk(pem)
    with pytest.raises(TypeError):
        jwk["kid"] = "forged"  # type: ignore[index]


def test_public_jwk_follows_a_changed_public_key() -> None:
    _, pem_a = _ec_key()
    _, pem_b = _ec_key()
    signer = ks.KMSGovernanceSigner(
        provider=GCPKMSProvider(key_version_name=_KEY, kms_client=_client()),
        key_version_name=_KEY,
        public_key_pem=pem_a,
    )
    kid_a = signer.public_jwk["kid"]

    signer._public_key_pem = pem_b

    assert signer.public_jwk["kid"] == jwks_mod.pem_to_jwk(pem_b)["kid"]
    assert signer.public_jwk["kid"] != kid_a


def test_seal_minting_makes_no_metadata_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    key, pem = _ec_key()
    client = _signing_client(key, pem)
    signer = ks.KMSGovernanceSigner(
        provider=GCPKMSProvider(key_version_name=_KEY, kms_client=client),
        key_version_name=_KEY,
    )
    monkeypatch.setattr(ks, "_signer", signer)
    # The seal JWKS is derived from the active signer; rebuild it.
    monkeypatch.setattr(jwks_mod, "_global_jwks", None)
    parsed = _count_pem_parses(monkeypatch)

    seals = [
        rs.generate_seal(_ACTION, _PARAMS, record_hash=_RECORD_HASH) for _ in range(20)
    ]

    client.get_crypto_key_version.assert_called_once_with(name=_KEY)
    assert client.asymmetric_sign.call_count == 20
    assert parsed == [pem]
    assert rs.verify_seal(
        seals[-1], _ACTION, _PARAMS, expected_record_hash=_RECORD_HASH
    )
