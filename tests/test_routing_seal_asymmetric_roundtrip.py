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

"""Asymmetric routing-seal round trip: ``generate_seal`` → ``verify_seal``.

Regression guard for the mint/verify mismatch where seals carried the
provider label (``KMS_ASYMMETRIC``) as the JOSE ``alg`` and ECDSA signatures
in KMS DER encoding, so every asymmetric seal was rejected by ``verify_seal``.

Runs hermetically: Ed25519 via ``SoftwareEd25519Provider`` and an EC P-256
provider that returns DER signatures exactly as Cloud KMS / AWS KMS do, plus
one that returns raw ``R||S`` as Azure Key Vault does.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from src.gateway.governance import jwks as jwks_mod
from src.gateway.governance import kms_signer as ks
from src.gateway.governance import routing_seal as rs

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ACTION = "execute_trade"
_PARAMS = {"symbol": "ACME", "amount": 10.0}
_RECORD_HASH = "a" * 64


class _HermeticECP256Provider(ks.BaseKMSProvider):
    """EC P-256 provider mimicking a KMS ``EC_SIGN_P256_SHA256`` key."""

    def __init__(self, *, encoding: str = "der") -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._encoding = encoding
        self._pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def provider_name(self) -> str:
        return "KMS_ASYMMETRIC"

    @property
    def is_software_fallback(self) -> bool:
        return True

    @property
    def key_id(self) -> str:
        return "hermetic-ec-p256-k1"

    @property
    def ecdsa_signature_encoding(self) -> str:
        return self._encoding

    def sign_digest(self, digest: bytes) -> bytes:
        der = self._key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        if self._encoding == "raw":
            return ks.der_to_raw_ecdsa_signature(der, "ES256")
        return der

    def sign_raw(self, message: bytes) -> bytes:
        raise NotImplementedError

    def get_public_key_pem(self) -> bytes:
        return self._pem


@pytest.fixture(autouse=True)
def _seal_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")


def _install(monkeypatch: pytest.MonkeyPatch, provider: ks.BaseKMSProvider) -> None:
    signer = ks.KMSGovernanceSigner(provider=provider)
    monkeypatch.setattr(ks, "_signer", signer)
    # The seal JWKS is derived from the active signer; rebuild it.
    monkeypatch.setattr(jwks_mod, "_global_jwks", None)


def _segments(seal: str) -> tuple[dict, bytes]:
    h, _, s = seal.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    signature = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return header, signature


@pytest.mark.parametrize(
    ("label", "factory", "expected_alg", "expected_sig_len"),
    [
        ("ed25519", ks.SoftwareEd25519Provider, "EdDSA", 64),
        ("ec-p256-der", lambda: _HermeticECP256Provider(encoding="der"), "ES256", 64),
        ("ec-p256-raw", lambda: _HermeticECP256Provider(encoding="raw"), "ES256", 64),
    ],
)
def test_asymmetric_seal_round_trip(
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    factory,
    expected_alg: str,
    expected_sig_len: int,
) -> None:
    _install(monkeypatch, factory())

    seal = rs.generate_seal(_ACTION, _PARAMS, record_hash=_RECORD_HASH)
    header, signature = _segments(seal)

    assert header["alg"] == expected_alg, label
    assert header["kid"], "minted seals must carry a kid"
    assert len(signature) == expected_sig_len, label
    assert rs.verify_seal(seal, _ACTION, _PARAMS, expected_record_hash=_RECORD_HASH)


def test_asymmetric_seal_rejects_param_tamper(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _HermeticECP256Provider())
    seal = rs.generate_seal(_ACTION, _PARAMS, record_hash=_RECORD_HASH)

    with pytest.raises(rs.SymbolicGovernorViolation):
        rs.verify_seal(seal, _ACTION, {**_PARAMS, "amount": 10_000.0})


def test_kidless_seal_rejected_even_with_single_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Trust is resolved by kid alone; stripping kid must not fall back."""
    provider = ks.SoftwareEd25519Provider()
    _install(monkeypatch, provider)
    seal = rs.generate_seal(_ACTION, _PARAMS, record_hash=_RECORD_HASH)

    h, p, _ = seal.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    header.pop("kid")
    h2 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    sig = provider.sign_raw(f"{h2}.{p}".encode())
    kidless = f"{h2}.{p}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    with pytest.raises(rs.SymbolicGovernorViolation, match="unknown kid"):
        rs.verify_seal(kidless, _ACTION, _PARAMS)


def test_sign_jws_leaves_eddsa_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = ks.KMSGovernanceSigner(provider=ks.SoftwareEd25519Provider())
    assert signer.sign_jws(b"x.y") == signer.sign_raw(b"x.y")
