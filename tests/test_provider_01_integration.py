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

"""Unit tests for Provider01NormativeProvider adapter."""

from __future__ import annotations

import httpx
import pytest
import respx

from src.integrations.provider_01.provider import Provider01NormativeProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def provider() -> Provider01NormativeProvider:
    return Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-api-key",
        timeout=2.0,
    )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_baseline_success(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/legal-baseline/US_FED").mock(
        return_value=httpx.Response(
            200,
            json={"profile": {"rule": "allow"}},
            headers={"ETag": "etag-123"},
        )
    )
    baseline = await provider.fetch_baseline("US_FED")
    assert baseline.region == "US_FED"
    assert baseline.profile == {"rule": "allow"}
    assert baseline.etag == "etag-123"
    assert baseline.error is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_baseline_error(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/legal-baseline/US_FED").mock(
        return_value=httpx.Response(500)
    )
    baseline = await provider.fetch_baseline("US_FED")
    assert baseline.region == "US_FED"
    assert baseline.error is not None


def _make_mock_signer():
    from unittest.mock import MagicMock

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from src.gateway.governance.kms_signer import (
        GCPKMSProvider,
        KMSGovernanceSigner,
    )

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    mock_client = MagicMock()
    key_name = (
        "projects/test/locations/us/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"
    )
    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = KMSGovernanceSigner(
        kms_client=mock_client,
        key_version_name=key_name,
        public_key_pem=public_pem,
        provider=provider,
    )

    def mock_sign_raw(message: bytes) -> bytes:
        import hashlib

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

        digest = hashlib.sha256(message).digest()
        hash_alg = hashes.SHA256()
        return private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hash_alg)))

    provider.sign_digest = MagicMock(side_effect=lambda d: mock_sign_raw(b"dummy"))
    signer.sign_raw = MagicMock(side_effect=mock_sign_raw)
    return signer


@pytest.mark.asyncio
@respx.mock
async def test_validate_fria_success(provider: Provider01NormativeProvider) -> None:
    from unittest.mock import patch

    respx.post("https://provider01.example.com/validate/fria").mock(
        return_value=httpx.Response(
            200,
            json={
                "decision": "ALLOW",
                "authority_record_id": "auth-record-xyz",
                "authority_state_version": "v1.2.3",
            },
        )
    )
    mock_signer = _make_mock_signer()
    with patch(
        "src.gateway.governance.kms_signer.get_governance_signer",
        return_value=mock_signer,
    ):
        result = await provider.validate_fria(
            {"action": "trade", "actor_id": "user-123", "thread_id": "thread-abc"}
        )
    assert result.admitted is True
    assert len(result.findings) == 1
    assert result.findings[0]["code"] == "CONSEQUENCE_TOKEN"


@pytest.mark.asyncio
@respx.mock
async def test_validate_fria_error(provider: Provider01NormativeProvider) -> None:
    respx.post("https://provider01.example.com/validate/fria").mock(
        return_value=httpx.Response(502)
    )
    result = await provider.validate_fria({"action": "trade"})
    assert result.admitted is False
    assert result.error is not None


@pytest.mark.asyncio
@respx.mock
async def test_submit_evidence_success(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/evidence-chain/thread-1").mock(
        return_value=httpx.Response(
            200,
            json={"seal_hash": "seal-abc-123"},
        )
    )
    seal = await provider.submit_evidence("thread-1", "evidence-hash-1")
    assert seal.thread_id == "thread-1"
    assert seal.seal_hash == "seal-abc-123"
    assert seal.error is None


@pytest.mark.asyncio
@respx.mock
async def test_submit_evidence_error(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/evidence-chain/thread-1").mock(
        return_value=httpx.Response(500)
    )
    seal = await provider.submit_evidence("thread-1", "evidence-hash-1")
    assert seal.thread_id == "thread-1"
    assert seal.error is not None
