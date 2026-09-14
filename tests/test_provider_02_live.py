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

"""Live integration tests for Provider 02 (CER attestation).

Executes live HTTP requests against the Provider 02 sandbox endpoint
when configured via environment variables.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from src.integrations.provider_02.provider import Provider02AttestationProvider

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]


def _get_live_credentials() -> tuple[str, str, str]:
    """Retrieve endpoint, JWK endpoint, and API key from environment variables."""
    endpoint = (
        os.environ.get("PROVIDER_02_API_ENDPOINT", "")
        .split("#")[0]
        .strip()
    )

    jwk_endpoint = (
        os.environ.get("PROVIDER_02_JWK_ENDPOINT", "")
        .split("#")[0]
        .strip()
    )

    api_key = (
        os.environ.get("PROVIDER_02_API_KEY_SECRET", "")
        .split("#")[0]
        .strip()
    )

    return endpoint, jwk_endpoint, api_key


@pytest.fixture
async def live_provider() -> Provider02AttestationProvider:
    """Create a live Provider 02 provider instance."""
    endpoint, jwk_endpoint, api_key = _get_live_credentials()
    
    if not endpoint:
        pytest.skip("PROVIDER_02_API_ENDPOINT not configured")
    
    provider = Provider02AttestationProvider(
        endpoint=endpoint,
        jwk_endpoint=jwk_endpoint,
        api_key=api_key,
        timeout=15.0,
    )
    
    # Start the JWK sync daemon
    await provider.start()
    
    yield provider
    
    # Clean shutdown
    await provider.stop()


@pytest.mark.asyncio
async def test_live_jwk_sync(
    live_provider: Provider02AttestationProvider,
) -> None:
    """Verify live JWK manifest synchronization and cache population."""
    # JWK cache should be populated after start()
    assert live_provider.has_jwk_keys, "JWK cache should be populated after start()"
    
    # Cache age should be recent (< 60 seconds from initial sync)
    cache_age = live_provider.jwk_cache_age_seconds
    assert cache_age < 60.0, f"JWK cache age {cache_age}s exceeds 60s threshold"


@pytest.mark.asyncio
async def test_live_cer_verification_signature(
    live_provider: Provider02AttestationProvider,
) -> None:
    """Verify Ed25519 signature verification against live Provider 02 CER.
    
    This test requires a valid certificate_hash from a real CER issued by
    Provider 02's sandbox. If no test certificate hash is available, the test
    will skip.
    """
    # Use a test certificate hash if provided via environment
    test_cert_hash = os.environ.get("PROVIDER_02_TEST_CERT_HASH", "").strip()
    
    if not test_cert_hash:
        pytest.skip(
            "PROVIDER_02_TEST_CERT_HASH not configured — "
            "provide a valid CER hash to test signature verification"
        )
    
    # Verify the CER (should resolve, verify hash binding, and check signature)
    result = await live_provider.verify_cer(test_cert_hash)
    
    # Assert two-stage verification passed
    assert result.valid, f"CER verification failed: {result.error}"
    assert result.signature_checked, "Signature should be checked"
    assert result.key_id, "Key ID should be present"
    assert result.signer, "Signer should be present"


@pytest.mark.asyncio
async def test_live_certify_decision(
    live_provider: Provider02AttestationProvider,
) -> None:
    """Verify live CER creation via certify_decision endpoint."""
    evidence_payload: dict[str, Any] = {
        "correlation_id": "test-cage-live-provider02-001",
        "action": "test.action.verify",
        "decision": "APPROVED",
        "context": {"test": True},
    }
    
    cer_receipt = await live_provider.certify_decision(evidence_payload)
    
    # Assert CER receipt is valid
    assert not cer_receipt.error, f"CER creation failed: {cer_receipt.error}"
    assert cer_receipt.certificate_hash, "Certificate hash should be present"
    assert len(cer_receipt.certificate_hash) == 64, "Hash should be 64-char hex"
    assert cer_receipt.signer_key_id, "Signer key ID should be present"


@pytest.mark.asyncio
async def test_live_fetch_attestations(
    live_provider: Provider02AttestationProvider,
) -> None:
    """Verify fetch_attestations protocol implementation with live CER.
    
    This test creates a CER, then fetches attestations for it to validate
    the AttestationProvider protocol.
    """
    # Create a test CER first
    evidence_payload: dict[str, Any] = {
        "correlation_id": "test-cage-live-provider02-002",
        "action": "test.action.attest",
        "decision": "APPROVED",
        "context": {"test": True},
    }
    
    cer_receipt = await live_provider.certify_decision(evidence_payload)
    assert not cer_receipt.error, f"CER creation failed: {cer_receipt.error}"
    
    # Fetch attestations using the AttestationProvider protocol
    attestations = await live_provider.fetch_attestations(
        {"certificate_hash": cer_receipt.certificate_hash}
    )
    
    # Assert attestation structure
    assert len(attestations) == 1, "Should return exactly one attestation"
    attestation = attestations[0]
    
    assert attestation.attestation_type == "CER"
    assert attestation.provider_name == "provider_02"
    assert attestation.status in ("VERIFIED", "UNVERIFIED"), \
        f"Unexpected status: {attestation.status}"
    assert attestation.receipt_id == cer_receipt.certificate_hash[:16]
    assert attestation.metadata.get("signer")
    assert attestation.metadata.get("key_id")
