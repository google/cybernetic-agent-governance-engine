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

import pytest

from src.integrations.provider_02.provider import Provider02AttestationProvider

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]


def _get_live_credentials() -> tuple[str, str, str]:
    """Retrieve endpoint, JWK endpoint, and API key from environment variables."""
    endpoint = os.environ.get("PROVIDER_02_API_ENDPOINT", "").split("#")[0].strip()

    jwk_endpoint = os.environ.get("PROVIDER_02_JWK_ENDPOINT", "").split("#")[0].strip()

    api_key = os.environ.get("PROVIDER_02_API_KEY_SECRET", "").split("#")[0].strip()

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
async def test_live_verify_bundle_with_cyclic_topology(
    live_provider: Provider02AttestationProvider,
) -> None:
    """Verify stateless CER verification via POST /v1/cer/verify with cyclic topology."""
    from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
    from src.integrations.provider_02.governed_cer import topology_to_wire
    from tests.integrations.provider_02.hitl_bundle import build_hitl_approval_bundle

    bundle = build_hitl_approval_bundle()
    verdict = await live_provider.verify_bundle(
        bundle, topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
    )
    assert verdict.verified, f"verify_bundle failed: {verdict.code}: {verdict.error}"
    assert verdict.certificate_hash.startswith("sha256:")
    assert verdict.governed_verification.get("topologyValidation") == "valid"
    assert verdict.governed_verification.get("causalGraphValidity") == "valid"
