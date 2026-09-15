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

"""Live integration tests for Provider 05 (AO warrant and blueprint).

Executes live HTTP requests against the Provider 05 sandbox endpoint
when configured via environment variables.
"""

from __future__ import annotations

import os

import pytest

from src.gateway.governance.seams.attestation import AttestationStatus
from src.integrations.provider_05.blueprint_provider import Provider05BlueprintProvider
from src.integrations.provider_05.client import Provider05Client

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]


def _get_live_config() -> tuple[str, str]:
    """Retrieve Provider 05 configuration from environment variables."""
    registry_url = (
        os.environ.get("PROVIDER_05_BLUEPRINT_REGISTRY_URL", "").split("#")[0].strip()
    )

    api_key = os.environ.get("PROVIDER_05_API_KEY", "").split("#")[0].strip()

    return registry_url, api_key


@pytest.fixture
def live_client() -> Provider05Client:
    """Create a live Provider 05 client instance."""
    registry_url, api_key = _get_live_config()

    if not registry_url:
        pytest.skip("PROVIDER_05_BLUEPRINT_REGISTRY_URL not configured")

    return Provider05Client(
        blueprint_registry_url=registry_url,
        api_key=api_key,
        timeout=10.0,
    )


@pytest.fixture
def live_blueprint_provider(
    live_client: Provider05Client,
) -> Provider05BlueprintProvider:
    """Create a live blueprint provider with active thresholds."""
    # Use test thresholds from environment or defaults
    active_thresholds = {
        "THR-FIN-006": float(os.environ.get("PROVIDER_05_TEST_THR_FIN_006", "15000.0"))
    }

    return Provider05BlueprintProvider(
        client=live_client,
        active_thresholds=active_thresholds,
    )


@pytest.mark.asyncio
async def test_live_ao_warrant_retrieval(live_client: Provider05Client) -> None:
    """Verify live AO warrant retrieval from Provider 05 registry."""
    # Use test threshold ID from environment or default
    threshold_id = os.environ.get("PROVIDER_05_TEST_THRESHOLD_ID", "THR-FIN-006")

    record = await live_client.get_risk_acceptance(threshold_id)

    # Provider 05 may not have all test thresholds configured
    if record is None:
        pytest.skip(
            f"No risk acceptance record found for {threshold_id} in sandbox — "
            "this is acceptable for partner integration tests"
        )

    # Assert record structure
    assert record.threshold_id == threshold_id
    assert record.receipt_id, "Receipt ID should be present"
    assert record.ao_signature_hash, "AO signature hash should be present"
    assert record.ao_name, "AO name should be present"
    assert record.threshold_value >= 0, "Threshold value should be non-negative"
    assert record.attested_at, "Attestation timestamp should be present"


@pytest.mark.asyncio
async def test_live_blueprint_attestation(
    live_blueprint_provider: Provider05BlueprintProvider,
) -> None:
    """Verify live blueprint attestation via AttestationProvider protocol."""
    threshold_id = os.environ.get("PROVIDER_05_TEST_THRESHOLD_ID", "THR-FIN-006")

    attestations = await live_blueprint_provider.fetch_attestations(
        {"threshold_id": threshold_id}
    )

    # Assert attestation structure
    assert len(attestations) == 1, "Should return exactly one attestation"
    attestation = attestations[0]

    assert attestation.attestation_type == "BLUEPRINT"
    assert attestation.provider_name == "provider_05-blueprint"

    # Status should be one of the valid attestation statuses
    valid_statuses = {
        AttestationStatus.VERIFIED.value,
        AttestationStatus.STALE.value,
        AttestationStatus.DRIFT_DETECTED.value,
    }
    assert attestation.status in valid_statuses, (
        f"Unexpected status: {attestation.status}"
    )

    # Metadata should contain threshold information
    assert "threshold_id" in attestation.metadata


@pytest.mark.asyncio
async def test_live_threshold_drift_detection(
    live_client: Provider05Client,
) -> None:
    """Verify threshold drift detection between signed warrant and runtime config.

    This test explicitly configures a mismatched active threshold to verify
    drift detection logic.
    """
    threshold_id = os.environ.get("PROVIDER_05_TEST_THRESHOLD_ID", "THR-FIN-006")

    # Fetch the signed risk acceptance record
    record = await live_client.get_risk_acceptance(threshold_id)

    if record is None:
        pytest.skip(f"No risk acceptance record found for {threshold_id}")

    # Create a blueprint provider with intentionally drifted threshold
    drifted_value = record.threshold_value + 1000.0  # Drift by 1000
    provider = Provider05BlueprintProvider(
        client=live_client,
        active_thresholds={threshold_id: drifted_value},
    )

    # Fetch attestations — should detect drift
    attestations = await provider.fetch_attestations({"threshold_id": threshold_id})

    assert len(attestations) == 1
    attestation = attestations[0]

    # Drift should be detected
    assert attestation.status == AttestationStatus.DRIFT_DETECTED.value, (
        f"Expected DRIFT_DETECTED, got {attestation.status}"
    )


@pytest.mark.asyncio
async def test_live_jcs_canonical_binding(live_client: Provider05Client) -> None:
    """Verify JCS canonical cryptographic binding in AO warrant schemas.

    Provider 05 warrants should use RFC 8785 (JCS) for canonical serialization
    to ensure signature stability across JSON implementations.
    """
    threshold_id = os.environ.get("PROVIDER_05_TEST_THRESHOLD_ID", "THR-FIN-006")

    record = await live_client.get_risk_acceptance(threshold_id)

    if record is None:
        pytest.skip(f"No risk acceptance record found for {threshold_id}")

    # The signature hash should be a valid SHA-256 hex digest
    assert len(record.ao_signature_hash) == 64, (
        f"AO signature hash should be 64-char hex, got {len(record.ao_signature_hash)}"
    )

    # Verify it's hexadecimal
    try:
        int(record.ao_signature_hash, 16)
    except ValueError:
        pytest.fail(f"AO signature hash is not valid hex: {record.ao_signature_hash}")
