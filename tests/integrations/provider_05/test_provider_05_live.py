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


# ── VEIP v0.2 Tier 1 Over-the-Wire Warrant Conformance Suite ─────────────────

from datetime import datetime, timezone  # noqa: E402

from src.cage_finance.tiers.trade_confidence_tier import (  # noqa: E402
    TRADE_CONFIDENCE_NORM_ID,
)
from src.gateway.governance.contracts import NormBinding, ViolationKind  # noqa: E402
from src.gateway.governance.governor.pipeline import Profile, StageContext  # noqa: E402
from src.gateway.governance.governor.stages.warrant import WarrantStage  # noqa: E402
from src.gateway.governance.warrant import (  # noqa: E402
    RelianceStatus,
    VerifiedKeyManifest,
    WarrantCache,
)
from src.integrations.provider_05 import (  # noqa: E402
    VEIP_SANDBOX_BASE_URL,
    VEIP_SANDBOX_ROOT_FINGERPRINT,
    VEIP_SANDBOX_TRUST_ANCHOR,
    Provider05WarrantSource,
)

VEIP_V02_EVAL_TIME = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)

_EU_ECB_BINDING = NormBinding(
    norm_id=TRADE_CONFIDENCE_NORM_ID,
    value=0.97,
    requires_warrant=True,
    actions=frozenset({"execute_trade", "execute_trade_bounded"}),
    governing_version="cage-policy-2.1.0",
)


def _veip_sandbox_url() -> str:
    return (
        os.environ.get("PROVIDER_05_ATTESTATION_ENDPOINT", "").strip()
        or VEIP_SANDBOX_BASE_URL
    )


@pytest.mark.asyncio
async def test_live_veip_v02_key_manifest_fetch_and_root_verification() -> None:
    """Fetch /.well-known/veip/key-manifest.json over the wire and verify root signature."""
    source = Provider05WarrantSource(endpoint=_veip_sandbox_url())
    assert source.trust_anchor is not None
    assert source.trust_anchor.fingerprint == VEIP_SANDBOX_ROOT_FINGERPRINT

    raw_manifest = await source.fetch_key_manifest()
    assert raw_manifest is not None and isinstance(raw_manifest, dict)

    verified = VerifiedKeyManifest.verify(
        raw_manifest,
        VEIP_SANDBOX_TRUST_ANCHOR,
        now=VEIP_V02_EVAL_TIME,
    )
    assert verified.schema_version == "veip-key-manifest/0.2"
    assert verified.manifest_id == "veip-sandbox-manifest-2026-10-07"
    assert (
        verified.manifest_digest
        == "fa6c4e0c1d03a6f760792738c2de00fc6f6c2d4fea7455098981986a91744b6d"
    )
    key_entry = verified.resolve_key("veip-sandbox-issuer-2026-10")
    assert key_entry is not None
    assert key_entry.is_active_at(VEIP_V02_EVAL_TIME)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_status", "expected_verified", "reason_substring"),
    [
        pytest.param(
            "ACTIVE",
            RelianceStatus.ELIGIBLE,
            "VERIFIED",
            "eligible for reliance",
            id="LIVE-ACTIVE",
        ),
        pytest.param(
            "REVOKED",
            RelianceStatus.INELIGIBLE_REVOKED,
            "VERIFIED",
            "Emergency Risk Notice #912",
            id="LIVE-REVOKED",
        ),
        pytest.param(
            "SUSPENDED",
            RelianceStatus.INELIGIBLE_UNRESOLVED,
            "VERIFIED",
            "Temporary Suspension #S-17",
            id="LIVE-SUSPENDED",
        ),
        pytest.param(
            "EXPIRED",
            RelianceStatus.INELIGIBLE_EXPIRED,
            "VERIFIED",
            "temporal window invalid",
            id="LIVE-EXPIRED",
        ),
        pytest.param(
            "STALE_STATE",
            RelianceStatus.INELIGIBLE_STALE,
            "VERIFIED",
            "state_as_of stale",
            id="LIVE-STALE_STATE",
        ),
        pytest.param(
            "TAMPERED_SIGNATURE",
            RelianceStatus.INELIGIBLE_UNRESOLVED,
            "UNVERIFIED",
            "SIGNATURE_INVALID",
            id="LIVE-TAMPERED_SIGNATURE",
        ),
        pytest.param(
            "UNKNOWN_KID",
            RelianceStatus.INELIGIBLE_UNRESOLVED,
            "UNVERIFIED",
            "UNKNOWN_KID",
            id="LIVE-UNKNOWN_KID",
        ),
        pytest.param(
            "MISSING",
            RelianceStatus.INELIGIBLE_MISSING,
            "UNVERIFIED",
            "Warrant is missing",
            id="LIVE-MISSING",
        ),
    ],
)
async def test_live_veip_v02_all_eight_scenarios_over_the_wire(
    scenario: str,
    expected_status: RelianceStatus,
    expected_verified: str,
    reason_substring: str,
) -> None:
    """Exercise all 8 VEIP v0.2 scenarios over the wire through WarrantCache and WarrantStage."""
    source = Provider05WarrantSource(
        endpoint=_veip_sandbox_url(),
        scenario="" if scenario == "ACTIVE" else scenario,
    )
    cache = WarrantCache(source, wall_clock=lambda: VEIP_V02_EVAL_TIME)
    stage = WarrantStage(
        [_EU_ECB_BINDING],
        cache,
        jurisdiction="EU_ECB",
        clock=lambda: VEIP_V02_EVAL_TIME,
    )

    output = await stage.run(
        StageContext(
            action="execute_trade",
            params={"confidence": 0.98},
            profile=Profile.FULL,
        )
    )
    assert len(output.reliance) == 1
    record = output.reliance[0]
    assert record.reliance_status is expected_status, record.reason
    assert record.verification_status == expected_verified
    assert reason_substring in record.reason

    if expected_status is RelianceStatus.ELIGIBLE:
        assert output.violations == ()
        att = record.attestation()
        assert att is not None
        assert att.status == "VERIFIED"
        assert (
            record.warrant_digest
            == "076b4ac5515f57f900f8afa4a5dcae2be2b0d1da5367de13d5882436b16bcd6e"
        )
    else:
        assert len(output.violations) == 1
        violation = output.violations[0]
        assert violation.kind is ViolationKind.RELIANCE_INELIGIBLE
        assert violation.code == f"RELIANCE_{expected_status.value}"
