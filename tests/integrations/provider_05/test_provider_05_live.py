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

"""Live over-the-wire tests for Provider 05 (VEIP warrant reliance, v0.2).

Runs the deployed VEIP v0.2 sandbox through ``WarrantCache`` and
``WarrantStage``: the root-signed key manifest, all eight warrant scenarios,
and alignment with the JCAR-001 comparison target
(``docs/partners/provider_05/veip_v02/``). The sandbox is public, so the suite
needs no credentials. ``PROVIDER_05_ATTESTATION_ENDPOINT`` overrides its URL.

VEIP has not deployed the v0.3 blueprint registry, so those live tests sit
outside the partner harness, in ``test_provider_05_blueprint_live.py``.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from src.cage_finance.tiers.trade_confidence_tier import TRADE_CONFIDENCE_NORM_ID
from src.gateway.governance.contracts import NormBinding, ViolationKind
from src.gateway.governance.governor.pipeline import Profile, StageContext
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.warrant import (
    RelianceStatus,
    VerifiedKeyManifest,
    WarrantCache,
)
from src.integrations.provider_05 import (
    VEIP_SANDBOX_BASE_URL,
    VEIP_SANDBOX_ROOT_FINGERPRINT,
    VEIP_SANDBOX_TRUST_ANCHOR,
    Provider05WarrantSource,
)

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]

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
            RelianceStatus.INELIGIBLE_SUSPENDED,
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
            RelianceStatus.INELIGIBLE_AUTHENTICITY,
            "UNVERIFIED",
            "SIGNATURE_INVALID",
            id="LIVE-TAMPERED_SIGNATURE",
        ),
        pytest.param(
            "UNKNOWN_KID",
            RelianceStatus.INELIGIBLE_AUTHENTICITY,
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


@pytest.mark.asyncio
async def test_live_veip_v02_alignment_against_jcar_comparison_target() -> None:
    """Verify all 8 live wire scenarios match the VEIP JCAR-001 expected target."""
    import json
    from pathlib import Path

    jcar_path = (
        Path(__file__).resolve().parents[3]
        / "docs"
        / "partners"
        / "provider_05"
        / "veip_v02"
        / "CAGE_VEIP_v0.2_JCAR_001_BASELINE.json"
    )
    baseline = json.loads(jcar_path.read_text(encoding="utf-8"))

    for target in baseline["comparison"]:
        scenario = target["scenario"]
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
        (record,) = output.reliance
        observed_consequence = "ALLOW" if not output.violations else "DEFER"
        assert record.reliance_status.value == target["expected_reliance_status"]
        assert record.verification_status == target["observed_verification_status"]
        assert observed_consequence == target["observed_gateway_consequence"]
        if "observed_verification_reason" in target:
            assert record.reason.startswith(target["observed_verification_reason"])
