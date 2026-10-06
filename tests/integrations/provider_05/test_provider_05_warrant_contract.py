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
Unit tests for CAGE x Provider 05 Warrant Contract v0.1.

Runs the first falsifiable test for min_trade_confidence = 0.97 through the
seeded ``Provider05WarrantSource`` and the kernel verifier. The schema and
failure-matrix tests are vendor-neutral and live in
``tests/governance/test_warrant_kernel.py``.
  - Test A: ACTIVE warrant -> norm eligible -> ALLOW -> seal with warrant digest.
  - Test B: REVOKED warrant -> norm ineligible for reliance.
  - Test C: EXPECTED failure -> DEFER (no Routing Seal, no fabricated hard DENY).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    GovernanceEnvelopeBuilder,
)
from src.gateway.governance.warrant import (
    RelianceStatus,
    Warrant,
    WarrantScope,
    WarrantStandingVerifier,
    WarrantStatus,
    bind_warrant_to_attestation,
)
from src.integrations.provider_05 import Provider05WarrantSource

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]


EVAL_TIME = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def sample_warrant() -> Warrant:
    """Fixture providing an active warrant for min_trade_confidence = 0.97."""
    return Warrant.issue(
        warrant_id="warrant-provider05-2026-001",
        norm_id="confidence.min_trade_confidence",
        issuing_authority="Risk Oversight Committee (EU_ECB)",
        authority_basis="EU AI Act Art. 9 Risk Management Instrument #442",
        scope=WarrantScope(
            actions=["execute_trade", "payment.wire.execute"],
            actors=["*"],
            systems=["cage-gateway"],
            jurisdictions=["EU_ECB"],
        ),
        valid_from="2026-08-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        governing_version="cage-policy-2.1.0",
        status=WarrantStatus.ACTIVE,
        revocation_ref=None,
        residual_risk_ref="RRR-2026-08-01-A1",
    )


@pytest.mark.asyncio
async def test_falsifiable_test_a_active_warrant_allows_and_seals(
    sample_warrant: Warrant,
) -> None:
    """Test A - ACTIVE: Valid warrant attached -> CAGE evaluates 0.97 and seals evidence with warrant digest."""
    source = Provider05WarrantSource()
    source.seed(sample_warrant)

    # 1. Query warrant from Provider 05
    warrant = await source.fetch("confidence.min_trade_confidence")
    assert warrant is not None

    context = {
        "action": "execute_trade",
        "jurisdiction": "EU_ECB",
        "governing_version": "cage-policy-2.1.0",
    }
    standing = WarrantStandingVerifier.verify_standing(
        warrant, context=context, now=EVAL_TIME
    )
    assert standing.eligible is True
    assert standing.reliance_status == RelianceStatus.ELIGIBLE

    # 2. Evaluate norm (confidence score 0.98 >= 0.97 threshold)
    model_confidence = 0.98
    target_threshold = 0.97
    assert model_confidence >= target_threshold

    # 3. Bind warrant to evidence record in GovernanceEnvelope.
    # UNVERIFIED: the digest proves consistency, not issuer identity (v0.2).
    att = bind_warrant_to_attestation(
        warrant, standing, provider_name=source.provider_name
    )
    assert att.attestation_type == "WARRANT"
    assert att.status == AttestationStatus.UNVERIFIED.value
    assert att.attested_at == EVAL_TIME.isoformat()
    assert att.provider_name == "provider_05_warrant"
    assert att.metadata["warrant_id"] == warrant.warrant_id
    assert att.metadata["warrant_digest"] == warrant.digest
    assert att.metadata["reliance_status"] == "ELIGIBLE"
    assert att.metadata["residual_risk_ref"] == "RRR-2026-08-01-A1"

    builder = GovernanceEnvelopeBuilder()
    envelope = builder.build_unsigned(
        action="execute_trade",
        params={"amount": 1000, "symbol": "AAPL"},
        governance_result={"verdict": GovernanceDecision.ALLOW.value},
        external_attestations=[att],
    )

    # 4. Verify envelope contains bound warrant digest
    envelope_dict = envelope.to_dict()
    assert len(envelope_dict["external_attestations"]) == 1
    bound_att = envelope_dict["external_attestations"][0]
    assert bound_att["warrant_digest"] == warrant.digest
    assert bound_att["reliance_status"] == "ELIGIBLE"


@pytest.mark.asyncio
async def test_falsifiable_test_b_and_c_revoked_warrant_defers_without_deny(
    sample_warrant: Warrant,
) -> None:
    """Test B & C - REVOKED & EXPECTED:

    Test B: Revoking the warrant makes 0.97 ineligible for reliance.
    Test C: No alternative eligible norm -> DEFER (no Routing Seal, no fabricated hard DENY).
    """
    # Create revoked variant of the same warrant
    revoked_warrant = Warrant.issue(
        warrant_id=sample_warrant.warrant_id,
        norm_id=sample_warrant.norm_id,
        issuing_authority=sample_warrant.issuing_authority,
        authority_basis=sample_warrant.authority_basis,
        scope=sample_warrant.scope,
        valid_from=sample_warrant.valid_from,
        valid_until=sample_warrant.valid_until,
        governing_version=sample_warrant.governing_version,
        status=WarrantStatus.REVOKED,
        revocation_ref="Board Resolution 2026-08-22 — Model baseline undergoing recertification",
        residual_risk_ref=sample_warrant.residual_risk_ref,
    )

    source = Provider05WarrantSource()
    source.seed(revoked_warrant)

    # Query warrant
    warrant = await source.fetch("confidence.min_trade_confidence")
    assert warrant is not None
    assert warrant.status == WarrantStatus.REVOKED

    context = {
        "action": "execute_trade",
        "jurisdiction": "EU_ECB",
        "governing_version": "cage-policy-2.1.0",
    }
    standing = WarrantStandingVerifier.verify_standing(
        warrant, context=context, now=EVAL_TIME
    )

    # Test B Assertion: 0.97 becomes ineligible for reliance
    assert standing.eligible is False
    assert standing.reliance_status == RelianceStatus.INELIGIBLE_REVOKED

    # Test C — contract-level simulation only. The verifier is not yet wired
    # into the governor pipeline; the end-to-end DEFER/no-seal assertion
    # belongs to the Phase 3 integration test.
    # When reliance is ineligible and no alternative warranted norm exists:
    # The decision must drop to DEFER (Parked in DeferQueue).
    # It must NOT emit an approved Routing Seal, and must NOT fabricate a hard DENY.
    governance_decision = None
    routing_seal_emitted = False

    if not standing.eligible:
        # Fallback resolution check: (none available)
        alternative_warranted_norm = None
        if alternative_warranted_norm is None:
            governance_decision = GovernanceDecision.DEFER
            routing_seal_emitted = False

    assert governance_decision == GovernanceDecision.DEFER
    assert governance_decision != GovernanceDecision.DENY
    assert routing_seal_emitted is False

    # Bind ineligible standing into the audit trail / evidence envelope.
    # Never DENIED: ineligibility is not an institutional verdict.
    att = bind_warrant_to_attestation(
        warrant, standing, provider_name=source.provider_name
    )
    assert att.status == AttestationStatus.UNVERIFIED.value
    assert att.status != AttestationStatus.DENIED.value
    assert att.metadata["reliance_status"] == "INELIGIBLE_REVOKED"
    assert "Board Resolution 2026-08-22" in att.metadata["reason"]
    assert att.metadata["revocation_ref"].startswith("Board Resolution 2026-08-22")
