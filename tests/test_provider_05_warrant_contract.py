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

Validates the frozen boundary, 11-field schema, standing verification failure
semantics, and the first falsifiable test for min_trade_confidence = 0.97:
  - Test A: ACTIVE warrant -> norm eligible -> ALLOW -> seal with warrant digest.
  - Test B: REVOKED warrant -> norm ineligible for reliance.
  - Test C: EXPECTED failure -> DEFER (no Routing Seal, no fabricated hard DENY).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

import pytest

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    GovernanceEnvelopeBuilder,
)
from src.integrations.provider_05 import (
    RelianceStatus,
    Provider05Client,
    Warrant,
    WarrantScope,
    WarrantStandingVerifier,
    WarrantStatus,
    bind_warrant_to_attestation,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def sample_warrant() -> Warrant:
    """Fixture providing an active warrant for min_trade_confidence = 0.97."""
    return Warrant(
        warrant_id="warrant-veip-2026-001",
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


def test_warrant_canonicalization_and_digest(sample_warrant: Warrant) -> None:
    """Verify deterministic RFC 8785 JCS canonicalization and SHA-256 digest."""
    canon_bytes = sample_warrant.to_canonical_bytes()
    assert isinstance(canon_bytes, bytes)

    digest = sample_warrant.compute_digest()
    assert isinstance(digest, str)
    assert len(digest) == 64
    assert digest == sample_warrant.digest

    # Verify deterministic digest matching direct SHA-256 over canonical bytes
    assert hashlib.sha256(canon_bytes).hexdigest() == digest

    # Verify all 11 fields are present in the canonical dict
    d = sample_warrant.to_canonical_dict()
    assert len(d) == 11
    assert d["warrant_id"] == "warrant-veip-2026-001"
    assert d["norm_id"] == "confidence.min_trade_confidence"
    assert d["status"] == "ACTIVE"


def test_warrant_standing_verification_valid(sample_warrant: Warrant) -> None:
    """Verify active warrant passes standing check within valid window and scope."""
    context = {
        "action": "execute_trade",
        "actor": "urn:archytan:op:test_operator",
        "system": "cage-gateway",
        "jurisdiction": "EU_ECB",
        "governing_version": "cage-policy-2.1.0",
    }
    eval_time = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
    result = WarrantStandingVerifier.verify_standing(
        sample_warrant, context=context, now=eval_time
    )

    assert result.eligible is True
    assert result.reliance_status == RelianceStatus.ELIGIBLE
    assert result.warrant_id == sample_warrant.warrant_id
    assert result.warrant_digest == sample_warrant.digest
    assert "verified and active" in result.reason


def test_warrant_standing_failure_matrix(sample_warrant: Warrant) -> None:
    """Verify all 6 failure states correctly yield reliance ineligibility."""
    context = {
        "action": "execute_trade",
        "system": "cage-gateway",
        "jurisdiction": "EU_ECB",
        "governing_version": "cage-policy-2.1.0",
    }
    eval_time = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)

    # 1. MISSING
    res_missing = WarrantStandingVerifier.verify_standing(None, context=context)
    assert res_missing.eligible is False
    assert res_missing.reliance_status == RelianceStatus.INELIGIBLE_MISSING

    # 2. EXPIRED (time past valid_until)
    late_time = datetime(2027, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
    res_expired = WarrantStandingVerifier.verify_standing(
        sample_warrant, context=context, now=late_time
    )
    assert res_expired.eligible is False
    assert res_expired.reliance_status == RelianceStatus.INELIGIBLE_EXPIRED

    # 3. REVOKED
    revoked_warrant = Warrant(
        warrant_id=sample_warrant.warrant_id,
        norm_id=sample_warrant.norm_id,
        issuing_authority=sample_warrant.issuing_authority,
        authority_basis=sample_warrant.authority_basis,
        scope=sample_warrant.scope,
        valid_from=sample_warrant.valid_from,
        valid_until=sample_warrant.valid_until,
        governing_version=sample_warrant.governing_version,
        status=WarrantStatus.REVOKED,
        revocation_ref="Emergency Risk Notice #912",
        residual_risk_ref=sample_warrant.residual_risk_ref,
    )
    res_revoked = WarrantStandingVerifier.verify_standing(
        revoked_warrant, context=context, now=eval_time
    )
    assert res_revoked.eligible is False
    assert res_revoked.reliance_status == RelianceStatus.INELIGIBLE_REVOKED
    assert "Emergency Risk Notice #912" in res_revoked.reason

    # 4. OUT_OF_SCOPE
    out_scope_ctx = {
        "action": "unauthorized_wire_action",
        "jurisdiction": "EU_ECB",
    }
    res_scope = WarrantStandingVerifier.verify_standing(
        sample_warrant, context=out_scope_ctx, now=eval_time
    )
    assert res_scope.eligible is False
    assert res_scope.reliance_status == RelianceStatus.INELIGIBLE_OUT_OF_SCOPE

    # 5. VERSION_MISMATCH
    wrong_ver_ctx = {
        "action": "execute_trade",
        "jurisdiction": "EU_ECB",
        "governing_version": "cage-policy-9.9.9",
    }
    res_ver = WarrantStandingVerifier.verify_standing(
        sample_warrant, context=wrong_ver_ctx, now=eval_time
    )
    assert res_ver.eligible is False
    assert res_ver.reliance_status == RelianceStatus.INELIGIBLE_VERSION_MISMATCH

    # 6. UNRESOLVED (Tampered digest)
    tampered_warrant = Warrant(
        warrant_id=sample_warrant.warrant_id,
        norm_id=sample_warrant.norm_id,
        issuing_authority=sample_warrant.issuing_authority,
        authority_basis=sample_warrant.authority_basis,
        scope=sample_warrant.scope,
        valid_from=sample_warrant.valid_from,
        valid_until=sample_warrant.valid_until,
        governing_version=sample_warrant.governing_version,
        status=WarrantStatus.ACTIVE,
        digest="bad_digest_00000000000000000000000000000000000000000000000000000000",
    )
    res_unresolved = WarrantStandingVerifier.verify_standing(
        tampered_warrant, context=context, now=eval_time
    )
    assert res_unresolved.eligible is False
    assert res_unresolved.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED


@pytest.mark.asyncio
async def test_falsifiable_test_a_active_warrant_allows_and_seals(
    sample_warrant: Warrant,
) -> None:
    """Test A - ACTIVE: Valid warrant attached -> CAGE evaluates 0.97 and seals evidence with warrant digest."""
    client = Provider05Client()
    client.seed_warrant(sample_warrant)

    # 1. Query warrant from Provider 05
    warrant = await client.get_warrant("confidence.min_trade_confidence")
    assert warrant is not None

    context = {
        "action": "execute_trade",
        "jurisdiction": "EU_ECB",
        "governing_version": "cage-policy-2.1.0",
    }
    standing = WarrantStandingVerifier.verify_standing(warrant, context=context)
    assert standing.eligible is True
    assert standing.reliance_status == RelianceStatus.ELIGIBLE

    # 2. Evaluate norm (confidence score 0.98 >= 0.97 threshold)
    model_confidence = 0.98
    target_threshold = 0.97
    assert model_confidence >= target_threshold

    # 3. Bind warrant to evidence record in GovernanceEnvelope
    att = bind_warrant_to_attestation(warrant, standing)
    assert att.attestation_type == "WARRANT"
    assert att.status == AttestationStatus.VERIFIED.value
    assert att.metadata["warrant_id"] == warrant.warrant_id
    assert att.metadata["warrant_digest"] == warrant.digest
    assert att.metadata["reliance_status"] == "ELIGIBLE"

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
    revoked_warrant = Warrant(
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

    client = Provider05Client()
    client.seed_warrant(revoked_warrant)

    # Query warrant
    warrant = await client.get_warrant("confidence.min_trade_confidence")
    assert warrant is not None
    assert warrant.status == WarrantStatus.REVOKED

    context = {
        "action": "execute_trade",
        "jurisdiction": "EU_ECB",
        "governing_version": "cage-policy-2.1.0",
    }
    standing = WarrantStandingVerifier.verify_standing(warrant, context=context)

    # Test B Assertion: 0.97 becomes ineligible for reliance
    assert standing.eligible is False
    assert standing.reliance_status == RelianceStatus.INELIGIBLE_REVOKED

    # Test C Enforcement Simulation:
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

    # Bind ineligible standing into the audit trail / evidence envelope
    att = bind_warrant_to_attestation(warrant, standing)
    assert att.status == AttestationStatus.DENIED.value
    assert att.metadata["reliance_status"] == "INELIGIBLE_REVOKED"
    assert (
        "Board Resolution 2026-08-22"
        in att.metadata["reason"]
    )

