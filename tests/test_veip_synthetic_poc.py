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
VEIP Synthetic Proof-of-Concept Test Suite (Treasury Transfer).

Validates all 6 success criteria from §8.4 of plans/veip_three_axioms_architecture.md:
  1. End-to-end envelope round-trip with all 3 axioms (BLUEPRINT, KEY, PHYSICS)
  2. Canonicalization parity (RFC 8785 JCS determinism)
  3. Signature tamper-evidence over external_attestations[]
  4. Trust-domain admissibility handoff gating (negative test)
  5. Fail-open resilience when VEIP endpoint is unavailable
  6. OSCAL four-state finding vocabulary ingestion
"""

import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.gateway.governance.attestation_aggregator import AttestationAggregator
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
    GovernanceEnvelope,
    GovernanceEnvelopeBuilder,
    IssuerMetadata,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.normative_provider import (
    FindingStatus,
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.veip import (
    AdmissibilityGrant,
    RiskAcceptanceRecord,
    SubstrateAttestation,
    VEIPBlueprintProvider,
    VEIPClient,
    VEIPKeyProvider,
    VEIPPhysicsProvider,
)


@pytest.fixture
def ec_key_pair():
    """Generate EC P-256 key pair for signing tests."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, public_pem


@pytest.fixture
def seeded_veip_client():
    """Create a VEIPClient seeded with valid records for the Treasury Transfer PoC."""
    client = VEIPClient()

    # Axiom 1 (Blueprint): AO risk-acceptance for THR-FIN-006 ($10,000 consensus trigger)
    client.seed_risk_acceptance(
        RiskAcceptanceRecord(
            threshold_id="THR-FIN-006",
            threshold_value=10000.0,
            ao_name="Jane Doe, CISO / AO",
            ao_signature_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            receipt_id="veip-blueprint-rec-9821",
            attested_at="2026-08-21T06:00:00.000Z",
            rationale="Approved $10k threshold per Q3 Risk Committee Charter",
        )
    )

    # Axiom 2 (Key): Admissibility grant for treasury-agent SPIFFE ID on consequence class
    client.seed_admissibility_grant(
        AdmissibilityGrant(
            spiffe_id="spiffe://cage.local/treasury-agent",
            consequence_class="treasury_transfer",
            ca_fingerprint="sha256:a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            receipt_id="veip-key-grant-4412",
            attested_at="2026-08-21T11:58:00.000Z",
            admitted=True,
        )
    )

    # Axiom 3 (Physics): Substrate attestation for test GKE node
    client.seed_substrate_attestation(
        SubstrateAttestation(
            node_id="gke-node-us-central1-01",
            vtpm_status="VERIFIED",
            ebpf_anomaly_count=0,
            receipt_id="veip-physics-att-7789",
            attested_at="2026-08-21T11:59:48.000Z",
            freshness_seconds=12,
        )
    )

    return client


# ---------------------------------------------------------------------------
# Success Criterion 1: End-to-End Envelope Round-Trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_criterion_1_end_to_end_envelope_round_trip(
    seeded_veip_client, ec_key_pair
):
    """Verify $25k Treasury Transfer produces signed envelope with 3 VERIFIED attestations."""
    private_key, _, public_pem = ec_key_pair

    # 1. Initialize Aggregator with all Three Axiom providers
    aggregator = AttestationAggregator(
        providers=[
            VEIPBlueprintProvider(client=seeded_veip_client),
            VEIPKeyProvider(client=seeded_veip_client),
            VEIPPhysicsProvider(client=seeded_veip_client),
        ]
    )
    await aggregator.boot_fetch()

    cached_attestations = aggregator.get_cached_attestations()
    assert len(cached_attestations) == 3

    # 2. Build Governance Envelope for Treasury Transfer ($25,000)
    builder = GovernanceEnvelopeBuilder()
    envelope = builder.build_unsigned(
        action="execute_treasury_transfer",
        params={
            "amount": 25000.00,
            "currency": "USD",
            "source_account": "treasury-ops-001",
            "destination_account": "counterparty-settlement-004",
            "initiating_agent_id": "treasury-agent-prod-v1",
            "trust_domain": "spiffe://cage.local/treasury-agent",
        },
        governance_result={
            "verdict": "ALLOW",
            "tiers_evaluated": ["stpa", "cbf", "opa", "consensus", "fria"],
            "consensus_score": 0.98,
        },
        external_attestations=cached_attestations,
    )

    # 3. Verify envelope structure and all three attestation types
    assert envelope.envelope_version == "2.1"
    assert len(envelope.external_attestations) == 3

    types = {att.attestation_type for att in envelope.external_attestations}
    assert types == {"BLUEPRINT", "KEY", "PHYSICS"}

    for att in envelope.external_attestations:
        assert att.status == AttestationStatus.VERIFIED.value
        assert att.receipt_id.startswith("veip-")

    # 4. Sign and verify envelope with mock key
    digest = envelope.compute_digest()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils

    der_signature = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    r, s = utils.decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    signed_env = builder.attach_signature(
        envelope=envelope,
        signature_bytes=raw_signature,
        kid="test-key-01",
        algorithm="ES256",
    )

    with pytest.MonkeyPatch.context() as mp:
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        jwks.add_key(public_pem, kid="test-key-01")
        mp.setattr("src.gateway.governance.jwks.get_jwks", lambda: jwks)

        assert builder.verify(signed_env) is True


# ---------------------------------------------------------------------------
# Success Criterion 2: Canonicalization Parity
# ---------------------------------------------------------------------------


def test_criterion_2_canonicalization_parity(seeded_veip_client):
    """Verify VEIP records and CAGE compute identical RFC 8785 JCS digests."""
    bp_record = seeded_veip_client._risk_acceptances["THR-FIN-006"]

    # VEIP record canonical bytes
    veip_bytes = bp_record.to_canonical_bytes()
    veip_digest = hashlib.sha256(veip_bytes).hexdigest()

    # CAGE JCS canonicalizer on raw dictionary
    cage_bytes = jcs_canonicalize_plan(
        {
            "threshold_id": "THR-FIN-006",
            "threshold_value": 10000.0,
            "ao_name": "Jane Doe, CISO / AO",
            "ao_signature_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "receipt_id": "veip-blueprint-rec-9821",
            "attested_at": "2026-08-21T06:00:00.000Z",
            "rationale": "Approved $10k threshold per Q3 Risk Committee Charter",
        }
    )
    cage_digest = hashlib.sha256(cage_bytes).hexdigest()

    assert veip_bytes == cage_bytes
    assert veip_digest == cage_digest


# ---------------------------------------------------------------------------
# Success Criterion 3: Signature Tamper-Evidence
# ---------------------------------------------------------------------------


def test_criterion_3_signature_tamper_evidence(seeded_veip_client, ec_key_pair):
    """Verify mutating any field inside external_attestations[] fails signature verification."""
    private_key, _, public_pem = ec_key_pair

    att = ExternalAttestation(
        attestation_type="BLUEPRINT",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="veip-blueprint-rec-9821",
        attested_at="2026-08-21T06:00:00.000Z",
        metadata={"threshold_id": "THR-FIN-006"},
    )

    builder = GovernanceEnvelopeBuilder()
    envelope = builder.build_unsigned(
        action="execute_treasury_transfer",
        params={"amount": 25000.0},
        governance_result={"verdict": "ALLOW"},
        external_attestations=[att],
    )

    digest = envelope.compute_digest()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils

    der_sig = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    signed_env = builder.attach_signature(
        envelope, raw_sig, kid="key-1", algorithm="ES256"
    )

    with pytest.MonkeyPatch.context() as mp:
        from src.gateway.governance.jwks import JWKSet

        jwks = JWKSet()
        jwks.add_key(public_pem, kid="key-1")
        mp.setattr("src.gateway.governance.jwks.get_jwks", lambda: jwks)

        # Untampered verifies
        assert builder.verify(signed_env) is True

        # Tamper 1: Mutate receipt_id
        env_tampered_receipt = builder._envelope_from_dict(signed_env.to_dict())
        env_tampered_receipt.external_attestations[0].receipt_id = "veip-FORGED-receipt"
        assert builder.verify(env_tampered_receipt) is False

        # Tamper 2: Mutate status from VERIFIED to DENIED
        env_tampered_status = builder._envelope_from_dict(signed_env.to_dict())
        env_tampered_status.external_attestations[0].status = "DENIED"
        assert builder.verify(env_tampered_status) is False

        # Tamper 3: Mutate metadata payload
        env_tampered_meta = builder._envelope_from_dict(signed_env.to_dict())
        env_tampered_meta.external_attestations[0].metadata["threshold_id"] = (
            "THR-MALICIOUS-999"
        )
        assert builder.verify(env_tampered_meta) is False


# ---------------------------------------------------------------------------
# Success Criterion 4: Trust-Domain Admissibility Negative Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_criterion_4_trust_domain_admissibility_negative_test(seeded_veip_client):
    """Verify unauthorized SPIFFE ID produces status: DENIED."""
    provider = VEIPKeyProvider(client=seeded_veip_client)

    # 1. Valid admitted agent
    valid_att = await provider.fetch_attestations(
        {
            "spiffe_id": "spiffe://cage.local/treasury-agent",
            "consequence_class": "treasury_transfer",
        }
    )
    assert len(valid_att) == 1
    assert valid_att[0].status == AttestationStatus.VERIFIED.value

    # 2. Seed an explicit DENIED grant for an unauthorized agent
    seeded_veip_client.seed_admissibility_grant(
        AdmissibilityGrant(
            spiffe_id="spiffe://cage.local/unauthorized-agent",
            consequence_class="treasury_transfer",
            ca_fingerprint="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            receipt_id="veip-key-grant-denied-001",
            attested_at="2026-08-21T12:00:00.000Z",
            admitted=False,
        )
    )

    denied_att = await provider.fetch_attestations(
        {
            "spiffe_id": "spiffe://cage.local/unauthorized-agent",
            "consequence_class": "treasury_transfer",
        }
    )
    assert len(denied_att) == 1
    assert denied_att[0].status == AttestationStatus.DENIED.value


# ---------------------------------------------------------------------------
# Success Criterion 5: Fail-Open Resilience
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_criterion_5_fail_open_resilience():
    """Verify empty/offline VEIP client emits STALE attestation without crashing."""
    empty_client = VEIPClient()  # No seeded records and no live endpoint
    provider = VEIPBlueprintProvider(client=empty_client)

    attestations = await provider.fetch_attestations({"threshold_id": "THR-FIN-006"})
    assert len(attestations) == 1
    assert attestations[0].status == AttestationStatus.STALE.value
    assert attestations[0].metadata["error"] == "Record not found"


# ---------------------------------------------------------------------------
# Success Criterion 6: OSCAL Four-State Vocabulary Alignment
# ---------------------------------------------------------------------------


def test_criterion_6_oscal_finding_vocabulary():
    """Verify FindingStatus vocabulary and ValidationResult integration."""
    # Ensure FindingStatus contains all 4 standard OSCAL assessment states
    assert FindingStatus.PASS.value == "pass"
    assert FindingStatus.FAIL.value == "fail"
    assert FindingStatus.NOT_APPLICABLE.value == "not_applicable"
    assert FindingStatus.ERROR.value == "error"

    # Construct ValidationResult with OSCAL findings
    findings = [
        {
            "control_id": "CTRL_OPA_001",
            "status": FindingStatus.PASS.value,
            "detail": "Policy met",
        },
        {
            "control_id": "CTRL_CBF_001",
            "status": FindingStatus.PASS.value,
            "detail": "Balance above floor",
        },
    ]
    result = ValidationResult(admitted=True, findings=findings)
    assert result.admitted is True
    assert len(result.findings) == 2
    assert all(f["status"] == FindingStatus.PASS.value for f in result.findings)

    # NormativeBaseline JCS profile_hash verification
    baseline = NormativeBaseline(
        region="US_FED",
        profile={"consensus_threshold": 10000.0, "risk_acceptance_id": "RA-001"},
    )
    expected_canon = jcs_canonicalize_plan(
        {"consensus_threshold": 10000.0, "risk_acceptance_id": "RA-001"}
    )
    assert baseline.profile_hash == hashlib.sha256(expected_canon).hexdigest()
