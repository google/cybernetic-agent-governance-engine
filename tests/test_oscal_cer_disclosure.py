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
tests/test_oscal_cer_disclosure.py — Tests for B6+B7 disclosure policy and
ContentAddress-based hash extraction.

Verification invariants:
  1. PUBLIC disclosure → link + cer-hash + cer-digest-alg props
  2. REDACTED disclosure → link + props + commitment-scheme metadata
  3. PRIVATE disclosure → props only, no link
  4. UNKNOWN disclosure → behaves as PRIVATE (fail-closed)
  5. Encoded and unencoded URIs produce identical cer-hash props
  6. CERIndex injection preserves backward compatibility (no index → no links)
"""

from __future__ import annotations

import pytest

from src.compliance_bridge.disclosure import Disclosure
from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
from src.compliance_bridge.types import OscalFinding
from src.integrations.provider_02.cer_index import Provider02CERIndex


def _finding(control_id: str, result: str = "PASS") -> OscalFinding:
    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}-disclosure",
        safety_rate=1.0 if result == "PASS" else 0.5,
        evidence_age_s=120.0,
    )


# ---------------------------------------------------------------------------
# Test 1: PUBLIC disclosure → link + structured props
# ---------------------------------------------------------------------------


def test_public_disclosure_emits_link_and_props():
    """PUBLIC disclosure emits link[rel=evidence] + cer-hash + cer-digest-alg."""
    findings = [_finding("SC-4")]
    cer_index = Provider02CERIndex(
        cer_uris={
            "SC-4": "https://verify.provider-02.example.com/cer/sha256:54647b2219e11e0db4c36bfd707b348b1f1e5e1ae6185c6e0e6ae75e4e1a5b2c"
        },
        disclosure_policies={"SC-4": Disclosure.PUBLIC},
    )

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="disclosure-test-001",
        cer_index=cer_index,
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]

    # Must have link
    assert "links" in finding
    assert len(finding["links"]) == 1
    assert finding["links"][0]["rel"] == "evidence"

    # Must have structured hash props
    props = finding["props"]
    cer_hash_props = [p for p in props if p["name"] == "cer-hash"]
    assert len(cer_hash_props) == 1
    assert (
        cer_hash_props[0]["value"]
        == "54647b2219e11e0db4c36bfd707b348b1f1e5e1ae6185c6e0e6ae75e4e1a5b2c"
    )

    cer_alg_props = [p for p in props if p["name"] == "cer-digest-alg"]
    assert len(cer_alg_props) == 1
    assert cer_alg_props[0]["value"] == "sha256"

    # Must NOT have commitment-scheme props (those are REDACTED-only)
    commitment_props = [p for p in props if p["name"] == "cer-commitment-scheme"]
    assert len(commitment_props) == 0


# ---------------------------------------------------------------------------
# Test 2: REDACTED disclosure → link + props + commitment metadata
# ---------------------------------------------------------------------------


def test_redacted_disclosure_emits_link_and_commitment_metadata():
    """REDACTED disclosure emits link + props + commitment-scheme metadata."""
    findings = [_finding("A.5.3")]
    cer_index = Provider02CERIndex(
        cer_uris={
            "A.5.3": "https://verify.provider-02.example.com/cer/sha256:abc123def456789012345678901234567890123456789012345678901234abcd"
        },
        disclosure_policies={"A.5.3": Disclosure.REDACTED},
    )

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="disclosure-test-002",
        cer_index=cer_index,
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]

    # Must have link (REDACTED still gets a link per Decision #2)
    assert "links" in finding
    assert finding["links"][0]["rel"] == "evidence"

    # Must have structured hash props
    props = finding["props"]
    cer_hash_props = [p for p in props if p["name"] == "cer-hash"]
    assert len(cer_hash_props) == 1
    assert (
        cer_hash_props[0]["value"]
        == "abc123def456789012345678901234567890123456789012345678901234abcd"
    )

    # Must have commitment-scheme metadata
    commitment_props = [p for p in props if p["name"] == "cer-commitment-scheme"]
    assert len(commitment_props) == 1
    assert commitment_props[0]["value"] == "confidential-field-hmac-sha256"

    redacted_fields_props = [p for p in props if p["name"] == "cer-redacted-fields"]
    assert len(redacted_fields_props) == 1
    assert redacted_fields_props[0]["value"] == "payload"


# ---------------------------------------------------------------------------
# Test 3: PRIVATE disclosure → props only, no link
# ---------------------------------------------------------------------------


def test_private_disclosure_emits_props_only():
    """PRIVATE disclosure emits cer-hash props but no dereferenceable link."""
    findings = [_finding("AC-3")]
    cer_index = Provider02CERIndex(
        cer_uris={
            "AC-3": "https://verify.provider-02.example.com/cer/sha256:deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
        },
        disclosure_policies={"AC-3": Disclosure.PRIVATE},
    )

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="disclosure-test-003",
        cer_index=cer_index,
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]

    # Must NOT have link
    # (AC-3 may have GCP Agent Registry link, but no CER link)
    if "links" in finding:
        cer_links = [link for link in finding["links"] if link["rel"] == "evidence"]
        assert len(cer_links) == 0

    # Must have props
    props = finding["props"]
    cer_hash_props = [p for p in props if p["name"] == "cer-hash"]
    assert len(cer_hash_props) == 1
    assert (
        cer_hash_props[0]["value"]
        == "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
    )


# ---------------------------------------------------------------------------
# Test 4: UNKNOWN disclosure → behaves as PRIVATE (fail-closed)
# ---------------------------------------------------------------------------


def test_unknown_disclosure_behaves_as_private():
    """UNKNOWN disclosure is treated as PRIVATE (fail-closed)."""
    findings = [_finding("SC-8")]
    cer_index = Provider02CERIndex(
        cer_uris={
            "SC-8": "https://verify.provider-02.example.com/cer/sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        },
        disclosure_policies={"SC-8": Disclosure.UNKNOWN},
    )

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="disclosure-test-004",
        cer_index=cer_index,
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]

    # Must NOT have link
    if "links" in finding:
        cer_links = [link for link in finding["links"] if link["rel"] == "evidence"]
        assert len(cer_links) == 0

    # Must have props
    props = finding["props"]
    cer_hash_props = [p for p in props if p["name"] == "cer-hash"]
    assert len(cer_hash_props) == 1
    assert (
        cer_hash_props[0]["value"]
        == "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    )


# ---------------------------------------------------------------------------
# Test 5: Encoded and unencoded URIs produce identical cer-hash props (B7)
# ---------------------------------------------------------------------------


def test_encoded_and_unencoded_uris_produce_identical_hash():
    """Encoded (sha256%3A...) and unencoded (sha256:...) URIs produce identical cer-hash."""
    findings = [_finding("IR-6"), _finding("AU-12")]
    cer_index = Provider02CERIndex(
        cer_uris={
            # Unencoded form
            "IR-6": "https://verify.provider-02.example.com/cer/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            # URL-encoded form (same hash)
            "AU-12": "https://verify.provider-02.example.com/cer/sha256%3A1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        },
        disclosure_policies={
            "IR-6": Disclosure.PUBLIC,
            "AU-12": Disclosure.PUBLIC,
        },
    )

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="disclosure-test-005",
        cer_index=cer_index,
    )

    oscal_findings = doc["assessment-results"]["results"][0]["findings"]

    # Extract cer-hash props
    ir6_finding = next(f for f in oscal_findings if f["target"]["target-id"] == "IR-6")
    au12_finding = next(
        f for f in oscal_findings if f["target"]["target-id"] == "AU-12"
    )

    ir6_hash = next(p["value"] for p in ir6_finding["props"] if p["name"] == "cer-hash")
    au12_hash = next(
        p["value"] for p in au12_finding["props"] if p["name"] == "cer-hash"
    )

    # The B7 regression: both forms must produce the same bare hex hash
    assert ir6_hash == au12_hash
    assert (
        ir6_hash == "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )


# ---------------------------------------------------------------------------
# Test 6: No CERIndex injected → output identical to legacy behavior
# ---------------------------------------------------------------------------


def test_no_cer_index_preserves_legacy_behavior():
    """Without a CERIndex, output is identical to current behavior (no links)."""
    findings = [_finding("A.5.3")]

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="disclosure-test-006",
        # No cer_uris, no cer_index
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]

    # Must not have links
    assert "links" not in finding

    # Must not have cer-hash props
    cer_hash_props = [p for p in finding["props"] if p["name"] == "cer-hash"]
    assert len(cer_hash_props) == 0


pytestmark = [pytest.mark.unit, pytest.mark.local]
