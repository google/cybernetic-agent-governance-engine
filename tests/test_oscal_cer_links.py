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
tests/test_oscal_cer_links.py — Tests for NexArt CER URI embedding in OSCAL
Assessment Results (Feature 2).

Verification invariants:
  1. links[] array is present when CER URIs are provided.
  2. links[] is absent when no CER URIs are provided (backward compat).
  3. CER hash is extracted from URI and added as a prop.
  4. Only findings with matching control_id get CER links.
  5. rel='evidence' semantics are correct per OSCAL spec.
"""

from __future__ import annotations

import json

import pytest

from src.compliance_bridge.oscal_exporter import (
    build_oscal_assessment_results,
    findings_from_metrics_dict,
)
from src.compliance_bridge.types import OscalFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(control_id: str, result: str = "PASS") -> OscalFinding:
    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}-cer",
        safety_rate=1.0 if result == "PASS" else 0.5,
        evidence_age_s=120.0,
    )


# ---------------------------------------------------------------------------
# Test 1: CER links present when URIs provided
# ---------------------------------------------------------------------------

def test_cer_links_present_when_uris_provided():
    """Findings get links[] array when cer_uris mapping includes their control_id."""
    findings = [_finding("A.5.3")]
    cer_uris = {
        "A.5.3": "https://verify.nexart.io/cer/abc123def456",
    }

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="cer-test-001",
        cer_uris=cer_uris,
    )

    oscal_findings = doc["assessment-results"]["results"][0]["findings"]
    assert len(oscal_findings) == 1

    finding = oscal_findings[0]
    assert "links" in finding
    assert len(finding["links"]) == 1

    link = finding["links"][0]
    assert link["href"] == "https://verify.nexart.io/cer/abc123def456"
    assert link["rel"] == "evidence"
    assert "NexArt CER" in link["text"]


# ---------------------------------------------------------------------------
# Test 2: No links when CER URIs not provided (backward compat)
# ---------------------------------------------------------------------------

def test_no_cer_links_without_uris():
    """Without cer_uris parameter, findings have no links[] array."""
    findings = [_finding("A.5.3")]

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="cer-test-002",
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]
    assert "links" not in finding


def test_no_cer_links_with_empty_uris():
    """With empty cer_uris dict, findings have no links[]."""
    findings = [_finding("A.5.3")]

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="cer-test-003",
        cer_uris={},
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]
    assert "links" not in finding


# ---------------------------------------------------------------------------
# Test 3: CER hash extracted as prop
# ---------------------------------------------------------------------------

def test_cer_hash_prop_extracted():
    """CER hash is extracted from URI and added as a 'cer-hash' prop."""
    findings = [_finding("SC-4")]
    cer_uris = {
        "SC-4": "https://verify.nexart.io/cer/deadbeef12345678",
    }

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="cer-test-004",
        cer_uris=cer_uris,
    )

    finding = doc["assessment-results"]["results"][0]["findings"][0]
    cer_props = [p for p in finding["props"] if p["name"] == "cer-hash"]
    assert len(cer_props) == 1
    assert cer_props[0]["value"] == "deadbeef12345678"


# ---------------------------------------------------------------------------
# Test 4: Only matching findings get CER links
# ---------------------------------------------------------------------------

def test_only_matching_findings_get_cer_links():
    """When cer_uris has entries for some controls, only those get links."""
    findings = [
        _finding("A.5.3"),
        _finding("SC-4"),
        _finding("A.8.4"),
    ]
    cer_uris = {
        "A.5.3": "https://verify.nexart.io/cer/hash_a53",
        # SC-4 and A.8.4 intentionally missing
    }

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="cer-test-005",
        cer_uris=cer_uris,
    )

    oscal_findings = doc["assessment-results"]["results"][0]["findings"]

    for f in oscal_findings:
        control_id = f["target"]["target-id"]
        if control_id == "A.5.3":
            assert "links" in f, f"A.5.3 should have CER links"
        else:
            assert "links" not in f, f"{control_id} should NOT have CER links"


# ---------------------------------------------------------------------------
# Test 5: OSCAL rel='evidence' semantics
# ---------------------------------------------------------------------------

def test_evidence_rel_semantics():
    """CER links use rel='evidence' per OSCAL linking model."""
    findings = [_finding("A.5.3")]
    cer_uris = {"A.5.3": "https://verify.nexart.io/cer/test_hash"}

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="cer-test-006",
        cer_uris=cer_uris,
    )

    link = doc["assessment-results"]["results"][0]["findings"][0]["links"][0]
    assert link["rel"] == "evidence"
    assert link["href"].startswith("https://")


# ---------------------------------------------------------------------------
# Test 6: Document is valid JSON (round-trip)
# ---------------------------------------------------------------------------

def test_document_round_trips_with_cer_links():
    """OSCAL document with CER links round-trips through JSON serialization."""
    findings = [_finding("A.5.3"), _finding("SC-4")]
    cer_uris = {
        "A.5.3": "https://verify.nexart.io/cer/hash1",
        "SC-4": "https://verify.nexart.io/cer/hash2",
    }

    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id="cer-test-007",
        cer_uris=cer_uris,
    )

    # Round-trip through JSON
    serialized = json.dumps(doc, default=str)
    deserialized = json.loads(serialized)

    assert deserialized["assessment-results"]["results"][0]["findings"][0]["links"][0]["rel"] == "evidence"
