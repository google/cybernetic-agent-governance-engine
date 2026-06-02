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
tests/test_aarm_mapper.py — Unit tests for the AARM Threat Vector ledger (CAGE v2.0.0).

Verifies:
  - All 11 AARM vectors are present in the ledger
  - Each vector has required fields
  - build_aarm_conformance_report() correctly scores NEUTRALIZED / PARTIAL / EXPOSED
  - Critical vectors (AARM-V1, V2, V3, V4, V9, V10, V11) have CRITICAL severity
  - EXPOSED detection works for all-FAIL findings
  - NEUTRALIZED detection works for all-PASS findings
  - Schema version and aarm_spec_version are stable
"""

from __future__ import annotations

import pytest

from src.compliance_bridge.aarm_mapper import (
    AARM_THREAT_VECTORS,
    AARMConformanceReport,
    AARMVectorResult,
    ConformanceStatus,
    build_aarm_conformance_report,
)
from src.compliance_bridge.types import OscalFinding

# Expected set of all 11 vector IDs
_ALL_VECTOR_IDS = {f"AARM-V{i}" for i in range(1, 12)}

# Expected critical vectors
_CRITICAL_VECTORS = {"AARM-V1", "AARM-V2", "AARM-V3", "AARM-V4", "AARM-V9", "AARM-V10", "AARM-V11"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(control_id: str, result: str = "PASS") -> OscalFinding:
    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}",
        safety_rate=1.0 if result == "PASS" else 0.0,
        evidence_age_s=100.0,
    )


def _all_pass_findings() -> list[OscalFinding]:
    """Return PASS findings for every control referenced by any AARM vector."""
    all_controls: set[str] = set()
    for v in AARM_THREAT_VECTORS.values():
        all_controls.update(v.neutralizing_controls)
    return [_finding(cid, "PASS") for cid in all_controls]


def _all_fail_findings() -> list[OscalFinding]:
    """Return FAIL findings for every control referenced by any AARM vector."""
    all_controls: set[str] = set()
    for v in AARM_THREAT_VECTORS.values():
        all_controls.update(v.neutralizing_controls)
    return [_finding(cid, "FAIL") for cid in all_controls]


# ---------------------------------------------------------------------------
# Test 1: Ledger completeness
# ---------------------------------------------------------------------------

def test_all_11_vectors_present():
    """AARM_THREAT_VECTORS contains exactly 11 entries, one per CSA AARM vector."""
    assert set(AARM_THREAT_VECTORS.keys()) == _ALL_VECTOR_IDS


def test_each_vector_has_required_fields():
    """Every vector has non-empty required fields."""
    for vid, v in AARM_THREAT_VECTORS.items():
        assert v.vector_id == vid,                       f"{vid}: vector_id mismatch"
        assert v.name,                                   f"{vid}: name is empty"
        assert v.description,                            f"{vid}: description is empty"
        assert v.aarm_severity in ("CRITICAL", "HIGH", "MEDIUM"), f"{vid}: invalid severity"
        assert len(v.neutralizing_controls) >= 1,        f"{vid}: no neutralizing controls"
        assert len(v.implementation_files) >= 1,         f"{vid}: no implementation files"


def test_critical_severity_vectors():
    """AARM-V1, V2, V3, V4, V9, V10, V11 must carry CRITICAL severity."""
    for vid in _CRITICAL_VECTORS:
        assert AARM_THREAT_VECTORS[vid].aarm_severity == "CRITICAL", (
            f"{vid} should be CRITICAL"
        )


# ---------------------------------------------------------------------------
# Test 2: All-PASS findings → all NEUTRALIZED
# ---------------------------------------------------------------------------

def test_all_pass_produces_all_neutralized():
    """When every neutralizing control passes, all 11 vectors should be NEUTRALIZED."""
    findings = _all_pass_findings()
    report   = build_aarm_conformance_report(findings, audit_id="all-pass-001")

    for vector_result in report.vectors:
        assert vector_result.status == "NEUTRALIZED", (
            f"{vector_result.vector_id} expected NEUTRALIZED, got {vector_result.status}"
        )

    assert report.exposed     == 0
    assert report.partial     == 0
    assert report.neutralized == 11
    assert report.overall_posture == "SECURE"


# ---------------------------------------------------------------------------
# Test 3: All-FAIL findings → all EXPOSED
# ---------------------------------------------------------------------------

def test_all_fail_produces_all_exposed():
    """When every neutralizing control fails, all 11 vectors should be EXPOSED."""
    findings = _all_fail_findings()
    report   = build_aarm_conformance_report(findings, audit_id="all-fail-001")

    for vector_result in report.vectors:
        assert vector_result.status == "EXPOSED", (
            f"{vector_result.vector_id} expected EXPOSED, got {vector_result.status}"
        )

    assert report.neutralized == 0
    assert report.partial     == 0
    assert report.exposed     == 11
    assert report.overall_posture == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 4: Mixed findings → PARTIAL / NEUTRALIZED / EXPOSED mix
# ---------------------------------------------------------------------------

def test_partial_vector_scoring():
    """A vector with one PASS and one FAIL control is scored PARTIAL."""
    # AARM-V4 requires ["SC-4", "SC-8"]
    findings = [
        _finding("SC-4", "PASS"),
        _finding("SC-8", "FAIL"),  # one failure
    ]
    report = build_aarm_conformance_report(findings, audit_id="partial-001")

    v4_result = next(r for r in report.vectors if r.vector_id == "AARM-V4")
    assert v4_result.status == "PARTIAL"
    assert v4_result.pass_count == 1
    assert v4_result.fail_count == 1


def test_not_found_controls_scored_correctly():
    """Controls absent from the findings list are counted as NOT_FOUND."""
    # Provide findings for only some controls — AARM-V7 needs A.8.4 only
    findings = [_finding("A.5.3", "PASS")]  # A.8.4 not provided → NOT_FOUND for AARM-V7
    report   = build_aarm_conformance_report(findings, audit_id="not-found-001")

    v7_result = next(r for r in report.vectors if r.vector_id == "AARM-V7")
    # NOT_FOUND with no PASSes → EXPOSED
    assert v7_result.not_found_count >= 1
    assert v7_result.status == "EXPOSED"


# ---------------------------------------------------------------------------
# Test 5: Report card metadata
# ---------------------------------------------------------------------------

def test_report_card_schema_version():
    """Report card schema_version is stable across runs."""
    report = build_aarm_conformance_report([], audit_id="schema-test-001")
    assert report.schema_version    == "cage-aarm-conformance/1.0"
    assert report.aarm_spec_version == "CSA-AARM-v1.0"


def test_report_card_total_vectors_always_11():
    """total_vectors is always 11 regardless of findings."""
    for findings in [[], _all_pass_findings(), _all_fail_findings()]:
        report = build_aarm_conformance_report(findings, audit_id="total-test")
        assert report.total_vectors == 11
        assert len(report.vectors)  == 11


def test_report_card_chain_root_embedded():
    """chain_root passed to build_aarm_conformance_report is included in output."""
    chain_root = "a" * 64  # fake SHA-256 hex
    report     = build_aarm_conformance_report(
        _all_pass_findings(), audit_id="chain-root-test", chain_root=chain_root
    )
    assert report.chain_root == chain_root


def test_report_card_audit_id_matches():
    """audit_id in the report matches the one passed to the builder."""
    audit_id = "my-specific-audit-999"
    report   = build_aarm_conformance_report([], audit_id=audit_id)
    assert report.audit_id == audit_id


# ---------------------------------------------------------------------------
# Test 6: Overall posture classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("posture,description", [
    ("SECURE",   "all NEUTRALIZED"),
    ("DEGRADED", "some PARTIAL, none EXPOSED"),
    ("CRITICAL", "at least one EXPOSED"),
])
def test_overall_posture_labels(posture, description):
    """overall_posture correctly classifies SECURE / DEGRADED / CRITICAL."""
    if posture == "SECURE":
        findings = _all_pass_findings()
    elif posture == "CRITICAL":
        findings = _all_fail_findings()
    else:  # DEGRADED
        # Make AARM-V10 (Data Exfiltration) PARTIAL by failing SC-7.
        # AARM-V10 requires ["A.9.2", "SC-7"]. SC-7 is only used by AARM-V10,
        # so failing it produces PARTIAL for V10 only (no other vector uses SC-7
        # alone without a passing partner), keeping all others NEUTRALIZED.
        findings = _all_pass_findings()
        findings = [
            f if f.control_id != "SC-7" else _finding("SC-7", "FAIL")
            for f in findings
        ]

    report = build_aarm_conformance_report(findings, audit_id=f"posture-{posture}")
    assert report.overall_posture == posture, (
        f"Expected {posture} ({description}), got {report.overall_posture}"
    )
