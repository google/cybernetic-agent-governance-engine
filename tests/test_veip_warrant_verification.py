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
VEIP v0.1 Warrant Verification Tests
Tests warrant eligibility verification against the 6 VEIP test vectors.
"""

import hashlib
from datetime import datetime
from typing import Any

import pytest

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan


def compute_warrant_digest_rfc8785(warrant: dict[str, Any]) -> str:
    """
    Compute SHA-256 digest of RFC 8785 JSON Canonicalization Scheme canonical bytes.
    CAGE migrated to RFC 8785 JCS in August 2026 (POAM-2026-060 closed).
    """
    # Create a copy without the digest field for canonical digest computation
    warrant_for_digest = {k: v for k, v in warrant.items() if k != "digest"}
    canonical_bytes = jcs_canonicalize_plan(warrant_for_digest)
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_warrant_eligibility(
    warrant: dict[str, Any],
    action: str,
    jurisdiction: str,
    governing_version: str,
    evaluation_timestamp: datetime,
) -> dict[str, Any]:
    """
    Verify warrant integrity, currency, scope, version, and status.
    Returns eligibility verdict matching VEIP test vector semantics.

    Frozen Governing Rule:
    A warrant failure removes CAGE's right to rely on that norm; it does not
    itself become an institutional ALLOW or DENY.
    """

    # VEC-006-TAMPERED-DIGEST: Cryptographic integrity check
    computed_digest = compute_warrant_digest_rfc8785(warrant)
    if computed_digest != warrant.get("digest"):
        return {
            "eligible": False,
            "reliance_status": "INELIGIBLE_UNRESOLVED",
            "reason": f"Digest mismatch: computed={computed_digest[:16]}..., declared={warrant.get('digest', '')[:16]}...",
        }

    # VEC-002-REVOKED: Status check
    if warrant.get("status") != "ACTIVE":
        return {
            "eligible": False,
            "reliance_status": f"INELIGIBLE_{warrant['status']}",
            "reason": f"Warrant revoked: {warrant.get('revocation_ref')}",
        }

    # VEC-003-EXPIRED: Temporal validity check
    valid_from = datetime.fromisoformat(warrant["valid_from"].replace("Z", "+00:00"))
    valid_until = datetime.fromisoformat(warrant["valid_until"].replace("Z", "+00:00"))
    if not (valid_from <= evaluation_timestamp <= valid_until):
        return {
            "eligible": False,
            "reliance_status": "INELIGIBLE_EXPIRED",
            "reason": f"Evaluated at {evaluation_timestamp.isoformat()}, valid window {valid_from.isoformat()} to {valid_until.isoformat()}",
        }

    # VEC-004-OUT-OF-SCOPE: Action scope check
    if action != warrant["scope"]["action"]:
        return {
            "eligible": False,
            "reliance_status": "INELIGIBLE_OUT_OF_SCOPE",
            "reason": f"Action '{action}' not in scope '{warrant['scope']['action']}'",
        }

    # VEC-004-OUT-OF-SCOPE: Jurisdiction scope check
    if jurisdiction != warrant["scope"]["jurisdiction"]:
        return {
            "eligible": False,
            "reliance_status": "INELIGIBLE_OUT_OF_SCOPE",
            "reason": f"Jurisdiction '{jurisdiction}' not in scope '{warrant['scope']['jurisdiction']}'",
        }

    # VEC-005-VERSION-MISMATCH: Governing version check
    if governing_version != warrant["governing_version"]:
        return {
            "eligible": False,
            "reliance_status": "INELIGIBLE_VERSION_MISMATCH",
            "reason": f"Runtime version '{governing_version}' ≠ warrant version '{warrant['governing_version']}'",
        }

    # VEC-001-ACTIVE: All checks passed
    return {
        "eligible": True,
        "reliance_status": "ELIGIBLE",
        "reason": "All warrant checks passed",
    }


# VEIP v0.1 Shared Warrant Baseline
SHARED_WARRANT_BASELINE = {
    "warrant_id": "warrant-veip-2026-001",
    "norm_id": "confidence.min_trade_confidence",
    "issuing_authority": "Risk Oversight Committee (EU_ECB)",
    "authority_basis": "EU AI Act Art 9 Risk Management Instrument #442",
    "scope": {
        "action": "execute_trade",
        "system": "cage-gateway",
        "jurisdiction": "EU_ECB",
    },
    "valid_from": "2026-08-01T00:00:00Z",
    "valid_until": "2026-12-31T23:59:59Z",
    "governing_version": "cage-policy-2.1.0",
    "residual_risk_ref": "RRR-2026-08-01-A1",
}


@pytest.mark.local
class TestVEIPWarrantVerification:
    """VEIP v0.1 Warrant Eligibility Verification Tests"""

    def test_vec_001_active_warrant(self):
        """
        VEC-001-ACTIVE: Valid warrant for 0.97 trade confidence within valid temporal window.
        Expected: eligible=true, reliance_status=ELIGIBLE, decision=ALLOW
        """
        # Build warrant with ACTIVE status and valid digest
        warrant = {
            **SHARED_WARRANT_BASELINE,
            "status": "ACTIVE",
            "revocation_ref": None,
        }
        # Compute digest for this warrant
        warrant["digest"] = compute_warrant_digest_rfc8785(warrant)

        # Evaluation context matches scope
        evaluation_context = {
            "action": "execute_trade",
            "jurisdiction": "EU_ECB",
            "governing_version": "cage-policy-2.1.0",
            "evaluation_timestamp": datetime.fromisoformat("2026-08-22T12:00:00+00:00"),
            "model_confidence": 0.98,
        }

        # Verify warrant eligibility
        result = verify_warrant_eligibility(
            warrant=warrant,
            action=evaluation_context["action"],
            jurisdiction=evaluation_context["jurisdiction"],
            governing_version=evaluation_context["governing_version"],
            evaluation_timestamp=evaluation_context["evaluation_timestamp"],
        )

        # Assert VEC-001 expected outcomes
        assert result["eligible"] is True, f"Expected eligible=true, got {result}"
        assert result["reliance_status"] == "ELIGIBLE", (
            f"Expected ELIGIBLE status, got {result['reliance_status']}"
        )
        assert "All warrant checks passed" in result["reason"]

        # Decision would be ALLOW (warrant is eligible for enforcement)
        print("✅ VEC-001-ACTIVE PASSED")
        print(f"   Warrant ID: {warrant['warrant_id']}")
        print(f"   Digest: {warrant['digest'][:32]}...")
        print(f"   Reliance Status: {result['reliance_status']}")
        print("   Decision: ALLOW (warrant eligible for enforcement)")

    def test_vec_002_revoked_warrant(self):
        """
        VEC-002-REVOKED: Revoked warrant with explicit revocation reference.
        Expected: eligible=false, reliance_status=INELIGIBLE_REVOKED, decision=DEFER
        """
        warrant = {
            **SHARED_WARRANT_BASELINE,
            "status": "REVOKED",
            "revocation_ref": "Emergency Risk Notice #912",
        }
        warrant["digest"] = compute_warrant_digest_rfc8785(warrant)

        evaluation_context = {
            "action": "execute_trade",
            "jurisdiction": "EU_ECB",
            "governing_version": "cage-policy-2.1.0",
            "evaluation_timestamp": datetime.fromisoformat("2026-08-22T12:00:00+00:00"),
        }

        result = verify_warrant_eligibility(
            warrant=warrant,
            action=evaluation_context["action"],
            jurisdiction=evaluation_context["jurisdiction"],
            governing_version=evaluation_context["governing_version"],
            evaluation_timestamp=evaluation_context["evaluation_timestamp"],
        )

        assert result["eligible"] is False
        assert result["reliance_status"] == "INELIGIBLE_REVOKED"
        assert "Emergency Risk Notice #912" in result["reason"]

        print("✅ VEC-002-REVOKED PASSED")
        print(f"   Reliance Status: {result['reliance_status']}")
        print(f"   Reason: {result['reason']}")
        print("   Decision: DEFER (warrant ineligible)")

    def test_vec_003_expired_warrant(self):
        """
        VEC-003-EXPIRED: Active warrant evaluated after valid_until timestamp.
        Expected: eligible=false, reliance_status=INELIGIBLE_EXPIRED, decision=DEFER
        """
        warrant = {
            **SHARED_WARRANT_BASELINE,
            "status": "ACTIVE",
            "revocation_ref": None,
        }
        warrant["digest"] = compute_warrant_digest_rfc8785(warrant)

        # Evaluate AFTER valid_until (2026-12-31)
        evaluation_context = {
            "action": "execute_trade",
            "jurisdiction": "EU_ECB",
            "governing_version": "cage-policy-2.1.0",
            "evaluation_timestamp": datetime.fromisoformat("2027-01-15T00:00:00+00:00"),
        }

        result = verify_warrant_eligibility(
            warrant=warrant,
            action=evaluation_context["action"],
            jurisdiction=evaluation_context["jurisdiction"],
            governing_version=evaluation_context["governing_version"],
            evaluation_timestamp=evaluation_context["evaluation_timestamp"],
        )

        assert result["eligible"] is False
        assert result["reliance_status"] == "INELIGIBLE_EXPIRED"

        print("✅ VEC-003-EXPIRED PASSED")
        print(f"   Reliance Status: {result['reliance_status']}")
        print("   Decision: DEFER (warrant expired)")

    def test_vec_004_out_of_scope_action(self):
        """
        VEC-004-OUT-OF-SCOPE: Evaluation context action falls outside warrant scope.
        Expected: eligible=false, reliance_status=INELIGIBLE_OUT_OF_SCOPE, decision=DEFER
        """
        warrant = {
            **SHARED_WARRANT_BASELINE,
            "status": "ACTIVE",
            "revocation_ref": None,
        }
        warrant["digest"] = compute_warrant_digest_rfc8785(warrant)

        # Action does NOT match scope (unauthorized_wire_action vs execute_trade)
        evaluation_context = {
            "action": "unauthorized_wire_action",
            "jurisdiction": "EU_ECB",
            "governing_version": "cage-policy-2.1.0",
            "evaluation_timestamp": datetime.fromisoformat("2026-08-22T12:00:00+00:00"),
        }

        result = verify_warrant_eligibility(
            warrant=warrant,
            action=evaluation_context["action"],
            jurisdiction=evaluation_context["jurisdiction"],
            governing_version=evaluation_context["governing_version"],
            evaluation_timestamp=evaluation_context["evaluation_timestamp"],
        )

        assert result["eligible"] is False
        assert result["reliance_status"] == "INELIGIBLE_OUT_OF_SCOPE"
        assert "unauthorized_wire_action" in result["reason"]

        print("✅ VEC-004-OUT-OF-SCOPE PASSED")
        print(f"   Reliance Status: {result['reliance_status']}")
        print("   Decision: DEFER (action out of scope)")

    def test_vec_005_version_mismatch(self):
        """
        VEC-005-VERSION-MISMATCH: Runtime governing version differs from warrant governing_version.
        Expected: eligible=false, reliance_status=INELIGIBLE_VERSION_MISMATCH, decision=DEFER
        """
        warrant = {
            **SHARED_WARRANT_BASELINE,
            "status": "ACTIVE",
            "revocation_ref": None,
        }
        warrant["digest"] = compute_warrant_digest_rfc8785(warrant)

        # Runtime version does NOT match warrant version
        evaluation_context = {
            "action": "execute_trade",
            "jurisdiction": "EU_ECB",
            "governing_version": "cage-policy-9.9.9",  # Mismatch!
            "evaluation_timestamp": datetime.fromisoformat("2026-08-22T12:00:00+00:00"),
        }

        result = verify_warrant_eligibility(
            warrant=warrant,
            action=evaluation_context["action"],
            jurisdiction=evaluation_context["jurisdiction"],
            governing_version=evaluation_context["governing_version"],
            evaluation_timestamp=evaluation_context["evaluation_timestamp"],
        )

        assert result["eligible"] is False
        assert result["reliance_status"] == "INELIGIBLE_VERSION_MISMATCH"
        assert "9.9.9" in result["reason"]
        assert "2.1.0" in result["reason"]

        print("✅ VEC-005-VERSION-MISMATCH PASSED")
        print(f"   Reliance Status: {result['reliance_status']}")
        print("   Decision: DEFER (version mismatch)")

    def test_vec_006_tampered_digest(self):
        """
        VEC-006-TAMPERED-DIGEST: Declared digest differs from SHA-256 of RFC 8785 canonical warrant bytes.
        Expected: eligible=false, reliance_status=INELIGIBLE_UNRESOLVED, decision=DEFER
        """
        warrant = {
            **SHARED_WARRANT_BASELINE,
            "status": "ACTIVE",
            "revocation_ref": None,
        }
        # Compute correct digest
        correct_digest = compute_warrant_digest_rfc8785(warrant)
        # Tamper with last character (change 'e' to '0')
        tampered_digest = correct_digest[:-1] + "0"
        warrant["digest"] = tampered_digest

        evaluation_context = {
            "action": "execute_trade",
            "jurisdiction": "EU_ECB",
            "governing_version": "cage-policy-2.1.0",
            "evaluation_timestamp": datetime.fromisoformat("2026-08-22T12:00:00+00:00"),
        }

        result = verify_warrant_eligibility(
            warrant=warrant,
            action=evaluation_context["action"],
            jurisdiction=evaluation_context["jurisdiction"],
            governing_version=evaluation_context["governing_version"],
            evaluation_timestamp=evaluation_context["evaluation_timestamp"],
        )

        assert result["eligible"] is False
        assert result["reliance_status"] == "INELIGIBLE_UNRESOLVED"
        assert "Digest mismatch" in result["reason"]

        print("✅ VEC-006-TAMPERED-DIGEST PASSED")
        print(f"   Reliance Status: {result['reliance_status']}")
        print("   Decision: DEFER (tampering detected)")


@pytest.mark.local
def test_warrant_digest_computation_rfc8785():
    """Verify RFC 8785 JCS digest computation matches expected canonical form"""
    warrant = {
        "warrant_id": "test-001",
        "norm_id": "test.norm",
        "status": "ACTIVE",
        "scope": {"action": "test", "jurisdiction": "TEST"},
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
    }

    digest1 = compute_warrant_digest_rfc8785(warrant)
    digest2 = compute_warrant_digest_rfc8785(warrant)

    # Digest should be deterministic (same input → same output)
    assert digest1 == digest2
    assert len(digest1) == 64  # SHA-256 produces 64 hex characters

    # Changing any field should produce different digest
    warrant_modified = {**warrant, "status": "REVOKED"}
    digest_modified = compute_warrant_digest_rfc8785(warrant_modified)
    assert digest1 != digest_modified

    print("✅ RFC 8785 JCS Digest Computation PASSED")
    print(f"   Digest: {digest1}")
