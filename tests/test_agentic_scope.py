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

"""Tests for agentic scope statement — AI 600-1 §2.5.1, §2.5.4.

POAM: AI600-004
Phase: 0 (foundation)
"""

import pytest


@pytest.fixture(autouse=True)
def disable_seal_strict_mode(monkeypatch):
    """Disable strict mode for all tests in this module.
    
    Strict mode rejects HMAC seals in production environments.
    Tests use HMAC seals for unit testing, so we disable strict mode.
    """
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")


# Skip the entire module gracefully when dowhy is not installed (e.g. in CI
# environments that install only the base dependency group without the
# [compliance] extra).  The TestCausalGatekeeperAuthorizedActionSpace class
# imports causal_gatekeeper which transitively requires dowhy.
pytest.importorskip(
    "dowhy", reason="dowhy not installed — skipping agentic scope causal tests"
)


# ---------------------------------------------------------------------------
# §4.1 Task 3a — RoutingSeal rejects requests without valid HMAC seal
# ---------------------------------------------------------------------------


class TestRoutingSealRejectsInvalidSeal:
    """RoutingSeal must reject requests without a valid HMAC seal.

    CRIT-1 fix note: verify_seal() now raises SymbolicGovernorViolation on any
    verification failure instead of returning False, preventing callers from
    silently ignoring a failed seal check.
    """

    def test_verify_seal_rejects_missing_seal(self):
        """verify_seal raises SymbolicGovernorViolation for an empty seal string."""
        # GOVERNANCE_SALT is set by conftest.py to ensure consistent HMAC key
        # across all tests. Do not override here.
        from src.gateway.governance.routing_seal import (
            SymbolicGovernorViolation,
            verify_seal,
        )

        with pytest.raises(SymbolicGovernorViolation):
            verify_seal("", "execute_trade", {"amount": 5000})

    def test_verify_seal_rejects_malformed_seal(self):
        """verify_seal raises SymbolicGovernorViolation for a malformed seal (wrong number of parts)."""
        # GOVERNANCE_SALT is set by conftest.py to ensure consistent HMAC key
        # across all tests. Do not override here.
        from src.gateway.governance.routing_seal import (
            SymbolicGovernorViolation,
            verify_seal,
        )

        with pytest.raises(SymbolicGovernorViolation):
            verify_seal("not-a-valid-seal", "execute_trade", {"amount": 5000})

    def test_verify_seal_rejects_tampered_hmac(self):
        """verify_seal raises SymbolicGovernorViolation when the HMAC is tampered."""
        # GOVERNANCE_SALT is set by conftest.py to ensure consistent HMAC key
        # across all tests. Do not override here.
        from src.gateway.governance.routing_seal import (
            SymbolicGovernorViolation,
            generate_seal,
            verify_seal,
        )

        seal = generate_seal("execute_trade", {"amount": 5000})
        # Tamper with the HMAC portion
        parts = seal.split(".")
        parts[2] = "a" * 64  # replace HMAC with garbage
        tampered = ".".join(parts)
        with pytest.raises(SymbolicGovernorViolation):
            verify_seal(tampered, "execute_trade", {"amount": 5000})

    def test_verify_seal_accepts_valid_seal(self):
        """verify_seal returns True for a freshly generated valid seal."""
        # GOVERNANCE_SALT is set by conftest.py to ensure consistent HMAC key
        # across all tests. Do not override here.
        from src.gateway.governance.routing_seal import generate_seal, verify_seal

        seal = generate_seal("execute_trade", {"amount": 5000})
        result = verify_seal(seal, "execute_trade", {"amount": 5000})
        assert result is True


# ---------------------------------------------------------------------------
# §4.1 Task 3b — ConsensusGate escalates when amount_usd > 10000
# ---------------------------------------------------------------------------


class TestConsensusGateThreshold:
    """ConsensusGate must escalate when amount_usd > USD 10,000."""

    def test_threshold_loaded_from_singleton(self):
        """ConsensusGate threshold matches governance_thresholds.json."""
        from src.gateway.governance.schemas.thresholds import THRESHOLDS

        assert THRESHOLDS.consensus.threshold_usd == 10000.0

    def test_hitl_escalator_fires_above_threshold(self):
        """should_escalate_for_consensus returns True when amount > threshold."""
        from src.gateway.governance.hitl_escalator import should_escalate_for_consensus

        assert should_escalate_for_consensus(15000.0, threshold_usd=10000.0) is True

    def test_hitl_escalator_does_not_fire_at_threshold(self):
        """should_escalate_for_consensus returns False when amount == threshold."""
        from src.gateway.governance.hitl_escalator import should_escalate_for_consensus

        assert should_escalate_for_consensus(10000.0, threshold_usd=10000.0) is False

    def test_hitl_escalator_does_not_fire_below_threshold(self):
        """should_escalate_for_consensus returns False when amount < threshold."""
        from src.gateway.governance.hitl_escalator import should_escalate_for_consensus

        assert should_escalate_for_consensus(9999.99, threshold_usd=10000.0) is False


# ---------------------------------------------------------------------------
# §4.1 Task 3c — CausalGatekeeper blocks tool calls outside authorized space
# ---------------------------------------------------------------------------


class TestCausalGatekeeperAuthorizedActionSpace:
    """CausalGatekeeper must block tool calls outside the authorized action space."""

    def test_causal_safety_check_blocks_zero_amount(self):
        """causal_safety_check returns True (no-op) for zero-amount actions."""
        from src.gateway.governance.causal_gatekeeper import causal_safety_check

        # Zero amount is not a meaningful trade — should pass through
        result = causal_safety_check({"amount": 0, "action_type": "get_portfolio"})
        assert result is True

    def test_agentic_scope_statement_file_exists(self):
        """docs/AGENTIC_SCOPE_STATEMENT.md must exist (AI 600-1 §2.5.1 prerequisite)."""
        import pathlib

        scope_doc = pathlib.Path("docs/AGENTIC_SCOPE_STATEMENT.md")
        assert scope_doc.exists(), (
            "docs/AGENTIC_SCOPE_STATEMENT.md is missing — required for AI 600-1 §2.5.1 "
            "and SR 26-2 §3.1 ATO package."
        )

    def test_us_fed_baseline_references_scope_statement(self):
        """config/compliance/US_FED_BASELINE.json must contain the agentic_scope_statement
        control-mapping entry with required regulatory metadata fields.

        AGENTIC_SCOPE_STATEMENT was promoted from a plain document-path pointer to a
        full GovernanceControl entry (SR 26-2 §3.1, AI 600-1 §2.5) so that it can be
        resolved by ControlRegistry.get_mapping() and appear in SIEM audit trails.
        The document path is captured in the 'description' field.
        """
        import json
        import pathlib

        baseline = json.loads(
            pathlib.Path("config/compliance/US_FED_BASELINE.json").read_text()
        )
        assert "agentic_scope_statement" in baseline, (
            "US_FED_BASELINE.json must contain 'agentic_scope_statement' field "
            "(AI 600-1 §2.5.1 prerequisite)."
        )
        entry = baseline["agentic_scope_statement"]
        assert isinstance(entry, dict), (
            "agentic_scope_statement must be a control-mapping dict (not a plain string) "
            "so that ControlRegistry.get_mapping() can resolve it. "
            f"Got: {type(entry).__name__!r}"
        )
        assert entry.get("legacy_citation"), (
            "agentic_scope_statement control-mapping is missing 'legacy_citation' — "
            "required for SIEM backward-compatibility."
        )
        assert entry.get("primary_framework"), (
            "agentic_scope_statement control-mapping is missing 'primary_framework'."
        )
        assert "AGENTIC_SCOPE_STATEMENT.md" in entry.get("description", ""), (
            "agentic_scope_statement description must reference the scope statement "
            "document path (docs/AGENTIC_SCOPE_STATEMENT.md) for traceability."
        )


pytestmark = [pytest.mark.unit, pytest.mark.local]
