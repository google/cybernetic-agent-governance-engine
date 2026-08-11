"""
Rego policy drift detection tests (Gap 3).

These tests provide a pytest-visible safety net that catches wholesale
deletion or corruption of key Rego rules without requiring a live OPA
instance.  They complement the native `.rego_test` suite by running
in the standard `pytest-logic` CI job (marker: ``local``).

Assertions:
- config/opa/trade_policy.rego exists and contains key rule names.
- config/opa/agent_catalog.rego exists, contains `allow`/`violation`,
  and references `input.agent` or `input.caller_identity`.
- config/opa/generated_stpa_policy.rego exists and is non-empty.
- agent_catalog.rego uses `input.caller_identity.sub` (the actual
  identity field), proving the Python re-impl in test_agent_catalog.py
  is not the only guard.
"""

from __future__ import annotations

import pytest
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve paths relative to repo root (works from any CWD)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
_OPA_DIR = _REPO_ROOT / "config" / "opa"

_TRADE_POLICY = _OPA_DIR / "trade_policy.rego"
_AGENT_CATALOG = _OPA_DIR / "agent_catalog.rego"
_STPA_POLICY = _OPA_DIR / "generated_stpa_policy.rego"


# ---------------------------------------------------------------------------
# Tests: trade_policy.rego
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestTradePolicyRego:
    """Drift-detection tests for config/opa/trade_policy.rego."""

    def test_file_exists(self):
        """trade_policy.rego exists on disk."""
        assert _TRADE_POLICY.exists(), (
            f"Expected {_TRADE_POLICY} to exist — was it deleted?"
        )

    def test_file_is_non_empty(self):
        """trade_policy.rego is not an empty file."""
        content = _TRADE_POLICY.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, "trade_policy.rego is empty"

    def test_contains_package_declaration(self):
        """trade_policy.rego declares an OPA package."""
        content = _TRADE_POLICY.read_text(encoding="utf-8")
        assert "package " in content, (
            "trade_policy.rego must contain a 'package' declaration"
        )

    def test_contains_allow_rule(self):
        """trade_policy.rego contains an 'allow' rule (default or computed)."""
        content = _TRADE_POLICY.read_text(encoding="utf-8")
        assert "allow" in content, (
            "trade_policy.rego must contain an 'allow' rule — "
            "if removed, downstream OPA queries will fail"
        )

    def test_package_is_financial_trade(self):
        """trade_policy.rego uses package financial.trade."""
        content = _TRADE_POLICY.read_text(encoding="utf-8")
        assert "financial.trade" in content, (
            "Package name 'financial.trade' not found — policy may have been replaced"
        )


# ---------------------------------------------------------------------------
# Tests: agent_catalog.rego
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestAgentCatalogRego:
    """Drift-detection tests for config/opa/agent_catalog.rego."""

    def test_file_exists(self):
        """agent_catalog.rego exists on disk."""
        assert _AGENT_CATALOG.exists(), (
            f"Expected {_AGENT_CATALOG} to exist — was it deleted?"
        )

    def test_file_is_non_empty(self):
        """agent_catalog.rego is not an empty file."""
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, "agent_catalog.rego is empty"

    def test_contains_allow_rule(self):
        """agent_catalog.rego contains at least one 'allow' rule."""
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        assert "allow" in content, (
            "agent_catalog.rego must contain an 'allow' rule"
        )

    def test_contains_violation_rule(self):
        """agent_catalog.rego contains a 'violation' rule for denial reasons."""
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        assert "violation" in content, (
            "agent_catalog.rego must contain a 'violation' rule — "
            "denial reason reporting has been removed"
        )

    def test_references_input_caller_identity_sub(self):
        """agent_catalog.rego references input.caller_identity.sub (OIDC identity field).

        This assertion proves that the Rego policy performs identity-based
        authorization — not just the Python re-implementation in
        test_agent_catalog.py.  If this string disappears, the catalog
        policy no longer gates on caller identity.
        """
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        assert "input.caller_identity.sub" in content, (
            "agent_catalog.rego no longer references 'input.caller_identity.sub' — "
            "OIDC-based agent identity enforcement may have been removed"
        )

    def test_references_input_tool_name(self):
        """agent_catalog.rego references input.tool_name for per-tool authorization."""
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        assert "input.tool_name" in content, (
            "agent_catalog.rego no longer references 'input.tool_name' — "
            "per-tool authorization gate may have been removed"
        )

    def test_contains_approved_agents_definition(self):
        """agent_catalog.rego defines approved_agents from data document."""
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        assert "approved_agents" in content, (
            "approved_agents definition missing from agent_catalog.rego"
        )

    def test_package_is_agent_catalog(self):
        """agent_catalog.rego uses package agent_catalog."""
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        assert "package agent_catalog" in content, (
            "Package 'agent_catalog' not found — policy package was renamed or removed"
        )


# ---------------------------------------------------------------------------
# Tests: generated_stpa_policy.rego
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestGeneratedStpaPolicyRego:
    """Drift-detection tests for config/opa/generated_stpa_policy.rego."""

    def test_file_exists(self):
        """generated_stpa_policy.rego exists — it is auto-generated by stpa_compiler."""
        assert _STPA_POLICY.exists(), (
            f"Expected {_STPA_POLICY} to exist. "
            "Run: python -m src.gateway.governance.stpa_compiler compile"
        )

    def test_file_is_non_empty(self):
        """generated_stpa_policy.rego has content (was not emptied)."""
        content = _STPA_POLICY.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, (
            "generated_stpa_policy.rego is empty — regenerate with stpa_compiler"
        )

    def test_contains_auto_generated_header(self):
        """generated_stpa_policy.rego contains the AUTO-GENERATED marker."""
        content = _STPA_POLICY.read_text(encoding="utf-8")
        assert "AUTO-GENERATED" in content or "stpa_compiler" in content, (
            "Auto-generated header not found — file may have been manually edited "
            "or replaced without the standard marker"
        )

    def test_contains_stpa_allow_rule(self):
        """generated_stpa_policy.rego defines stpa_allow."""
        content = _STPA_POLICY.read_text(encoding="utf-8")
        assert "stpa_allow" in content, (
            "stpa_allow rule not found in generated_stpa_policy.rego — "
            "STPA safety gate has been removed from the generated policy"
        )

    def test_contains_stpa_violations_aggregate(self):
        """generated_stpa_policy.rego defines stpa_violations aggregate set."""
        content = _STPA_POLICY.read_text(encoding="utf-8")
        assert "stpa_violations" in content, (
            "stpa_violations aggregate missing — STPA UCA enforcement removed"
        )

    def test_contains_uca_violations(self):
        """generated_stpa_policy.rego contains at least one UCA violation rule."""
        content = _STPA_POLICY.read_text(encoding="utf-8")
        # At minimum UCA-1 should be present
        assert "stpa_violation_uca" in content, (
            "No stpa_violation_uca_* rules found — all STPA constraints removed"
        )

    def test_package_is_stpa_generated(self):
        """generated_stpa_policy.rego uses package stpa.generated."""
        content = _STPA_POLICY.read_text(encoding="utf-8")
        assert "package stpa.generated" in content, (
            "Package 'stpa.generated' not found — policy was re-packaged or replaced"
        )


# ---------------------------------------------------------------------------
# Tests: cross-policy consistency
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestCrossPolicyConsistency:
    """Cross-file consistency checks that no single policy can satisfy alone."""

    def test_all_three_rego_files_exist(self):
        """All three OPA policy files co-exist in config/opa/."""
        missing = [p for p in [_TRADE_POLICY, _AGENT_CATALOG, _STPA_POLICY] if not p.exists()]
        assert not missing, (
            f"Missing OPA policy files: {[str(m) for m in missing]}"
        )

    def test_opa_directory_is_not_empty(self):
        """config/opa/ contains at least 3 .rego files."""
        rego_files = list(_OPA_DIR.glob("*.rego"))
        assert len(rego_files) >= 3, (
            f"Expected ≥3 .rego files in {_OPA_DIR}, found {len(rego_files)}: "
            f"{[f.name for f in rego_files]}"
        )

    def test_agent_catalog_input_agent_or_caller_identity(self):
        """agent_catalog.rego references the 'input.agent' or 'input.caller_identity' namespace.

        Confirms the Rego file checks agent identity (not just the Python
        re-implementation).  Either reference pattern is acceptable — the
        key requirement is that identity is checked in the Rego file itself.
        """
        content = _AGENT_CATALOG.read_text(encoding="utf-8")
        has_caller_identity = "input.caller_identity" in content
        has_input_agent = "input.agent" in content
        assert has_caller_identity or has_input_agent, (
            "agent_catalog.rego contains neither 'input.caller_identity' nor "
            "'input.agent' — identity-based authorization appears to have been removed"
        )
