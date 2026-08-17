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

"""Tests for config/opa/agent_catalog.rego — Phase B Work Stream F.

Tests the OPA agent catalog policy logic using pure Python evaluation
(no OPA binary required). The policy logic is re-implemented in Python
to mirror the Rego semantics exactly, enabling fast unit tests.

For integration tests with the actual OPA binary, see the end-to-end
test suite in Sprint 6.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Python mirror of the agent_catalog.rego policy logic
# ---------------------------------------------------------------------------
# This mirrors the Rego policy semantics exactly so tests run without OPA.
# When the OPA binary is available, replace with actual OPA evaluation.


def _load_catalog() -> dict:
    """Load the agent catalog data document from config/agent_catalog.json."""
    catalog_path = Path(__file__).parent.parent / "config" / "agent_catalog.json"
    with open(catalog_path) as f:
        doc = json.load(f)
    return doc.get("agents", {})


def _evaluate_catalog_policy(
    caller_sub: str,
    tool_name: str,
    catalog: dict | None = None,
) -> tuple[bool, list[str]]:
    """Evaluate the agent_catalog OPA policy in Python.

    Mirrors the Rego logic in config/opa/agent_catalog.rego:
      - allow = True if caller in catalog AND tool in allowed_tools
      - violation = set of denial reasons

    Args:
        caller_sub: OIDC sub claim or SPIFFE ID.
        tool_name:  Tool name to check.
        catalog:    Agent catalog dict (defaults to loading from file).

    Returns:
        Tuple of (allow: bool, violations: list[str]).
    """
    if catalog is None:
        catalog = _load_catalog()

    violations: list[str] = []

    # Caller not in catalog
    if caller_sub not in catalog:
        violations.append(f"caller '{caller_sub}' is not in the approved agent catalog")
        return False, violations

    agent = catalog[caller_sub]
    allowed_tools = agent.get("allowed_tools", [])

    # Tool not in allowed_tools
    if tool_name not in allowed_tools:
        violations.append(
            f"caller '{caller_sub}' is not authorized to call tool '{tool_name}'"
        )
        return False, violations

    return True, []


# ---------------------------------------------------------------------------
# Tests using the real catalog file
# ---------------------------------------------------------------------------


class TestAgentCatalogFile:
    """Tests that verify the catalog file structure and content."""

    def test_catalog_file_exists(self):
        catalog_path = Path(__file__).parent.parent / "config" / "agent_catalog.json"
        assert catalog_path.exists(), "config/agent_catalog.json must exist"

    def test_catalog_file_is_valid_json(self):
        catalog_path = Path(__file__).parent.parent / "config" / "agent_catalog.json"
        with open(catalog_path) as f:
            doc = json.load(f)
        assert isinstance(doc, dict)

    def test_catalog_has_agents_key(self):
        catalog_path = Path(__file__).parent.parent / "config" / "agent_catalog.json"
        with open(catalog_path) as f:
            doc = json.load(f)
        assert "agents" in doc, "catalog must have 'agents' key"

    def test_each_agent_has_required_fields(self):
        catalog = _load_catalog()
        for sub, agent in catalog.items():
            assert "display_name" in agent, f"agent {sub} missing display_name"
            assert "allowed_tools" in agent, f"agent {sub} missing allowed_tools"
            assert isinstance(agent["allowed_tools"], list), (
                f"agent {sub} allowed_tools must be a list"
            )

    def test_trader_agent_can_execute_trade(self):
        catalog = _load_catalog()
        trader_sub = "spiffe://trust-domain/ns/default/sa/trader-agent"
        assert trader_sub in catalog
        assert "execute_trade" in catalog[trader_sub]["allowed_tools"]

    def test_risk_agent_cannot_execute_trade(self):
        catalog = _load_catalog()
        risk_sub = "spiffe://trust-domain/ns/default/sa/risk-agent"
        assert risk_sub in catalog
        assert "execute_trade" not in catalog[risk_sub]["allowed_tools"]


# ---------------------------------------------------------------------------
# Policy logic tests (using Python mirror of Rego)
# ---------------------------------------------------------------------------


class TestAgentCatalogPolicy:
    """Tests for the agent_catalog OPA policy logic."""

    # Minimal test catalog (independent of the real catalog file)
    _CATALOG = {
        "spiffe://trust-domain/ns/default/sa/trader-agent": {
            "display_name": "Governed Trader Agent",
            "allowed_tools": ["execute_trade", "market_analysis", "get_portfolio"],
            "trust_domain": "trust-domain",
        },
        "spiffe://trust-domain/ns/default/sa/risk-agent": {
            "display_name": "Risk Analyst Agent",
            "allowed_tools": ["market_analysis", "get_portfolio", "risk_assessment"],
            "trust_domain": "trust-domain",
        },
    }

    def test_approved_caller_allowed_tool_returns_allow_true(self):
        """Approved caller + allowed tool → allow = true."""
        allow, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/trader-agent",
            tool_name="execute_trade",
            catalog=self._CATALOG,
        )
        assert allow is True
        assert violations == []

    def test_approved_caller_disallowed_tool_returns_allow_false(self):
        """Approved caller + disallowed tool → allow = false + violation message."""
        allow, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/risk-agent",
            tool_name="execute_trade",
            catalog=self._CATALOG,
        )
        assert allow is False
        assert len(violations) == 1
        assert "execute_trade" in violations[0]
        assert "risk-agent" in violations[0]

    def test_unknown_caller_returns_allow_false(self):
        """Unknown caller → allow = false + violation message."""
        allow, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/unknown-agent",
            tool_name="execute_trade",
            catalog=self._CATALOG,
        )
        assert allow is False
        assert len(violations) == 1
        assert "unknown-agent" in violations[0]
        assert "not in the approved agent catalog" in violations[0]

    def test_empty_catalog_denies_all(self):
        """Empty catalog → all callers denied."""
        allow, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/trader-agent",
            tool_name="execute_trade",
            catalog={},
        )
        assert allow is False
        assert len(violations) == 1

    def test_violation_message_contains_caller_sub(self):
        """Violation message must contain the caller sub for auditability."""
        _, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/unknown-agent",
            tool_name="execute_trade",
            catalog=self._CATALOG,
        )
        assert "spiffe://trust-domain/ns/default/sa/unknown-agent" in violations[0]

    def test_violation_message_contains_tool_name_for_disallowed_tool(self):
        """Violation message must contain the tool name for disallowed tool."""
        _, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/risk-agent",
            tool_name="execute_trade",
            catalog=self._CATALOG,
        )
        assert "execute_trade" in violations[0]

    def test_multiple_allowed_tools_all_permitted(self):
        """All tools in allowed_tools list are permitted."""
        for tool in ["market_analysis", "get_portfolio", "risk_assessment"]:
            allow, violations = _evaluate_catalog_policy(
                caller_sub="spiffe://trust-domain/ns/default/sa/risk-agent",
                tool_name=tool,
                catalog=self._CATALOG,
            )
            assert allow is True, f"tool {tool} should be allowed for risk-agent"
            assert violations == []

    def test_trader_cannot_call_risk_assessment(self):
        """Trader agent cannot call risk_assessment (not in allowed_tools)."""
        allow, _violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/trader-agent",
            tool_name="risk_assessment",
            catalog=self._CATALOG,
        )
        assert allow is False

    def test_empty_caller_sub_denied(self):
        """Empty caller sub → denied (not in catalog)."""
        allow, _violations = _evaluate_catalog_policy(
            caller_sub="",
            tool_name="execute_trade",
            catalog=self._CATALOG,
        )
        assert allow is False

    def test_empty_tool_name_denied(self):
        """Empty tool name → denied (not in allowed_tools)."""
        allow, _violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/trader-agent",
            tool_name="",
            catalog=self._CATALOG,
        )
        assert allow is False


# ---------------------------------------------------------------------------
# Real catalog integration tests
# ---------------------------------------------------------------------------


class TestRealCatalogPolicy:
    """Tests using the actual config/agent_catalog.json file."""

    def test_trader_agent_execute_trade_allowed(self):
        allow, _ = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/trader-agent",
            tool_name="execute_trade",
        )
        assert allow is True

    def test_trader_agent_market_analysis_allowed(self):
        allow, _ = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/trader-agent",
            tool_name="market_analysis",
        )
        assert allow is True

    def test_risk_agent_execute_trade_denied(self):
        allow, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/risk-agent",
            tool_name="execute_trade",
        )
        assert allow is False
        assert len(violations) == 1

    def test_data_analyst_cannot_execute_trade(self):
        allow, _ = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/data-analyst-agent",
            tool_name="execute_trade",
        )
        assert allow is False

    def test_supervisor_cannot_execute_trade(self):
        allow, _ = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/supervisor-agent",
            tool_name="execute_trade",
        )
        assert allow is False

    def test_unknown_agent_denied_for_any_tool(self):
        allow, violations = _evaluate_catalog_policy(
            caller_sub="spiffe://trust-domain/ns/default/sa/rogue-agent",
            tool_name="execute_trade",
        )
        assert allow is False
        assert "not in the approved agent catalog" in violations[0]


pytestmark = [pytest.mark.unit, pytest.mark.local]
