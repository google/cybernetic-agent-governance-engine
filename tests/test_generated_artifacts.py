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
tests/test_generated_artifacts.py
==================================
Functional coverage of auto-generated governance artifacts.

Gap 5: Only a freshness diff check exists in CI for generated artifacts.
This file adds runtime assertions that the generated modules and policy files
are structurally sound and contain the expected public API surface.

Tests in this file are hermetic — no live services required.

Marks
-----
- ``local`` : safe to run with no live services (CI default)
"""

from __future__ import annotations

import importlib
import pathlib
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Paths to generated artifacts
# ---------------------------------------------------------------------------

_SAGA_MODULE = "src.gateway.governance.generated_saga_nodes"
_STPA_MODULE = "src.gateway.governance.generated_stpa_validator"
_REGO_POLICY = pathlib.Path("config/opa/generated_stpa_policy.rego")
_SEMANTIC_POLICY = pathlib.Path("config/agp/generated_semantic_policy.txt")
_STPA_RAILS = pathlib.Path("config/rails/generated_stpa_rails.co")


# ---------------------------------------------------------------------------
# Module import helpers — mock heavy dependencies at import time
# ---------------------------------------------------------------------------


def _import_saga_nodes() -> types.ModuleType:
    """Import generated_saga_nodes with heavy GFA deps mocked."""
    # Stub all transitive heavy imports so the module loads hermetically
    stub_modules = {
        "src": MagicMock(),
        "src.governed_financial_advisor": MagicMock(),
        "src.governed_financial_advisor.graph": MagicMock(),
        "src.governed_financial_advisor.graph.state": MagicMock(),
        "src.governed_financial_advisor.infrastructure": MagicMock(),
        "src.gateway.infrastructure.mcp_client": MagicMock(),
    }

    # Provide typed stubs that match what the module needs
    agent_state_stub = MagicMock()
    agent_state_stub.AgentState = dict
    ledger_entry_stub = MagicMock()
    ledger_entry_stub.LedgerEntry = dict
    stub_modules["src.governed_financial_advisor.graph.state"].AgentState = dict
    stub_modules["src.governed_financial_advisor.graph.state"].LedgerEntry = dict

    MagicMock()
    stub_modules["src.gateway.infrastructure.mcp_client"].GatewayMCPClient = MagicMock

    for name, stub in stub_modules.items():
        if name not in sys.modules:
            sys.modules[name] = stub

    # Remove cached version so we get a fresh import
    if _SAGA_MODULE in sys.modules:
        del sys.modules[_SAGA_MODULE]

    return importlib.import_module(_SAGA_MODULE)


def _import_stpa_validator() -> types.ModuleType:
    """Import generated_stpa_validator with THRESHOLDS singleton mocked."""
    # Mock the thresholds singleton
    thresholds_stub = MagicMock()
    thresholds_stub.stpa.max_latency_ms = 200.0
    thresholds_stub.stpa.uca5_drawdown_threshold_pct = 4.5

    schemas_stub = MagicMock()
    schemas_stub.THRESHOLDS = thresholds_stub

    stub_modules = {
        "src.gateway.governance.schemas": MagicMock(),
        "src.gateway.governance.schemas.thresholds": schemas_stub,
    }
    for name, stub in stub_modules.items():
        if name not in sys.modules:
            sys.modules[name] = stub

    stub_modules["src.gateway.governance.schemas"].thresholds = schemas_stub
    stub_modules[
        "src.gateway.governance.schemas"
    ].thresholds.THRESHOLDS = thresholds_stub

    if _STPA_MODULE in sys.modules:
        del sys.modules[_STPA_MODULE]

    return importlib.import_module(_STPA_MODULE)


# ---------------------------------------------------------------------------
# Tests: generated_saga_nodes.py
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGeneratedSagaNodes:
    """Functional tests for src/gateway/governance/generated_saga_nodes.py."""

    def test_module_imports_successfully(self) -> None:
        """generated_saga_nodes must be importable."""
        mod = _import_saga_nodes()
        assert mod is not None, "Module failed to import"
        assert hasattr(mod, "__name__"), "Module has no __name__"

    def test_module_exports_public_functions(self) -> None:
        """generated_saga_nodes must export at least one public function."""
        mod = _import_saga_nodes()
        public_names = [name for name in dir(mod) if not name.startswith("_")]
        assert len(public_names) >= 1, (
            f"generated_saga_nodes exports no public names; found: {dir(mod)}"
        )

    def test_forward_execute_trade_node_exists(self) -> None:
        """forward_execute_trade_node_uca_4 must be a generator function."""
        mod = _import_saga_nodes()
        assert hasattr(mod, "forward_execute_trade_node_uca_4"), (
            "generated_saga_nodes must define forward_execute_trade_node_uca_4"
        )
        fn = mod.forward_execute_trade_node_uca_4
        assert callable(fn), "forward_execute_trade_node_uca_4 must be callable"

    def test_compensate_reverse_trade_node_exists(self) -> None:
        """compensate_reverse_trade_node_uca_4 must be callable."""
        mod = _import_saga_nodes()
        assert hasattr(mod, "compensate_reverse_trade_node_uca_4"), (
            "generated_saga_nodes must define compensate_reverse_trade_node_uca_4"
        )
        fn = mod.compensate_reverse_trade_node_uca_4
        assert callable(fn), "compensate_reverse_trade_node_uca_4 must be callable"

    def test_saga_router_node_exists(self) -> None:
        """saga_router_node must be callable."""
        mod = _import_saga_nodes()
        assert hasattr(mod, "saga_router_node"), (
            "generated_saga_nodes must define saga_router_node"
        )
        assert callable(mod.saga_router_node), "saga_router_node must be callable"

    def test_compensate_no_completed_entry_escalates(self) -> None:
        """compensate_reverse_trade_node_uca_4 escalates when no COMPLETED entry exists."""
        mod = _import_saga_nodes()
        state = {"completed_transactions": []}
        result = mod.compensate_reverse_trade_node_uca_4(state)
        assert isinstance(result, dict), "Must return a dict"
        assert result.get("safety_status") == "ESCALATED", (
            f"Expected ESCALATED when no completed entry, got {result.get('safety_status')!r}"
        )

    def test_saga_router_empty_state_returns_blocked(self) -> None:
        """saga_router_node with no completed transactions returns BLOCKED."""
        mod = _import_saga_nodes()
        state: dict = {"completed_transactions": []}
        result = mod.saga_router_node(state)
        assert isinstance(result, dict), "Must return a dict"
        assert result.get("safety_status") == "BLOCKED", (
            f"Expected BLOCKED with no transactions, got {result.get('safety_status')!r}"
        )

    def test_saga_router_pending_entry_escalates(self) -> None:
        """saga_router_node escalates to human_review when ghost-state PENDING detected."""
        mod = _import_saga_nodes()
        state = {
            "completed_transactions": [
                {
                    "sequence_id": 0,
                    "status": "PENDING",
                    "uca_ref": "UCA-4",
                    "action": "execute_trade",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "idempotency_key": "",
                    "context_data": {},
                }
            ]
        }
        result = mod.saga_router_node(state)
        assert isinstance(result, dict), "Must return a dict"
        assert result.get("safety_status") == "ESCALATED", (
            f"Expected ESCALATED for ghost state, got {result.get('safety_status')!r}"
        )
        assert result.get("next_step") == "human_review", (
            f"Expected next_step='human_review', got {result.get('next_step')!r}"
        )

    def test_derive_idempotency_key_is_deterministic(self) -> None:
        """_derive_idempotency_key must produce the same output for the same inputs."""
        mod = _import_saga_nodes()
        key1 = mod._derive_idempotency_key("tx-123", "reverse_trade")
        key2 = mod._derive_idempotency_key("tx-123", "reverse_trade")
        assert key1 == key2, "Idempotency key must be deterministic"
        assert len(key1) == 32, f"Expected 32-char hex key, got length {len(key1)}"

    def test_derive_idempotency_key_differs_for_different_inputs(self) -> None:
        """_derive_idempotency_key must produce different outputs for different inputs."""
        mod = _import_saga_nodes()
        key1 = mod._derive_idempotency_key("tx-123", "reverse_trade")
        key2 = mod._derive_idempotency_key("tx-456", "reverse_trade")
        assert key1 != key2, "Different inputs must produce different idempotency keys"


# ---------------------------------------------------------------------------
# Tests: generated_stpa_validator.py
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGeneratedSTPAValidator:
    """Functional tests for src/gateway/governance/generated_stpa_validator.py."""

    def _get_validator(self):
        """Return a GeneratedSTPAValidator instance with mocked THRESHOLDS."""
        mod = _import_stpa_validator()
        return mod.GeneratedSTPAValidator()

    def test_module_exports_validator_class(self) -> None:
        """generated_stpa_validator must export GeneratedSTPAValidator."""
        mod = _import_stpa_validator()
        assert hasattr(mod, "GeneratedSTPAValidator"), (
            "generated_stpa_validator must define GeneratedSTPAValidator"
        )
        cls = mod.GeneratedSTPAValidator
        assert isinstance(cls, type), "GeneratedSTPAValidator must be a class"

    def test_validator_has_validate_method(self) -> None:
        """GeneratedSTPAValidator must have a validate() public entry-point."""
        validator = self._get_validator()
        assert hasattr(validator, "validate"), "Validator must have a validate() method"
        assert callable(validator.validate), "validate must be callable"

    def test_uca_1_passes_for_non_write_action(self) -> None:
        """UCA-1 must not trigger for non write_db actions."""
        validator = self._get_validator()
        violations = validator.validate("execute_trade", {"approval_token": "tok-123"})
        assert isinstance(violations, list), "validate() must return a list"
        # UCA-1 is write_db specific — should not appear for execute_trade
        uca1_violations = [v for v in violations if "UCA-1" in v]
        assert len(uca1_violations) == 0, (
            f"UCA-1 must not fire for execute_trade. Violations: {uca1_violations}"
        )

    def test_uca_1_triggers_for_write_db_without_token(self) -> None:
        """UCA-1 must fire for write_db action without approval_token."""
        validator = self._get_validator()
        violations = validator.validate("write_db", {})
        assert isinstance(violations, list), "validate() must return a list"
        uca1_violations = [v for v in violations if "UCA-1" in v]
        assert len(uca1_violations) >= 1, (
            "UCA-1 must trigger for write_db without approval_token"
        )

    def test_uca_1_passes_for_write_db_with_token(self) -> None:
        """UCA-1 must not fire for write_db when approval_token is provided."""
        validator = self._get_validator()
        violations = validator.validate("write_db", {"approval_token": "signed-tok"})
        assert isinstance(violations, list), "validate() must return a list"
        uca1_violations = [v for v in violations if "UCA-1" in v]
        assert len(uca1_violations) == 0, (
            f"UCA-1 must not fire when approval_token is present. Got: {uca1_violations}"
        )

    def test_uca_8_triggers_for_unassessed_trade(self) -> None:
        """UCA-8 must fire when risk_assessed=False."""
        validator = self._get_validator()
        violations = validator.validate(
            "execute_trade",
            {
                "risk_assessed": False,
                "drawdown": 0.1,
                "latency_ms": 50.0,
                "compliance_checked": True,
            },
        )
        uca8_violations = [v for v in violations if "UCA-8" in v]
        assert len(uca8_violations) >= 1, "UCA-8 must trigger when risk_assessed=False"

    def test_uca_9_triggers_for_compliance_bypass(self) -> None:
        """UCA-9 must fire when compliance_checked=False."""
        validator = self._get_validator()
        violations = validator.validate(
            "execute_trade",
            {
                "risk_assessed": True,
                "drawdown": 0.1,
                "latency_ms": 50.0,
                "compliance_checked": False,
            },
        )
        uca9_violations = [v for v in violations if "UCA-9" in v]
        assert len(uca9_violations) >= 1, (
            "UCA-9 must trigger when compliance_checked=False"
        )

    def test_safe_execute_trade_produces_no_violations(self) -> None:
        """A fully-compliant execute_trade call must produce zero violations."""
        validator = self._get_validator()
        violations = validator.validate(
            "execute_trade",
            {
                "risk_assessed": True,
                "compliance_checked": True,
                "drawdown": 0.1,  # well below threshold of 4.5
                "latency_ms": 50.0,  # well below max_latency_ms=200
                "approval_token": "tok",
                "order_size": 0,
                "daily_vol": 0,
            },
        )
        assert isinstance(violations, list), "validate() must return a list"
        assert len(violations) == 0, (
            f"Safe trade must produce zero violations, got: {violations}"
        )

    def test_validate_returns_list_for_unknown_action(self) -> None:
        """validate() must return an empty list for unknown action names."""
        validator = self._get_validator()
        violations = validator.validate("unknown_action", {})
        assert isinstance(violations, list), "Must return a list for unknown action"
        assert len(violations) == 0, (
            f"Unknown action must produce no violations, got: {violations}"
        )


# ---------------------------------------------------------------------------
# Tests: generated Rego, semantic policy, and Rails artifacts
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGeneratedPolicyArtifacts:
    """Structural tests for non-Python generated governance artifacts."""

    def test_generated_stpa_rego_exists(self) -> None:
        """config/opa/generated_stpa_policy.rego must exist."""
        assert _REGO_POLICY.exists(), (
            f"{_REGO_POLICY} not found. generated_stpa_policy.rego must be present."
        )

    def test_generated_stpa_rego_contains_package_declaration(self) -> None:
        """generated_stpa_policy.rego must have a 'package' statement."""
        if not _REGO_POLICY.exists():
            pytest.skip(f"{_REGO_POLICY} not found")
        content = _REGO_POLICY.read_text()
        assert "package" in content, (
            f"generated_stpa_policy.rego must contain a 'package' declaration, "
            f"got first 200 chars: {content[:200]!r}"
        )

    def test_generated_stpa_rego_contains_stpa_allow(self) -> None:
        """generated_stpa_policy.rego must define an stpa_allow rule."""
        if not _REGO_POLICY.exists():
            pytest.skip(f"{_REGO_POLICY} not found")
        content = _REGO_POLICY.read_text()
        assert "stpa_allow" in content, (
            "generated_stpa_policy.rego must define 'stpa_allow' rule"
        )

    def test_generated_stpa_rego_is_nonempty(self) -> None:
        """generated_stpa_policy.rego must have substantial content."""
        if not _REGO_POLICY.exists():
            pytest.skip(f"{_REGO_POLICY} not found")
        content = _REGO_POLICY.read_text()
        assert len(content.strip()) >= 50, (
            f"generated_stpa_policy.rego must have at least 50 characters, "
            f"got {len(content.strip())}"
        )

    def test_generated_semantic_policy_exists(self) -> None:
        """config/agp/generated_semantic_policy.txt must exist."""
        assert _SEMANTIC_POLICY.exists(), (
            f"{_SEMANTIC_POLICY} not found. "
            "generated_semantic_policy.txt must be present."
        )

    def test_generated_semantic_policy_is_nonempty(self) -> None:
        """generated_semantic_policy.txt must be non-empty."""
        if not _SEMANTIC_POLICY.exists():
            pytest.skip(f"{_SEMANTIC_POLICY} not found")
        content = _SEMANTIC_POLICY.read_text()
        assert len(content.strip()) >= 1, (
            "generated_semantic_policy.txt must not be empty"
        )

    def test_generated_stpa_rails_exists(self) -> None:
        """config/rails/generated_stpa_rails.co must exist."""
        assert _STPA_RAILS.exists(), (
            f"{_STPA_RAILS} not found. generated_stpa_rails.co must be present."
        )

    def test_generated_stpa_rails_is_nonempty(self) -> None:
        """generated_stpa_rails.co must be non-empty."""
        if not _STPA_RAILS.exists():
            pytest.skip(f"{_STPA_RAILS} not found")
        content = _STPA_RAILS.read_text()
        assert len(content.strip()) >= 1, "generated_stpa_rails.co must not be empty"
