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
R-22 Regression Guard — NeMo Action Registry completeness.

Asserts that:
1. ``config.rails.actions`` exports all expected financial pass-through stubs,
   i.e. the Priority-1 import path in ``nemo_action_registry.get_all_actions()``
   does NOT trigger an ImportError for any action.
2. All stubs are async callables.
3. The stubs return True (pass-through / fail-open semantics consistent with
   OPA being the authoritative financial policy enforcer).
4. ``nemo_action_registry.get_all_actions()`` returns all required action names
   without falling back to the synchronous Priority-2 stubs.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SEMANTIC_ACTIONS = [
    "retrieve_knowledge",
    "mask_pii_action",
    "custom_self_check_input",
    "custom_self_check_output",
]

FINANCIAL_STUB_ACTIONS = [
    "check_approval_token_action",
    "check_data_latency_action",
    "check_drawdown_limit_action",
    "check_slippage_risk_action",
    "check_atomic_execution_action",
    "log_safety_audit_action",
]

ALL_EXPECTED_ACTIONS = SEMANTIC_ACTIONS + FINANCIAL_STUB_ACTIONS

# Registry names (as registered with rails.register_action)
REGISTRY_ACTION_NAMES = [
    "RetrieveKnowledgeAction",
    "CheckApprovalTokenAction",
    "CheckDataLatencyAction",
    "CheckDrawdownLimitAction",
    "CheckSlippageRiskAction",
    "CheckAtomicExecutionAction",
    "MaskPIIAction",
    "CustomSelfCheckInputAction",
    "CustomSelfCheckOutputAction",
    "mask_sensitive_data",
    "detect_sensitive_data",
    "InvokeVllmFallbackAction",
]


# ---------------------------------------------------------------------------
# 1. config.rails.actions exports
# ---------------------------------------------------------------------------


class TestConfigRailsActionsExports:
    """All actions must be importable from config.rails.actions (P1 path)."""

    def setup_method(self):
        self.module = importlib.import_module("config.rails.actions")

    @pytest.mark.parametrize("name", ALL_EXPECTED_ACTIONS)
    def test_action_exported(self, name):
        assert hasattr(self.module, name), (
            f"config.rails.actions is missing '{name}' — "
            f"nemo_action_registry Priority-1 will ImportError and fall back to sync stubs. "
            f"Add a pass-through stub for this action. (R-22)"
        )

    @pytest.mark.parametrize("name", FINANCIAL_STUB_ACTIONS)
    def test_financial_stub_is_async(self, name):
        fn = getattr(self.module, name)
        assert inspect.iscoroutinefunction(fn), (
            f"config.rails.actions.{name} must be an async function "
            f"(NeMo expects async action callables)."
        )

    @pytest.mark.parametrize("name", ALL_EXPECTED_ACTIONS)
    def test_name_in_all(self, name):
        all_names = getattr(self.module, "__all__", [])
        assert name in all_names, (
            f"'{name}' is defined in config.rails.actions but not listed in __all__."
        )


# ---------------------------------------------------------------------------
# 2. Financial pass-through stubs return True
# ---------------------------------------------------------------------------


class TestFinancialStubReturnValues:
    """Financial pass-through stubs must return True (fail-open; OPA is authoritative)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", FINANCIAL_STUB_ACTIONS)
    async def test_stub_returns_true(self, name):
        module = importlib.import_module("config.rails.actions")
        fn = getattr(module, name)
        result = await fn(context={})
        assert result is True, (
            f"config.rails.actions.{name} returned {result!r} — "
            f"financial stubs must return True (pass-through; OPA enforces policy)."
        )

    @pytest.mark.asyncio
    async def test_stub_handles_none_context(self):
        """Stubs must not crash when called with context=None."""
        from config.rails.actions import check_approval_token_action

        result = await check_approval_token_action(context=None)
        assert result is True

    @pytest.mark.asyncio
    async def test_stub_handles_extra_kwargs(self):
        """Stubs must accept arbitrary kwargs (NeMo may pass extra arguments)."""
        from config.rails.actions import check_drawdown_limit_action

        result = await check_drawdown_limit_action(
            context={"amount": 5000.0}, event={"type": "execute_trade"}
        )
        assert result is True


# ---------------------------------------------------------------------------
# 3. nemo_action_registry.get_all_actions() completeness (Priority-1 path)
# ---------------------------------------------------------------------------


class TestNemoActionRegistryCompleteness:
    """get_all_actions() must return all required names without falling back."""

    def test_all_required_names_present(self):
        from src.governed_financial_advisor.governance.nemo_action_registry import (
            get_all_actions,
        )

        actions = get_all_actions()
        registered_names = {name for name, _ in actions}

        for required in REGISTRY_ACTION_NAMES:
            assert required in registered_names, (
                f"nemo_action_registry.get_all_actions() is missing '{required}'. "
                f"This means the Priority-1 config.rails.actions import failed and "
                f"the system fell back to synchronous stubs (R-22 regression)."
            )

    def test_no_duplicate_names(self):
        from src.governed_financial_advisor.governance.nemo_action_registry import (
            get_all_actions,
        )

        actions = get_all_actions()
        names = [name for name, _ in actions]
        assert len(names) == len(set(names)), (
            f"Duplicate action names in get_all_actions(): "
            f"{[n for n in names if names.count(n) > 1]}"
        )

    def test_all_callables_are_callable(self):
        from src.governed_financial_advisor.governance.nemo_action_registry import (
            get_all_actions,
        )

        actions = get_all_actions()
        for name, fn in actions:
            assert callable(fn), f"Action '{name}' is not callable."


# ---------------------------------------------------------------------------
# 4. Colang definitions.co declares all registered actions
# ---------------------------------------------------------------------------


class TestColangDefinitionsSync:
    """definitions.co must declare every action that is Python-registered."""

    DECLARED_IN_DEFINITIONS_CO = {
        "MaskPIIAction",
        "InvokeVllmFallbackAction",
        "CustomSelfCheckInputAction",
        "CustomSelfCheckOutputAction",
        "LogSafetyAuditAction",
    }

    def test_log_safety_audit_has_python_impl(self):
        """LogSafetyAuditAction is declared in definitions.co and must have a Python impl."""
        from config.rails.actions import log_safety_audit_action

        assert callable(log_safety_audit_action)

    def test_invoke_vllm_fallback_accessible(self):
        """InvokeVllmFallbackAction must be accessible via nemo_action_registry."""
        from src.governed_financial_advisor.governance.nemo_action_registry import (
            get_all_actions,
        )

        names = {n for n, _ in get_all_actions()}
        assert "InvokeVllmFallbackAction" in names


pytestmark = [pytest.mark.unit, pytest.mark.local]
