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

"""Tests for execute_trade_bounded terminal classification.

Phase 5 Step 11 validation: execute_trade_bounded must be classified as
EXTERNALLY_REVERSIBLE in terminal_registry.json, enabling HITL review without
the confidence hard-gate (per VEC-004 conformance vector).

Critical design point:
- execute_trade is IRREVERSIBLE_TERMINAL (T₀ worst-case, blocks low-confidence)
- execute_trade_bounded is EXTERNALLY_REVERSIBLE (allows HITL review at any confidence)
- When B10 rollback window validation fails, it emits a classification override
  to IRREVERSIBLE_TERMINAL, preventing execution
"""

import pytest

from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
from src.gateway.governance.ftra.models import TerminalClassification


class TestExecuteTradeBoundedClassification:
    """Phase 5 Step 11 validation: execute_trade_bounded terminal classification."""

    def test_execute_trade_bounded_is_externally_reversible(self):
        """Verify execute_trade_bounded is classified as EXTERNALLY_REVERSIBLE.

        Per Phase 5 implementation plan:
        - execute_trade_bounded extends execute_trade with rollback_window_seconds
        - B10 contract validates the rollback window is sufficient for external reversibility
        - When B10 passes, action remains EXTERNALLY_REVERSIBLE (enables HITL at any confidence)
        - When B10 fails, it emits classification override to IRREVERSIBLE_TERMINAL
        """
        classifier = IrreversibilityClassifier()
        classification = classifier.classify("execute_trade_bounded")

        assert classification == TerminalClassification.EXTERNALLY_REVERSIBLE, (
            "execute_trade_bounded must be EXTERNALLY_REVERSIBLE to enable "
            "HITL review without confidence hard-gate (VEC-004 conformance)"
        )

    def test_execute_trade_remains_irreversible_terminal(self):
        """Verify execute_trade remains IRREVERSIBLE_TERMINAL (baseline action).

        execute_trade is the T₀ worst-case action without bounding contract protection.
        It must remain IRREVERSIBLE_TERMINAL to enforce the confidence hard-gate.
        """
        classifier = IrreversibilityClassifier()
        classification = classifier.classify("execute_trade")

        assert classification == TerminalClassification.IRREVERSIBLE_TERMINAL

    def test_execute_trade_bounded_in_known_actions(self):
        """Verify execute_trade_bounded appears in terminal registry."""
        classifier = IrreversibilityClassifier()
        known_actions = classifier.known_actions()

        assert "execute_trade_bounded" in known_actions, (
            "execute_trade_bounded must be present in terminal_registry.json"
        )

    def test_classification_semantics_differ(self):
        """Verify execute_trade and execute_trade_bounded have different classifications.

        This distinction is the foundation of Phase 5:
        - execute_trade: IRREVERSIBLE_TERMINAL → blocks low-confidence, T₀ worst-case
        - execute_trade_bounded: EXTERNALLY_REVERSIBLE → HITL at any confidence, B10 validation
        """
        classifier = IrreversibilityClassifier()

        trade_class = classifier.classify("execute_trade")
        bounded_class = classifier.classify("execute_trade_bounded")

        assert trade_class == TerminalClassification.IRREVERSIBLE_TERMINAL
        assert bounded_class == TerminalClassification.EXTERNALLY_REVERSIBLE
        assert trade_class != bounded_class, (
            "execute_trade and execute_trade_bounded must have different "
            "classifications to enable bounding contract protection"
        )

    def test_externally_reversible_severity(self):
        """Verify EXTERNALLY_REVERSIBLE severity is less restrictive than IRREVERSIBLE_TERMINAL.

        Per CLASSIFICATION_SEVERITY mapping:
        - READ_ONLY: 0
        - REVERSIBLE: 1
        - EXTERNALLY_REVERSIBLE: 2
        - IRREVERSIBLE_TERMINAL: 3

        This ordering determines FTRA verdict routing:
        - IRREVERSIBLE_TERMINAL → CONFIDENCE_HARD_GATE (blocks low confidence)
        - EXTERNALLY_REVERSIBLE → HITL_REQUIRED (parks for review at any confidence)
        """
        from src.gateway.governance.ftra.models import CLASSIFICATION_SEVERITY

        ext_reversible_severity = CLASSIFICATION_SEVERITY[
            TerminalClassification.EXTERNALLY_REVERSIBLE
        ]
        irreversible_severity = CLASSIFICATION_SEVERITY[
            TerminalClassification.IRREVERSIBLE_TERMINAL
        ]

        assert ext_reversible_severity < irreversible_severity, (
            "EXTERNALLY_REVERSIBLE must be less restrictive than IRREVERSIBLE_TERMINAL"
        )
        assert ext_reversible_severity == 2
        assert irreversible_severity == 3


@pytest.mark.local
class TestTerminalRegistryIntegrity:
    """Guard tests for terminal_registry.json schema integrity."""

    def test_registry_contains_all_finance_actions(self):
        """Verify all finance domain actions are registered.

        Per fail-closed semantics, any action absent from the registry is
        classified as IRREVERSIBLE_TERMINAL at runtime. This test ensures
        all finance domain actions have explicit classifications.
        """
        classifier = IrreversibilityClassifier()
        known_actions = classifier.known_actions()

        expected_finance_actions = [
            "execute_trade",
            "execute_trade_bounded",
            "check_balance",
            "release_wire",
        ]

        for action in expected_finance_actions:
            assert action in known_actions, (
                f"Finance action '{action}' must be present in terminal_registry.json"
            )

    def test_registry_version_unchanged(self):
        """Verify terminal registry uses v3.0 schema (upgraded from v1.0)."""
        import json
        from pathlib import Path

        registry_path = Path("config/ftra/terminal_registry.json")
        with open(registry_path) as f:
            registry = json.load(f)

        assert registry["version"] == "3.0", (
            "Terminal registry must use v3.0 schema (includes domain, serial, issued_at, expires_at)"
        )

    def test_registry_has_fail_closed_note(self):
        """Verify fail-closed semantics are documented in registry."""
        import json
        from pathlib import Path

        registry_path = Path("config/ftra/terminal_registry.json")
        with open(registry_path) as f:
            registry = json.load(f)

        assert "fail_closed_note" in registry
        assert "IRREVERSIBLE_TERMINAL" in registry["fail_closed_note"]
