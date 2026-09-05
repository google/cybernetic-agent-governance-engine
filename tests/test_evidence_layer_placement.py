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

"""Tests verifying kernel independence from Layer 3 (compliance_bridge).

Ensures the kernel can boot, evaluate governance, issue seals, and process evidence
when Layer 3 (compliance_bridge) is completely absent or poisoned in sys.modules.
"""

from __future__ import annotations

import importlib
import sys
from unittest.mock import patch

import pytest


class TestEvidenceLayerPlacement:
    """Verifies that Layer 1 kernel has no dependency on Layer 3 compliance_bridge."""

    def test_no_compatibility_shim_at_legacy_path(self) -> None:
        """Legacy path src.compliance_bridge.evidence_stream must fail loudly with ModuleNotFoundError.

        Per AGENTS.md clean architecture principles, no compatibility shims or
        aliases are preserved.
        """
        # Ensure fresh import attempt
        sys.modules.pop("src.compliance_bridge.evidence_stream", None)
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("src.compliance_bridge.evidence_stream")

    def test_kernel_boots_with_compliance_bridge_poisoned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Kernel modules must import and function with compliance_bridge blocked in sys.modules."""
        monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
        poisoned_modules = {
            "src.compliance_bridge": None,
            "src.compliance_bridge.evidence_stream": None,
            "src.compliance_bridge.main": None,
            "src.compliance_bridge.types": None,
            "compliance_bridge": None,
            "compliance_bridge.evidence_stream": None,
        }

        with patch.dict(sys.modules, poisoned_modules):
            # 1. Evidence module and submodules
            import src.gateway.governance.evidence as evidence_pkg
            import src.gateway.governance.evidence.factory as evidence_factory
            import src.gateway.governance.evidence.stream as evidence_stream
            import src.gateway.governance.iso_control as iso_control

            # 2. Kernel governance modules that log or process evidence
            import src.gateway.governance.routing_seal as routing_seal
            import src.gateway.governance.uca_logger as uca_logger
            import src.gateway.observability.langfuse_utils as langfuse_utils

            # 3. Server / middleware modules
            import src.gateway.server.governance_middleware as gov_mw
            import src.gateway.server.hybrid_server as hybrid_srv

            # Verify core symbols are present and callable
            sink = evidence_stream.get_evidence_sink()
            assert sink is not None
            assert hasattr(evidence_stream, "EvidenceRecord")
            assert hasattr(evidence_pkg, "get_cold_store")

            # Verify seal generation works without compliance_bridge
            seal = routing_seal.generate_seal("test_action", {"key": "value"})
            assert seal is not None
            assert routing_seal.verify_seal(seal, "test_action", {"key": "value"})

            # Verify ISO control map works
            control_map = iso_control.get_iso_control_map("US_FED")
            assert "A.6.1.1" in control_map or len(control_map) > 0

