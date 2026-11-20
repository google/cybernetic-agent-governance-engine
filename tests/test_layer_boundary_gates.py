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

"""Tests for layer boundary enforcement gates (G3, G6, G8).

Each gate needs a test proving it actually fails on a violation. A gate that has never
been observed failing is indistinguishable from one that does nothing.

Test coverage:
  1. G3 reverse scan (9a) rejects src/integrations/ importing src.cage_*
  2. G6 rejects a domain literal introduced into src/integrations/
  3. G8 rejects a vendor brand introduced as an executable literal in src/gateway/
  4. G8 accepts the same brand in a docstring or comment
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from scripts.check_domain_literals import check_file as check_domain_file
from scripts.check_import_boundaries import (
    check_integrations_boundaries,
)
from scripts.check_vendor_brands import check_file as check_vendor_file

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestG3ReverseScan:
    """Gate G3 reverse scan: src/integrations/ must not import src.cage_* or Layer 4."""

    def test_rejects_integrations_importing_cage_domain(self):
        """9a: Reverse scan rejects src/integrations/ importing src.cage_finance."""
        # Create a synthetic integrations file importing a domain plugin
        source = """
# Test file
from src.cage_finance.tiers import FinanceTier

def foo():
    pass
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="."
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_integrations_boundaries(temp_path, verbose=False)
            assert len(violations) >= 1, "G3 reverse scan should detect cage_* import"
            assert any("cage_finance" in v.imported_module for v in violations), (
                "Violation should identify cage_finance import"
            )
        finally:
            temp_path.unlink()

    def test_rejects_integrations_importing_compliance_bridge(self):
        """9a: Reverse scan rejects src/integrations/ importing src.compliance_bridge (non-allowlisted)."""
        # Create a synthetic integrations file importing compliance_bridge
        source = """
# Test file (not in allowlist)
from src.compliance_bridge.audit_workflow import AuditWorkflow

def bar():
    pass
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="."
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_integrations_boundaries(temp_path, verbose=False)
            # Should detect violation if not in allowlist
            # (provider_02/cer_index.py is allowlisted, but this file is not)
            if "cer_index.py" not in str(temp_path):
                assert len(violations) >= 1, (
                    "G3 reverse scan should detect compliance_bridge import outside allowlist"
                )
        finally:
            temp_path.unlink()


class TestG6DomainLiterals:
    """Gate G6: src/integrations/ must not contain domain action literals."""

    def test_rejects_domain_literal_in_integrations(self):
        """9b: G6 rejects domain literal 'execute_trade' in src/integrations/ non-test file."""
        # Create a synthetic integrations file with a domain literal
        source = """
# Not a test file
def process_action(action_name):
    if action_name == "execute_trade":
        return True
    return False
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            dir=".",
            prefix="adapter_",  # not test_*
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_domain_file(temp_path)
            assert len(violations) >= 1, (
                "G6 should detect 'execute_trade' in integrations code"
            )
            assert any("execute_trade" in literal for _, literal in violations), (
                "Violation should identify execute_trade literal"
            )
        finally:
            temp_path.unlink()


class TestG8VendorBrands:
    """Gate G8: src/gateway/ must not contain vendor brand literals in executable code."""

    def test_rejects_vendor_brand_in_executable_code(self):
        """9c: G8 rejects vendor brand 'langfuse' in executable string literal."""
        # Temporarily add langfuse to the forbidden list for this test
        from scripts import check_vendor_brands

        original_brands = check_vendor_brands.FORBIDDEN_VENDOR_BRANDS.copy()
        check_vendor_brands.FORBIDDEN_VENDOR_BRANDS = {"langfuse"}

        source = """
# Test file with vendor brand in executable code
def get_telemetry_provider():
    provider = "langfuse"
    return provider
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="."
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_vendor_file(temp_path)
            assert len(violations) >= 1, (
                "G8 should detect 'langfuse' in executable code"
            )
            assert any("langfuse" in literal.lower() for _, literal in violations), (
                "Violation should identify langfuse literal"
            )
        finally:
            temp_path.unlink()
            # Restore original brand list
            check_vendor_brands.FORBIDDEN_VENDOR_BRANDS = original_brands

    def test_accepts_vendor_brand_in_docstring(self):
        """9c: G8 accepts vendor brand 'langfuse' in docstring (prose is legitimate)."""
        from scripts import check_vendor_brands

        original_brands = check_vendor_brands.FORBIDDEN_VENDOR_BRANDS.copy()
        check_vendor_brands.FORBIDDEN_VENDOR_BRANDS = {"langfuse"}

        source = '''
"""Module for telemetry.

This module integrates with Langfuse for sovereign observability.
The vendor name in this docstring is legitimate documentation.
"""

def get_telemetry_provider():
    # Langfuse is the reference implementation (comment is also fine)
    provider = "abstract_telemetry_provider"  # Not the vendor name
    return provider
'''
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="."
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_vendor_file(temp_path)
            # Should NOT flag docstring or comment occurrences
            assert len(violations) == 0, (
                "G8 should NOT flag vendor names in docstrings or comments"
            )
        finally:
            temp_path.unlink()
            # Restore original brand list
            check_vendor_brands.FORBIDDEN_VENDOR_BRANDS = original_brands

    def test_accepts_vendor_brand_in_comment(self):
        """9c: G8 accepts vendor brand in comments (AST is comment-blind by design)."""
        from scripts import check_vendor_brands

        original_brands = check_vendor_brands.FORBIDDEN_VENDOR_BRANDS.copy()
        check_vendor_brands.FORBIDDEN_VENDOR_BRANDS = {"langfuse"}

        source = """
# Langfuse integration example
# This comment mentions the vendor but should not trigger the gate
def foo():
    return "safe_value"
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="."
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_vendor_file(temp_path)
            assert len(violations) == 0, "G8 should NOT flag vendor names in comments"
        finally:
            temp_path.unlink()
            # Restore original brand list
            check_vendor_brands.FORBIDDEN_VENDOR_BRANDS = original_brands

    def test_rejects_partner_brand_in_file_path(self):
        """G8 path check rejects branded filenames across scripts/, tests/, and vectors/."""
        from scripts.check_vendor_brands import PARTNER_VENDOR_BRANDS, check_path

        repo_root = Path("/repo")
        assert check_path(
            repo_root / "scripts" / "verify_flowsignal_wire_and_hostile.py",
            repo_root,
            PARTNER_VENDOR_BRANDS,
        ) == ["flowsignal"]
        assert check_path(
            repo_root
            / "packages"
            / "cage-conformance"
            / "src"
            / "cage_conformance"
            / "vectors"
            / "flowsignal_v02.json",
            repo_root,
            PARTNER_VENDOR_BRANDS,
        ) == ["flowsignal"]
        assert (
            check_path(
                repo_root / "scripts" / "verify_provider_01_wire_and_hostile.py",
                repo_root,
                PARTNER_VENDOR_BRANDS,
            )
            == []
        )

    def test_rejects_partner_brand_in_class_and_function_identifiers(self):
        """G8 rejects reintroducing FlowSignalNormativeProvider in src/integrations/."""
        from scripts.check_vendor_brands import PARTNER_VENDOR_BRANDS

        source = """
class FlowSignalNormativeProvider:
    def _map_flowsignal_decision(self, flowsignal_resp: dict) -> str:
        return "ALLOW"
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="."
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_vendor_file(
                temp_path,
                PARTNER_VENDOR_BRANDS,
                allow_wire_literals=True,
            )
            tokens = [token for _, token in violations]
            assert "class:FlowSignalNormativeProvider" in tokens
            assert "def:_map_flowsignal_decision" in tokens
            assert "arg:flowsignal_resp" in tokens
        finally:
            temp_path.unlink()

    def test_layer3_wire_protocol_literal_boundary(self):
        """G8 permits LAYER3_WIRE_PROTOCOL_LITERALS at Layer 3 but rejects non-wire partner strings."""
        from scripts.check_vendor_brands import PARTNER_VENDOR_BRANDS

        source = """
RECEIPT_DOMAIN_TAG = b"ARCHYTAN_RECEIPT_V1:"
WELL_KNOWN = "/.well-known/nexart-node.json"
BAD_URL = "https://flowsignal.example.com/v1/evaluate"
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="."
        ) as f:
            f.write(source)
            f.flush()
            temp_path = Path(f.name)

        try:
            violations = check_vendor_file(
                temp_path,
                PARTNER_VENDOR_BRANDS,
                allow_wire_literals=True,
            )
            assert violations == [(4, "https://flowsignal.example.com/v1/evaluate")]
        finally:
            temp_path.unlink()

    def test_layer3_wire_protocol_provenance_and_ceiling(self, tmp_path):
        """G8 enforces .md/.json spec/vector provenance on LAYER3_WIRE_PROTOCOL_PROVENANCE and pins the 36-entry ceiling."""
        from scripts.check_vendor_brands import (
            LAYER3_WIRE_PROTOCOL_PROVENANCE,
            check_wire_literal_provenance,
        )

        repo_root = Path(__file__).resolve().parent.parent
        assert check_wire_literal_provenance(repo_root) == []
        assert len(LAYER3_WIRE_PROTOCOL_PROVENANCE) == 36

        # Rejects citing a .py file as provenance
        py_file = tmp_path / "adapter.py"
        py_file.write_text('TAG = "flowsignal-convenient-string"\n', encoding="utf-8")
        errs_py = check_wire_literal_provenance(
            tmp_path,
            {"flowsignal-convenient-string": "adapter.py"},
        )
        assert len(errs_py) == 1
        assert "non-Python" in errs_py[0]

        # Rejects citing a .md/.json artifact that does not contain the literal
        spec_file = tmp_path / "spec.md"
        spec_file.write_text(
            "# Partner Spec\nNo such constant here.\n", encoding="utf-8"
        )
        errs_missing = check_wire_literal_provenance(
            tmp_path,
            {"flowsignal-unverified-constant": "spec.md"},
        )
        assert len(errs_missing) == 1
        assert "not found in cited provenance artifact" in errs_missing[0]

    def test_slot_brand_tokens_cover_every_partner_slot_and_fail_on_drift(self):
        """G8 mechanically enforces 1:1 parity between SLOT_BRAND_TOKENS and check_partner_headers.PARTNER_SLOTS."""
        from scripts.check_partner_headers import PARTNER_SLOTS, PartnerSlot
        from scripts.check_vendor_brands import (
            SLOT_BRAND_TOKENS,
            check_partner_slot_coverage,
        )

        repo_root = Path(__file__).resolve().parent.parent
        assert check_partner_slot_coverage(repo_root) == []
        assert set(SLOT_BRAND_TOKENS) == set(PARTNER_SLOTS)

        # Omitting an active partner slot fails closed
        without_p09 = {k: v for k, v in SLOT_BRAND_TOKENS.items() if k != "provider_09"}
        errs_missing = check_partner_slot_coverage(
            repo_root, slot_tokens=without_p09, partner_slots=PARTNER_SLOTS
        )
        assert any("provider_09" in e and "no brand tokens" in e for e in errs_missing)

        # Registering tokens unrelated to the canonical vendor fails closed
        mismatched_slots = {
            **PARTNER_SLOTS,
            "provider_99": PartnerSlot(
                vendor="ExampleVendorCorp",
                status_label="ExampleVendorCorp",
                seams=("NormativeProvider",),
            ),
        }
        mismatched_tokens = {
            **SLOT_BRAND_TOKENS,
            "provider_99": frozenset({"unrelatedtoken"}),
        }
        errs_mismatch = check_partner_slot_coverage(
            repo_root, slot_tokens=mismatched_tokens, partner_slots=mismatched_slots
        )
        assert any("do not match canonical vendor" in e for e in errs_mismatch)

    def test_rejects_previously_omitted_partner_brands_and_layer1_wire_literals(
        self, tmp_path
    ):
        """G8 catches all 6 previously omitted partner slots and blocks Layer 3 wire literals in Layer 1."""
        from scripts.check_vendor_brands import (
            FORBIDDEN_VENDOR_BRANDS,
            PARTNER_VENDOR_BRANDS,
            check_path,
        )

        repo_root = Path("/repo")
        for branded_rel in (
            "tests/integrations/provider_05/test_veip_vectors.py",
            "src/integrations/provider_09/opscanvas_adapter.py",
            "src/integrations/actuator_02/openshell_bridge.py",
            "src/integrations/actuator_03/doca_quarantine.py",
            "src/integrations/provider_03/veritas_client.py",
            "src/integrations/provider_06/guardiancyber_adapter.py",
        ):
            assert check_path(repo_root / branded_rel, repo_root, PARTNER_VENDOR_BRANDS)

        kernel_file = tmp_path / "kernel_leak.py"
        kernel_file.write_text(
            'SCHEMA = "veip-warrant/0.2"\nALIAS = "opscanvas"\n',
            encoding="utf-8",
        )
        # Layer 1 sets allow_wire_literals=False, so even registered Layer 3 wire strings fail
        kernel_violations = check_vendor_file(
            kernel_file,
            FORBIDDEN_VENDOR_BRANDS,
            allow_wire_literals=False,
        )
        assert len(kernel_violations) == 2
