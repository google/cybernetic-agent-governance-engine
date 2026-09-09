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
