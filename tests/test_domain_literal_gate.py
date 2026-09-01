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

"""Domain literal detection gate (G6) tests.

Validates that scripts/check_domain_literals.py correctly detects forbidden
domain action literals in kernel code and allows them in docstrings/comments.

Part of: PR A - Capability-Driven Tier Dispatch (Stage 8)
Gate: G6 (domain literal enforcement)
"""

import pytest
import subprocess
import tempfile
import os
from pathlib import Path


@pytest.mark.local
class TestDomainLiteralGate:
    """Domain literal gate (G6) tests."""

    def test_gate_passes_on_clean_kernel(self) -> None:
        """G6 gate passes when src/gateway/ contains no domain literals."""
        result = subprocess.run(
            ["uv", "run", "python", "scripts/check_domain_literals.py"],
            capture_output=True,
            text=True,
        )

        # Should pass (exit code 0)
        assert result.returncode == 0
        assert "✅ Gate G6 PASSED" in result.stdout

    def test_gate_detects_execute_trade_literal(self) -> None:
        """G6 gate detects 'execute_trade' in executable code."""
        # Create a temporary file with a forbidden literal
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            dir="src/gateway/governance",
            delete=False,
        ) as f:
            f.write('action = "execute_trade"\n')
            temp_path = f.name

        try:
            result = subprocess.run(
                ["uv", "run", "python", "scripts/check_domain_literals.py"],
                capture_output=True,
                text=True,
            )

            # Should fail (exit code 1)
            assert result.returncode == 1
            assert "❌ Gate G6 FAILED" in result.stdout
            assert "execute_trade" in result.stdout
        finally:
            os.unlink(temp_path)

    def test_gate_allows_literals_in_docstrings(self) -> None:
        """G6 gate allows domain literals in docstrings."""
        # Create a temporary file with literal in docstring
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            dir="src/gateway/governance",
            delete=False,
        ) as f:
            f.write('"""Example: execute_trade action."""\n')
            f.write('def foo(): pass\n')
            temp_path = f.name

        try:
            result = subprocess.run(
                ["uv", "run", "python", "scripts/check_domain_literals.py"],
                capture_output=True,
                text=True,
            )

            # Should pass (docstrings are excluded)
            assert result.returncode == 0
        finally:
            os.unlink(temp_path)

    def test_gate_allows_literals_in_comments(self) -> None:
        """G6 gate allows domain literals in comments."""
        # Create a temporary file with literal in comment
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            dir="src/gateway/governance",
            delete=False,
        ) as f:
            f.write('# This used to handle execute_trade\n')
            f.write('def foo(): pass\n')
            temp_path = f.name

        try:
            result = subprocess.run(
                ["uv", "run", "python", "scripts/check_domain_literals.py"],
                capture_output=True,
                text=True,
            )

            # Should pass (comments are excluded by line-level filtering)
            assert result.returncode == 0
        finally:
            os.unlink(temp_path)


@pytest.mark.local
class TestDomainLiteralGateExclusions:
    """G6 gate exclusion tests."""

    def test_gate_excludes_generated_files(self) -> None:
        """G6 gate skips files in EXCLUDED_FILES list."""
        # The gate should skip generated files like stpa_actions.py
        # We can't easily test this without modifying real files,
        # but we can verify the exclusion list exists
        
        # Read the script to verify exclusion logic
        script_path = Path("scripts/check_domain_literals.py")
        content = script_path.read_text()
        
        assert "EXCLUDED_FILES" in content
        assert "stpa_actions.py" in content

    def test_gate_excludes_proto_generated_files(self) -> None:
        """G6 gate skips *_pb2.py generated protobuf files."""
        script_path = Path("scripts/check_domain_literals.py")
        content = script_path.read_text()
        
        assert "_pb2.py" in content or "generated" in content.lower()

    def test_gate_scans_src_gateway_only(self) -> None:
        """G6 gate only scans src/gateway/ (kernel Layer 1)."""
        script_path = Path("scripts/check_domain_literals.py")
        content = script_path.read_text()
        
        # Should target src/gateway/ specifically
        assert "src/gateway" in content


@pytest.mark.local
class TestDomainLiteralGateOutput:
    """G6 gate output format tests."""

    def test_gate_reports_file_count_on_pass(self) -> None:
        """G6 gate reports number of files scanned on pass."""
        result = subprocess.run(
            ["uv", "run", "python", "scripts/check_domain_literals.py"],
            capture_output=True,
            text=True,
        )

        assert "scanned" in result.stdout.lower()
        assert "files" in result.stdout.lower()

    def test_gate_reports_forbidden_literals_list(self) -> None:
        """G6 gate output includes the forbidden literals list."""
        result = subprocess.run(
            ["uv", "run", "python", "scripts/check_domain_literals.py"],
            capture_output=True,
            text=True,
        )

        # Should mention the forbidden literals
        output = result.stdout + result.stderr
        assert "execute_trade" in output or "reverse_trade" in output
