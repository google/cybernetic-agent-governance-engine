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
Security tests for scripts/ utilities to prevent shell injection vulnerabilities.

Regression tests for CWE-78 shell injection removal in scripts/verify_all.py
and scripts/lib/utils.py.
"""

import shlex

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestShellInjectionPrevention:
    """Regression tests for CWE-78 shell injection removal."""

    def test_verify_all_does_not_use_shell_true(self):
        """verify_all.py subprocess.run() does not use shell=True."""
        import inspect

        import scripts.verify_all as verify_all

        source = inspect.getsource(verify_all.run_command)

        # Assert shell=True is NOT present in the function
        assert "shell=True" not in source, (
            "verify_all.run_command() must not use shell=True (CWE-78 prevention)"
        )

        # Assert shlex.split is present (secure pattern)
        assert "shlex.split" in source, (
            "verify_all.run_command() must use shlex.split() for safe argument parsing"
        )

    def test_lib_utils_does_not_use_shell_true(self):
        """scripts/lib/utils.py subprocess.run() does not use shell=True."""
        import inspect

        import scripts.lib.utils as utils

        source = inspect.getsource(utils)

        # Count shell=True occurrences (should be 0)
        shell_true_count = source.count("shell=True")
        assert shell_true_count == 0, (
            f"Found {shell_true_count} shell=True in lib/utils.py (expected 0 after CWE-78 fix)"
        )

    def test_shlex_split_tokenizes_command_chaining_safely(self):
        """shlex.split() treats command separators as literal tokens, not shell operators."""
        malicious_cmd = "echo safe; echo danger"
        args = shlex.split(malicious_cmd)

        # Command chaining operators are tokenized as literal strings
        assert args == ["echo", "safe;", "echo", "danger"]

        # This proves the injection vector is neutralized:
        # - ";" is treated as part of the first argument "safe;"
        # - No second command execution occurs

    def test_shlex_split_neutralizes_pipe_injection(self):
        """shlex.split() neutralizes pipe injection attempts."""
        pipe_injection = "ls | grep secret"
        args = shlex.split(pipe_injection)

        # Pipe operator is tokenized as a literal argument
        assert args == ["ls", "|", "grep", "secret"]

    def test_shlex_split_neutralizes_redirection_injection(self):
        """shlex.split() neutralizes file redirection injection."""
        redirect_injection = "cat /etc/passwd > /tmp/stolen"
        args = shlex.split(redirect_injection)

        # Redirection operators are tokenized as literals
        assert args == ["cat", "/etc/passwd", ">", "/tmp/stolen"]
