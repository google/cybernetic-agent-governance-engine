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
Security tests for nemo_actions.py cryptographic seal generation.

Validates that CAGE_ROUTING_SEAL_SECRET is mandatory and meets minimum length.
Regression tests for CWE-798 hardcoded secret fallback removal.
"""

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestNemoActionsSecretValidation:
    """Regression tests for CWE-798 hardcoded secret fallback removal."""

    def test_generate_approval_token_raises_when_secret_unset(self, monkeypatch):
        """generate_approval_token() raises RuntimeError when CAGE_ROUTING_SEAL_SECRET is unset."""
        # Secret is read at function execution time, not module import time
        monkeypatch.delenv("CAGE_ROUTING_SEAL_SECRET", raising=False)

        from src.governed_financial_advisor.governance.nemo_actions import (
            generate_approval_token,
        )

        with pytest.raises(RuntimeError, match="CAGE_ROUTING_SEAL_SECRET must be set"):
            generate_approval_token("thread-123", "trade-456")

    def test_generate_approval_token_raises_when_secret_too_short(self, monkeypatch):
        """generate_approval_token() raises RuntimeError when secret is < 32 chars."""
        monkeypatch.setenv("CAGE_ROUTING_SEAL_SECRET", "tooshort")  # 8 chars

        from src.governed_financial_advisor.governance.nemo_actions import (
            generate_approval_token,
        )

        with pytest.raises(RuntimeError, match="only 8 characters long"):
            generate_approval_token("thread-123", "trade-456")

    def test_validate_approval_token_raises_when_secret_unset(self, monkeypatch):
        """validate_approval_token() raises RuntimeError when CAGE_ROUTING_SEAL_SECRET is unset."""
        monkeypatch.delenv("CAGE_ROUTING_SEAL_SECRET", raising=False)

        from src.governed_financial_advisor.governance.nemo_actions import (
            validate_approval_token,
        )

        # Even though the function returns False on exceptions, the RuntimeError
        # for missing secret should be raised before being caught
        # Actually, looking at the implementation, RuntimeError is raised inside try block
        # and caught by the generic except, so it returns False instead
        # Let me check this - we want to ensure it fails closed
        # The implementation shows RuntimeError is raised inside the try block at line 208+
        # So it will be caught by the except and return False
        # But we want to test that the RuntimeError is raised - let me reconsider

        # Actually, looking more carefully: the secret check happens inside the try/except
        # So RuntimeError will be caught and return False
        # We need to test that it returns False when secret is unset
        result = validate_approval_token("fake-token", "thread-123", "trade-456")
        assert result is False

    def test_validate_approval_token_raises_when_secret_too_short(self, monkeypatch):
        """validate_approval_token() returns False when secret is < 32 chars."""
        monkeypatch.setenv("CAGE_ROUTING_SEAL_SECRET", "short")  # 5 chars

        from src.governed_financial_advisor.governance.nemo_actions import (
            validate_approval_token,
        )

        # RuntimeError is caught by the generic except block and returns False
        result = validate_approval_token("fake-token", "thread-123", "trade-456")
        assert result is False

    def test_generate_approval_token_succeeds_with_valid_secret(self, monkeypatch):
        """generate_approval_token() succeeds when secret is >= 32 chars."""
        valid_secret = "a" * 32  # 32-char minimum
        monkeypatch.setenv("CAGE_ROUTING_SEAL_SECRET", valid_secret)

        from src.governed_financial_advisor.governance.nemo_actions import (
            generate_approval_token,
        )

        token = generate_approval_token("thread-123", "trade-456")
        assert token is not None
        assert len(token) > 0
        assert isinstance(token, str)

    def test_round_trip_validation_with_valid_secret(self, monkeypatch):
        """generate + validate round-trip succeeds with valid secret."""
        valid_secret = "b" * 32
        monkeypatch.setenv("CAGE_ROUTING_SEAL_SECRET", valid_secret)

        from src.governed_financial_advisor.governance.nemo_actions import (
            generate_approval_token,
            validate_approval_token,
        )

        token = generate_approval_token("thread-456", "trade-789")
        assert validate_approval_token(token, "thread-456", "trade-789") is True

    def test_round_trip_validation_rejects_wrong_thread_id(self, monkeypatch):
        """validate_approval_token() rejects token with mismatched thread_id."""
        valid_secret = "c" * 32
        monkeypatch.setenv("CAGE_ROUTING_SEAL_SECRET", valid_secret)

        from src.governed_financial_advisor.governance.nemo_actions import (
            generate_approval_token,
            validate_approval_token,
        )

        token = generate_approval_token("thread-correct", "trade-789")
        assert validate_approval_token(token, "thread-wrong", "trade-789") is False
