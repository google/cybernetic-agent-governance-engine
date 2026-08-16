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
Tests for evidence stream startup precondition validation.

Phase 2.2: Validates that EVIDENCE_CHAIN_BLOCKING=true requires
EVIDENCE_STREAM_ENABLED=true. This fail-fast check prevents an invalid
configuration where blocking mode is enabled but the evidence stream
is disabled (which would cause all seal issuances to fail at runtime).
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from src.compliance_bridge import evidence_stream


class TestValidateEvidenceStreamPreconditions:
    """Test suite for validate_evidence_stream_preconditions() startup check."""

    def test_validation_passes_when_both_disabled(self) -> None:
        """When both flags are disabled, validation should pass (default state)."""
        with mock.patch.dict(
            os.environ,
            {
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
            },
            clear=False,
        ):
            # Should not raise
            evidence_stream.validate_evidence_stream_preconditions()

    def test_validation_passes_when_both_enabled(self) -> None:
        """When both flags are enabled, validation should pass (valid blocking config)."""
        with mock.patch.dict(
            os.environ,
            {
                "EVIDENCE_CHAIN_BLOCKING": "true",
                "EVIDENCE_STREAM_ENABLED": "true",
            },
            clear=False,
        ):
            # Should not raise
            evidence_stream.validate_evidence_stream_preconditions()

    def test_validation_passes_when_blocking_false_stream_true(self) -> None:
        """When blocking=false and stream=true, validation should pass.

        This is a valid configuration: evidence stream is available but
        blocking mode is not enforced (fire-and-forget behavior preserved).
        """
        with mock.patch.dict(
            os.environ,
            {
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "true",
            },
            clear=False,
        ):
            # Should not raise
            evidence_stream.validate_evidence_stream_preconditions()

    def test_validation_raises_when_blocking_true_stream_false(self) -> None:
        """When blocking=true but stream=false, validation should raise ConfigurationError.

        This is an invalid configuration: blocking mode requires the evidence
        stream to be available, otherwise all seal issuances will fail.
        """
        with mock.patch.dict(
            os.environ,
            {
                "EVIDENCE_CHAIN_BLOCKING": "true",
                "EVIDENCE_STREAM_ENABLED": "false",
            },
            clear=False,
        ):
            with pytest.raises(evidence_stream.ConfigurationError) as exc_info:
                evidence_stream.validate_evidence_stream_preconditions()

            error_msg = str(exc_info.value)
            # Verify error message contains both env var values
            assert "EVIDENCE_CHAIN_BLOCKING=true" in error_msg or "EVIDENCE_CHAIN_BLOCKING=True" in error_msg
            assert "EVIDENCE_STREAM_ENABLED" in error_msg
            # Verify error message explains the fix
            assert "enable the evidence stream" in error_msg.lower() or "disable blocking mode" in error_msg.lower()

    def test_validation_raises_with_clear_error_message(self) -> None:
        """Error message should clearly explain the invalid configuration and fix."""
        with mock.patch.dict(
            os.environ,
            {
                "EVIDENCE_CHAIN_BLOCKING": "true",
                "EVIDENCE_STREAM_ENABLED": "false",
            },
            clear=False,
        ):
            with pytest.raises(evidence_stream.ConfigurationError) as exc_info:
                evidence_stream.validate_evidence_stream_preconditions()

            error_msg = str(exc_info.value)
            # Should mention the required fix
            assert "EVIDENCE_STREAM_ENABLED=true" in error_msg or "enable the evidence stream" in error_msg.lower()

    def test_validation_handles_missing_env_vars(self) -> None:
        """When env vars are not set, defaults to false for both (passes)."""
        # Remove env vars if they exist
        env_copy = {
            k: v for k, v in os.environ.items()
            if k not in ("EVIDENCE_CHAIN_BLOCKING", "EVIDENCE_STREAM_ENABLED")
        }
        with mock.patch.dict(os.environ, env_copy, clear=True):
            # Should not raise - defaults to false for both
            evidence_stream.validate_evidence_stream_preconditions()

    def test_validation_handles_case_insensitive_true(self) -> None:
        """Validation should handle various capitalizations of 'true'."""
        test_cases = [
            ("TRUE", "TRUE"),
            ("True", "True"),
            ("TrUe", "TrUe"),
        ]
        for blocking_val, stream_val in test_cases:
            with mock.patch.dict(
                os.environ,
                {
                    "EVIDENCE_CHAIN_BLOCKING": blocking_val,
                    "EVIDENCE_STREAM_ENABLED": stream_val,
                },
                clear=False,
            ):
                # Should not raise - both enabled
                evidence_stream.validate_evidence_stream_preconditions()

    def test_validation_invalid_config_with_various_case(self) -> None:
        """Invalid config should be detected regardless of case."""
        test_cases = [
            ("TRUE", "FALSE"),
            ("True", "False"),
            ("true", "FALSE"),
        ]
        for blocking_val, stream_val in test_cases:
            with mock.patch.dict(
                os.environ,
                {
                    "EVIDENCE_CHAIN_BLOCKING": blocking_val,
                    "EVIDENCE_STREAM_ENABLED": stream_val,
                },
                clear=False,
            ):
                with pytest.raises(evidence_stream.ConfigurationError):
                    evidence_stream.validate_evidence_stream_preconditions()


class TestConfigurationErrorException:
    """Test the ConfigurationError exception class."""

    def test_configuration_error_is_exception(self) -> None:
        """ConfigurationError should be a subclass of Exception."""
        assert issubclass(evidence_stream.ConfigurationError, Exception)

    def test_configuration_error_can_be_raised(self) -> None:
        """ConfigurationError should be raisable with a message."""
        with pytest.raises(evidence_stream.ConfigurationError) as exc_info:
            raise evidence_stream.ConfigurationError("Test error message")
        assert "Test error message" in str(exc_info.value)

    def test_configuration_error_distinct_from_evidence_chain_error(self) -> None:
        """ConfigurationError should be distinct from EvidenceChainUnavailableError."""
        from src.compliance_bridge.evidence_stream import EvidenceChainUnavailableError

        assert evidence_stream.ConfigurationError is not EvidenceChainUnavailableError
        assert not issubclass(evidence_stream.ConfigurationError, EvidenceChainUnavailableError)
        assert not issubclass(EvidenceChainUnavailableError, evidence_stream.ConfigurationError)

