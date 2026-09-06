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

B4 Enhancement: Extended validation with:
- Production non-blocking check (fails startup unless CAGE_ALLOW_NONBLOCKING_PROD=true)
- Stream disabled warning (logs warning when evidence stream is disabled)
- Prometheus metrics for configuration warnings
"""

from __future__ import annotations

import logging
import os
from unittest import mock

import pytest

from src.gateway.governance.evidence import stream as evidence_stream


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
            assert (
                "EVIDENCE_CHAIN_BLOCKING=true" in error_msg
                or "EVIDENCE_CHAIN_BLOCKING=True" in error_msg
            )
            assert "EVIDENCE_STREAM_ENABLED" in error_msg
            # Verify error message explains the fix
            assert (
                "enable the evidence stream" in error_msg.lower()
                or "disable blocking mode" in error_msg.lower()
            )

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
            assert (
                "EVIDENCE_STREAM_ENABLED=true" in error_msg
                or "enable the evidence stream" in error_msg.lower()
            )

    def test_validation_handles_missing_env_vars(self) -> None:
        """When env vars are not set, uses module defaults.

        Module defaults (as of B4 enhancement):
        - EVIDENCE_CHAIN_BLOCKING defaults to "true" (fail-closed safety)
        - EVIDENCE_STREAM_ENABLED defaults to "false"

        This is a contradictory config and should raise ConfigurationError,
        forcing operators to explicitly configure evidence stream settings.
        """
        # Remove env vars if they exist
        env_copy = {
            k: v
            for k, v in os.environ.items()
            if k not in ("EVIDENCE_CHAIN_BLOCKING", "EVIDENCE_STREAM_ENABLED")
        }
        with mock.patch.dict(os.environ, env_copy, clear=True):
            # Should raise - blocking=true (default) + stream=false (default) is contradictory
            with pytest.raises(evidence_stream.ConfigurationError) as exc_info:
                evidence_stream.validate_evidence_stream_preconditions()

            error_msg = str(exc_info.value)
            assert (
                "EVIDENCE_CHAIN_BLOCKING=true" in error_msg
                or "EVIDENCE_CHAIN_BLOCKING=True" in error_msg
            )
            assert "EVIDENCE_STREAM_ENABLED" in error_msg

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
        from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError

        assert evidence_stream.ConfigurationError is not EvidenceChainUnavailableError
        assert not issubclass(
            evidence_stream.ConfigurationError, EvidenceChainUnavailableError
        )
        assert not issubclass(
            EvidenceChainUnavailableError, evidence_stream.ConfigurationError
        )


class TestProductionNonBlockingCheck:
    """B4 Enhancement: Test production non-blocking configuration check.

    When CAGE_ENV=prod and EVIDENCE_CHAIN_BLOCKING=false, startup should fail
    unless CAGE_ALLOW_NONBLOCKING_PROD=true is set as an explicit override.
    """

    def test_prod_nonblocking_fails_without_override(self) -> None:
        """In production, non-blocking mode should fail startup by default."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "prod",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
                "CAGE_ALLOW_NONBLOCKING_PROD": "false",
            },
            clear=False,
        ):
            with pytest.raises(evidence_stream.ConfigurationError) as exc_info:
                evidence_stream.validate_evidence_stream_preconditions()

            error_msg = str(exc_info.value)
            assert "production" in error_msg.lower() or "prod" in error_msg.lower()
            assert "CAGE_ALLOW_NONBLOCKING_PROD" in error_msg

    def test_prod_nonblocking_succeeds_with_override(self) -> None:
        """In production, non-blocking mode succeeds with explicit override."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "prod",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
                "CAGE_ALLOW_NONBLOCKING_PROD": "true",
            },
            clear=False,
        ):
            # Should not raise - override acknowledged
            evidence_stream.validate_evidence_stream_preconditions()

    def test_prod_nonblocking_fails_without_explicit_override_env(self) -> None:
        """When CAGE_ALLOW_NONBLOCKING_PROD is not set, default to failing."""
        env_copy = {
            k: v for k, v in os.environ.items() if k != "CAGE_ALLOW_NONBLOCKING_PROD"
        }
        env_copy.update(
            {
                "CAGE_ENV": "prod",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
            }
        )
        with mock.patch.dict(os.environ, env_copy, clear=True):
            with pytest.raises(evidence_stream.ConfigurationError):
                evidence_stream.validate_evidence_stream_preconditions()

    def test_dev_nonblocking_does_not_fail(self) -> None:
        """In dev environment, non-blocking mode should not fail."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "dev",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
            },
            clear=False,
        ):
            # Should not raise - dev environment
            evidence_stream.validate_evidence_stream_preconditions()

    def test_staging_nonblocking_does_not_fail(self) -> None:
        """In staging environment, non-blocking mode should not fail."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "staging",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
            },
            clear=False,
        ):
            # Should not raise - staging environment
            evidence_stream.validate_evidence_stream_preconditions()

    def test_prod_blocking_enabled_does_not_fail(self) -> None:
        """In production with blocking enabled, should not fail (normal config)."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "prod",
                "EVIDENCE_CHAIN_BLOCKING": "true",
                "EVIDENCE_STREAM_ENABLED": "true",
            },
            clear=False,
        ):
            # Should not raise - blocking enabled with stream
            evidence_stream.validate_evidence_stream_preconditions()


class TestStreamDisabledWarning:
    """B4 Enhancement: Test stream disabled warning logging.

    When EVIDENCE_STREAM_ENABLED=false, a warning should be logged.
    """

    def test_stream_disabled_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When evidence stream is disabled, a warning should be logged."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "dev",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
            },
            clear=False,
        ):
            with caplog.at_level(logging.WARNING, logger="cage.evidence_stream"):
                evidence_stream.validate_evidence_stream_preconditions()

            # Check that warning was logged
            warning_msgs = [
                record.message
                for record in caplog.records
                if record.levelno == logging.WARNING
            ]
            assert any(
                "EVIDENCE_STREAM_ENABLED=false" in msg for msg in warning_msgs
            ), f"Expected warning about disabled stream, got: {warning_msgs}"

    def test_stream_enabled_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """When evidence stream is enabled, no disabled warning should appear."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "dev",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "true",
            },
            clear=False,
        ):
            with caplog.at_level(logging.WARNING, logger="cage.evidence_stream"):
                evidence_stream.validate_evidence_stream_preconditions()

            # Check that no stream-disabled warning was logged
            warning_msgs = [
                record.message
                for record in caplog.records
                if record.levelno == logging.WARNING
                and "EVIDENCE_STREAM_ENABLED=false" in record.message
            ]
            assert len(warning_msgs) == 0, f"Unexpected warning: {warning_msgs}"


class TestProductionNonBlockingLogging:
    """B4 Enhancement: Test production non-blocking critical logging."""

    def test_prod_nonblocking_logs_critical(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When production has blocking disabled, a CRITICAL log should be emitted."""
        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "prod",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
                "CAGE_ALLOW_NONBLOCKING_PROD": "true",
            },
            clear=False,
        ):
            with caplog.at_level(logging.CRITICAL, logger="cage.evidence_stream"):
                evidence_stream.validate_evidence_stream_preconditions()

            # Check that critical warning was logged
            critical_msgs = [
                record.message
                for record in caplog.records
                if record.levelno == logging.CRITICAL
            ]
            assert any(
                "EVIDENCE_CHAIN_BLOCKING=false" in msg and "production" in msg.lower()
                for msg in critical_msgs
            ), (
                f"Expected critical warning about non-blocking in prod, got: {critical_msgs}"
            )


class TestPrometheusMetricsEmission:
    """B4 Enhancement: Test Prometheus metrics are emitted for config warnings."""

    def test_blocking_disabled_metric_emitted_in_prod(self) -> None:
        """EVIDENCE_BLOCKING_DISABLED metric should be set when blocking disabled in prod."""
        # Skip if prometheus_client not available
        if not evidence_stream._PROM_AVAILABLE:
            pytest.skip("prometheus_client not installed")

        # Reset the metric before test
        from prometheus_client import REGISTRY

        # Get current metric value (may not exist)
        _initial_value = None
        try:
            for metric in REGISTRY.collect():
                if metric.name == "cage_evidence_blocking_disabled":
                    for sample in metric.samples:
                        if sample.labels.get("env") == "prod":
                            _initial_value = sample.value
        except Exception:
            pass

        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "prod",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
                "CAGE_ALLOW_NONBLOCKING_PROD": "true",
            },
            clear=False,
        ):
            evidence_stream.validate_evidence_stream_preconditions()

        # Check metric was set
        metric_value = None
        for metric in REGISTRY.collect():
            if metric.name == "cage_evidence_blocking_disabled":
                for sample in metric.samples:
                    if sample.labels.get("env") == "prod":
                        metric_value = sample.value
                        break

        assert metric_value == 1.0, f"Expected metric value 1.0, got {metric_value}"

    def test_stream_disabled_metric_emitted(self) -> None:
        """EVIDENCE_STREAM_DISABLED metric should be set when stream disabled."""
        # Skip if prometheus_client not available
        if not evidence_stream._PROM_AVAILABLE:
            pytest.skip("prometheus_client not installed")

        from prometheus_client import REGISTRY

        with mock.patch.dict(
            os.environ,
            {
                "CAGE_ENV": "dev",
                "EVIDENCE_CHAIN_BLOCKING": "false",
                "EVIDENCE_STREAM_ENABLED": "false",
            },
            clear=False,
        ):
            evidence_stream.validate_evidence_stream_preconditions()

        # Check metric was set
        metric_value = None
        for metric in REGISTRY.collect():
            if metric.name == "cage_evidence_stream_disabled":
                for sample in metric.samples:
                    if sample.labels.get("env") == "dev":
                        metric_value = sample.value
                        break

        assert metric_value == 1.0, f"Expected metric value 1.0, got {metric_value}"


pytestmark = [pytest.mark.unit, pytest.mark.local]
