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
Unit tests for environment-driven adapter loading (AttestationAggregator, ActuatorRegistry).

Tests the env-driven factory methods:
- AttestationAggregator.from_env()
- load_actuators_from_env()
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.governance.attestation_aggregator import AttestationAggregator
from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.execution_actuator import (
    ActuatorRegistry,
    ExecutionActuator,
    load_actuators_from_env,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# =============================================================================
# AttestationAggregator.from_env() Tests
# =============================================================================


def test_attestation_aggregator_from_env_default_empty(monkeypatch):
    """With CAGE_ATTESTATION_PROVIDERS unset, assert aggregator.provider_count == 0."""
    monkeypatch.delenv("CAGE_ATTESTATION_PROVIDERS", raising=False)

    aggregator = AttestationAggregator.from_env()

    assert aggregator.provider_count == 0


def test_attestation_aggregator_from_env_unknown_provider(monkeypatch):
    """With CAGE_ATTESTATION_PROVIDERS='invalid_provider', assert raises ValueError."""
    monkeypatch.setenv("CAGE_ATTESTATION_PROVIDERS", "invalid_provider")

    with pytest.raises(ValueError, match="Unknown attestation provider"):
        AttestationAggregator.from_env()


def test_attestation_aggregator_from_env_success(monkeypatch):
    """
    Patch _load_attestation_provider to return MagicMock(spec=AttestationProvider).
    Set CAGE_ATTESTATION_PROVIDERS='provider_02, provider_05'.
    Assert aggregator.provider_count == 2.
    """
    monkeypatch.setenv("CAGE_ATTESTATION_PROVIDERS", "provider_02, provider_05")

    # Create mock provider instances
    mock_provider_02 = MagicMock(spec=AttestationProvider)
    mock_provider_02.provider_name = "provider_02"

    mock_provider_05 = MagicMock(spec=AttestationProvider)
    mock_provider_05.provider_name = "provider_05"

    # Patch _load_attestation_provider to return appropriate mocks
    def mock_loader(name: str) -> AttestationProvider:
        normalized = name.strip().lower()
        if normalized in ("provider_02", "p02"):
            return mock_provider_02
        elif normalized in ("provider_05", "p05"):
            return mock_provider_05
        else:
            raise ValueError(f"Unknown attestation provider: '{name}'")

    with patch(
        "src.gateway.governance.attestation_aggregator._load_attestation_provider",
        side_effect=mock_loader,
    ):
        aggregator = AttestationAggregator.from_env()

    assert aggregator.provider_count == 2


# =============================================================================
# load_actuators_from_env() Tests
# =============================================================================


def test_load_actuators_from_env_default_empty(monkeypatch):
    """With CAGE_ACTIVE_ACTUATORS unset, assert returns ActuatorRegistry without raising."""
    monkeypatch.delenv("CAGE_ACTIVE_ACTUATORS", raising=False)

    # Create fresh registry to avoid singleton pollution
    registry = ActuatorRegistry()
    result = load_actuators_from_env(registry=registry)

    # Should return the registry without raising
    assert isinstance(result, ActuatorRegistry)
    assert len(result.list_actuators()) == 0


def test_load_actuators_from_env_unknown_actuator(monkeypatch):
    """With CAGE_ACTIVE_ACTUATORS='invalid_actuator', assert raises ValueError."""
    monkeypatch.setenv("CAGE_ACTIVE_ACTUATORS", "invalid_actuator")

    registry = ActuatorRegistry()

    with pytest.raises(ValueError, match="Unknown execution actuator"):
        load_actuators_from_env(registry=registry)


def test_load_actuators_from_env_success(monkeypatch):
    """
    Patch _load_actuator to return mock ExecutionActuator with claim 'execute_mock'.
    Set CAGE_ACTIVE_ACTUATORS='actuator_01'.
    Assert actuator is registered and callable in registry.
    """
    monkeypatch.setenv("CAGE_ACTIVE_ACTUATORS", "actuator_01")

    # Create mock actuator
    mock_actuator = MagicMock(spec=ExecutionActuator)
    mock_actuator.actuator_id = "actuator_01"

    def mock_loader(name: str) -> ExecutionActuator:
        normalized = name.strip().lower()
        if normalized in ("actuator_01", "a01", "archytan"):
            return mock_actuator
        else:
            raise ValueError(f"Unknown execution actuator: '{name}'")

    with patch(
        "src.gateway.governance.execution_actuator._load_actuator",
        side_effect=mock_loader,
    ):
        registry = ActuatorRegistry()
        result = load_actuators_from_env(registry=registry)

    # Verify actuator was registered
    assert len(result.list_actuators()) == 1
    assert "actuator_01" in result.list_actuators()

    # Verify actuator is retrievable by action claim
    retrieved = result.get_actuator("execute_mock")
    assert retrieved is mock_actuator
