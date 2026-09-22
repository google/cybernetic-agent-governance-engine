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
ExecutionActuator protocol and supporting types for downstream execution boundary.

CAGE is the ISSUER, not the consumer. This is a fundamentally different trust
boundary from the upstream NormativeProvider/AttestationProvider seams.

BREAKING CHANGE (C0): ExecutionActuator, ExecutionClearance, ActuationReceipt,
and ActuatorCapability have been moved to src.gateway.governance.seams.actuation
to eliminate circular dependencies with vendor adapters. This module now
re-exports them for backward compatibility, but the re-export will be removed
in the same PR per the C0 specification.
"""

from __future__ import annotations

import logging
import os

# Re-export seam contracts for backward compatibility during transition.
# New code should import directly from seams.actuation.
from src.gateway.governance.seams.actuation import (
    ActuationReceipt,
    ActuatorCapability,
    ExecutionActuator,
    ExecutionClearance,
)

logger = logging.getLogger("Gateway.Governance.ExecutionActuator")

__all__ = [
    "ActuationReceipt",
    "ActuatorCapability",
    "ActuatorRegistry",
    "ExecutionActuator",
    "ExecutionClearance",
    "get_actuator_registry",
    "load_actuators_from_env",
]


def _load_actuator(name: str) -> ExecutionActuator:
    """Lazy-load execution actuator by name.

    Args:
        name: Actuator name (actuator_01, a01, archytan).

    Returns:
        Instantiated ExecutionActuator.

    Raises:
        ValueError: Unknown actuator name.
        Exception: Actuator.from_env() configuration errors propagate.
    """
    normalized = name.strip().lower()

    if normalized in ("actuator_01", "a01", "archytan"):
        from src.integrations.actuator_01.adapter import Actuator01Adapter

        return Actuator01Adapter.from_env()

    raise ValueError(f"Unknown execution actuator: '{name}'. Supported: actuator_01")


class ActuatorRegistry:
    """
    Registry of ExecutionActuator instances.

    Unlike NormativeProvider's singleton, this supports N registered actuators
    dispatched by claim (which actions each actuator handles).

    The registry shape is fixed now so a second actuator does not force a refactor.
    """

    def __init__(self) -> None:
        self._actuators: dict[str, ExecutionActuator] = {}
        self._claims: dict[str, set[str]] = {}  # actuator_id -> set of action patterns

    def register(
        self,
        actuator: ExecutionActuator,
        claims: set[str] | None = None,
    ) -> None:
        """
        Register an actuator.

        Args:
            actuator: The ExecutionActuator instance
            claims: Set of action patterns this actuator handles (e.g., {"trade.*", "transfer.*"})
                   If None, the actuator handles all actions (default for the first actuator)
        """
        actuator_id = actuator.actuator_id
        if actuator_id in self._actuators:
            raise ValueError(f"Actuator {actuator_id} already registered")

        if not isinstance(actuator, ExecutionActuator):
            raise TypeError(
                f"Actuator must implement ExecutionActuator protocol, got {type(actuator)}"
            )

        self._actuators[actuator_id] = actuator
        self._claims[actuator_id] = claims if claims is not None else {"*"}

    def get_actuator(self, action: str) -> ExecutionActuator | None:
        """
        Retrieve the actuator that handles the given action.

        Returns the first matching actuator, or None if no actuator claims it.
        """
        for actuator_id, patterns in self._claims.items():
            if "*" in patterns:
                return self._actuators[actuator_id]
            # Simple prefix matching for now
            for pattern in patterns:
                if pattern.endswith("*") and action.startswith(pattern[:-1]):
                    return self._actuators[actuator_id]
                elif action == pattern:
                    return self._actuators[actuator_id]
        return None

    def list_actuators(self) -> list[str]:
        """Return list of registered actuator IDs."""
        return list(self._actuators.keys())


# ── Thread-safe singleton accessor ──

_actuator_registry_singleton: ActuatorRegistry | None = None


def get_actuator_registry() -> ActuatorRegistry:
    """
    Retrieve the global ActuatorRegistry singleton.

    Thread-safe singleton accessor for the ActuatorRegistry.
    Creates the registry on first access.

    Returns:
        The global ActuatorRegistry instance.
    """
    global _actuator_registry_singleton
    if _actuator_registry_singleton is None:
        _actuator_registry_singleton = ActuatorRegistry()
    return _actuator_registry_singleton


def load_actuators_from_env(
    registry: ActuatorRegistry | None = None,
) -> ActuatorRegistry:
    """Load actuators from CAGE_ACTIVE_ACTUATORS environment variable.

    Reads:
        CAGE_ACTIVE_ACTUATORS: Comma-separated list of actuator names
            (e.g., "actuator_01,archytan"). Empty or unset -> no-op.

    Args:
        registry: Target registry (defaults to global singleton).

    Returns:
        The registry (for chaining).

    Raises:
        ValueError: Unknown actuator name or duplicate registration.
        Exception: Actuator configuration errors propagate (fail-closed).
    """
    if registry is None:
        registry = get_actuator_registry()

    actuator_names_raw = os.getenv("CAGE_ACTIVE_ACTUATORS", "").strip()

    # Hermetic default: return registry unmodified
    if not actuator_names_raw:
        logger.info("CAGE_ACTIVE_ACTUATORS unset or empty; no actuators loaded")
        return registry

    # Split on comma, strip whitespace, ignore empty tokens
    actuator_names = [
        name.strip() for name in actuator_names_raw.split(",") if name.strip()
    ]

    # Lazy-load and register each actuator
    loaded_ids: list[str] = []
    for name in actuator_names:
        actuator = _load_actuator(name)
        registry.register(actuator)
        loaded_ids.append(actuator.actuator_id)

    logger.info(
        "Loaded %d execution actuator(s): %s",
        len(loaded_ids),
        ", ".join(loaded_ids),
    )

    return registry
