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

# Re-export seam contracts for backward compatibility during transition.
# New code should import directly from seams.actuation.
from src.gateway.governance.seams.actuation import (
    ActuationReceipt,
    ActuatorCapability,
    ExecutionActuator,
    ExecutionClearance,
)

__all__ = [
    "ActuationReceipt",
    "ActuatorCapability",
    "ActuatorRegistry",
    "ExecutionActuator",
    "ExecutionClearance",
]


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
