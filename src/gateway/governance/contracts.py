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
Governance Contracts (Protocols).
This module defines the interfaces that the Gateway expects for governance components,
decoupling the Gateway from the specific application implementations.
"""

from typing import Any, Dict, Protocol

class SafetyFilter(Protocol):
    """
    Protocol for a Control Barrier Function or similar safety filter.
    Enforces hard constraints on actions (e.g. bankruptcy prevention).
    """
    def verify_action(self, action_name: str, payload: Dict[str, Any]) -> str:
        """
        Verifies if the action is safe.
        Returns "SAFE" or an error message starting with "UNSAFE".
        """
        ...

    def update_state(self, cost: float) -> None:
        """
        Updates the safety state (e.g. deducts cash).
        """
        ...

    def rollback_state(self, cost: float) -> None:
        """
        Rolls back the safety state (e.g. restores cash) after a failure.
        """
        ...

class ConsensusProvider(Protocol):
    """
    Protocol for a Multi-Agent Consensus Engine.
    Enforces ISO 42001 Human Oversight and Adaptive Compute requirements.
    """
    async def check_consensus(self, action: str, amount: float, symbol: str) -> Dict[str, Any]:
        """
        Checks if the action requires consensus and performs it.
        Returns a dict with "status" (APPROVE, REJECT, ESCALATE) and "reason".
        """
        ...
