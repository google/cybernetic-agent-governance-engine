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

from dataclasses import dataclass
from typing import Any, Protocol

from src.gateway.governance.contracts import Violation


@dataclass(frozen=True)
class NarrowingResult:
    """Result of a narrower evaluation."""
    can_narrow: bool
    narrowed_params: dict[str, Any]
    constraints_applied: list[str]
    narrowing_reason: str

class Narrower(Protocol):
    """Protocol for parameter narrowing plugins.
    
    A Narrower evaluates whether a violation can be resolved by
    clamping/restricting parameters while preserving action semantics.
    """
    
    def can_narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> bool:
        """Return True if this narrower can handle the violation."""
        ...
    
    def narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> NarrowingResult:
        """Compute narrowed parameters that resolve the violation."""
        ...

class NarrowerRegistry:
    """Registry for narrower plugins."""
    
    def __init__(self, narrowers: list[Narrower] = []):
        self._narrowers = list(narrowers)
    
    def register(self, narrower: Narrower) -> None:
        """Register a narrower plugin."""
        self._narrowers.append(narrower)
    
    def find_narrower(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> Narrower | None:
        """Find first narrower that can handle this violation."""
        for narrower in self._narrowers:
            if narrower.can_narrow(violation, action, params):
                return narrower
        return None
