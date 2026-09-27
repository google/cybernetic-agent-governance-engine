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

from typing import Any

from src.gateway.governance.contracts import (
    Narrower,
    NarrowingResult,
    Violation,
)


class NarrowerRegistry:
    """Registry for narrower plugins."""

    def __init__(self, narrowers: list[Narrower] | None = None):
        self._narrowers = list(narrowers) if narrowers else []

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


__all__ = ["Narrower", "NarrowerRegistry", "NarrowingResult"]

