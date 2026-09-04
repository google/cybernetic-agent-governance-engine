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

from src.gateway.governance.causal import gatekeeper
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


def causal_safety_check(params: dict[str, Any]) -> bool:
    """Forwarding wrapper for causal safety check, supporting both module-level and gatekeeper patching."""
    return gatekeeper.causal_safety_check(params)


class CausalTierPlugin(GovernanceTierPlugin):
    """Causal guard tier (phase 1, order 6)."""

    @property
    def tier_name(self) -> str:
        return "causal"

    @property
    def phase(self) -> int:
        return 1

    @property
    def order(self) -> int:
        return 6

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "execute_trade"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Calling the module-level causal_safety_check function allows patching at either
        # src.cage_finance.tiers.causal_tier.causal_safety_check or
        # src.gateway.governance.causal.gatekeeper.causal_safety_check.
        is_safe = causal_safety_check(params)
        if not is_safe:
            return [
                Violation(
                    tier=self.tier_name,
                    code="CAUSAL_CHECK_FAILED",
                    message="World-model is untrustworthy or predicted risk exceeds safety boundary (DoWhy refutation failed).",
                    recoverable=False,
                )
            ]
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        pass
