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

"""Narrower for trade amounts that exceed configured domain thresholds."""

from collections.abc import Callable
import math
from typing import Any

from src.gateway.governance.contracts import NarrowingResult, Violation
from src.gateway.governance.schemas.thresholds import THRESHOLDS


def _default_limit_resolver() -> float:
    return float(THRESHOLDS.consensus.threshold_usd)


class AmountNarrower:
    """Narrows trade amounts that exceed the configured domain threshold.

    Uses structured violation classification (`violation.narrowable`) and an
    explicit numeric `limit_resolver` (defaulting to
    `THRESHOLDS.consensus.threshold_usd`) rather than parsing free-text
    violation messages.
    """

    def __init__(
        self,
        limit_resolver: Callable[[], float] | float = _default_limit_resolver,
    ) -> None:
        self._limit_resolver = limit_resolver

    def _resolve_limit(self) -> float | None:
        try:
            raw = (
                self._limit_resolver()
                if callable(self._limit_resolver)
                else float(self._limit_resolver)
            )
            limit = float(raw)
        except (TypeError, ValueError):
            return None
        if math.isnan(limit) or math.isinf(limit) or limit <= 0:
            return None
        return limit

    @staticmethod
    def _extract_amount(params: dict[str, Any]) -> float | None:
        if "amount" not in params:
            return None
        raw = params.get("amount")
        if raw is None or isinstance(raw, bool):
            return None
        try:
            amount = float(raw)
        except (TypeError, ValueError):
            return None
        if math.isnan(amount) or math.isinf(amount):
            return None
        return amount

    def can_narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> bool:
        """Return True iff violation is narrowable and amount exceeds resolved limit."""
        if not violation.narrowable:
            return False
        limit = self._resolve_limit()
        if limit is None:
            return False
        amount = self._extract_amount(params)
        if amount is None:
            return False
        return amount > limit

    def narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> NarrowingResult | None:
        """Clamp ``params["amount"]`` to 99% of the resolved limit, or return ``None``."""
        if not self.can_narrow(violation, action, params):
            return None
        limit = self._resolve_limit()
        amount = self._extract_amount(params)
        if limit is None or amount is None:
            return None

        narrowed_amount = round(limit * 0.99, 2)
        narrowed_params = {**params, "amount": narrowed_amount}
        return NarrowingResult(
            can_narrow=True,
            narrowed_params=narrowed_params,
            constraints_applied=[f"amount <= {narrowed_amount}"],
            narrowing_reason=(
                f"Clamped amount from {amount} to {narrowed_amount} (99% of {limit})"
            ),
        )
