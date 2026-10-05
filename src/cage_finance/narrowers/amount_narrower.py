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

"""Narrower for trade amounts that exceed what the refusing tier would admit."""

import math
from collections.abc import Callable
from typing import Any

from src.gateway.governance.contracts import NarrowingResult, Violation
from src.gateway.governance.schemas.thresholds import THRESHOLDS


def _default_limit_resolver() -> float:
    return float(THRESHOLDS.resolve("domains.finance.consensus.threshold_usd"))


class AmountNarrower:
    """Clamps ``params["amount"]`` to the limit a NARROWABLE refusal names.

    The limit is ``violation.bound`` when the refusing tier reported one
    (e.g. the fiscal tier's remaining daily headroom); the amount is clamped
    to exactly that bound, floored to the cent so it never rounds above it.
    A bound of 0 means nothing fits, so there is no proposal: the configured
    threshold is never consulted in its place.

    Only when the tier reported no bound does it fall back to the explicit
    numeric ``limit_resolver`` (default
    ``THRESHOLDS.resolve("domains.finance.consensus.threshold_usd")``),
    clamping to 99% of it. Free-text violation messages are never parsed.

    Either way the proposal is a candidate: the governor re-runs the
    pipeline on it before anything is sealed.
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

    def _clamp(self, violation: Violation) -> tuple[float, float, str] | None:
        """``(limit, clamp_to, source)`` for this violation, or ``None``.

        An amount above ``limit`` is narrowed to ``clamp_to``.
        """
        if violation.bound is not None:
            # round() first absorbs float noise (1234.57 * 100 == 123456.999...).
            clamp_to = math.floor(round(violation.bound * 100, 6)) / 100
            if clamp_to <= 0:
                return None
            return clamp_to, clamp_to, f"the {violation.tier} bound {violation.bound}"
        limit = self._resolve_limit()
        if limit is None:
            return None
        return limit, round(limit * 0.99, 2), f"99% of {limit}"

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
        """Return True iff the violation is narrowable and the amount exceeds its limit."""
        if not violation.narrowable:
            return False
        clamp = self._clamp(violation)
        amount = self._extract_amount(params)
        if clamp is None or amount is None:
            return False
        return amount > clamp[0]

    def narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> NarrowingResult | None:
        """Clamp ``params["amount"]`` to the violation's limit, or return ``None``."""
        if not self.can_narrow(violation, action, params):
            return None
        clamp = self._clamp(violation)
        amount = self._extract_amount(params)
        if clamp is None or amount is None:
            return None

        _, narrowed_amount, source = clamp
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={**params, "amount": narrowed_amount},
            constraints_applied=[f"amount <= {narrowed_amount}"],
            narrowing_reason=f"Clamped amount from {amount} to {narrowed_amount} ({source})",
        )
