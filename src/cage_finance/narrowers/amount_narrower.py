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

"""Narrower for trade amounts that exceed soft thresholds."""

import re
from typing import Any

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.narrower import NarrowingResult


class AmountNarrower:
    """Narrows trade amounts that exceed soft thresholds.
    
    This narrower handles NARROWABLE violations where a trade amount exceeds
    a soft threshold. It clamps the amount to the maximum allowed value while
    preserving all other action parameters.
    
    Example:
        violation.message = "Amount $50000 exceeds soft limit of $25000"
        params = {"amount": 50000, "symbol": "AAPL", "side": "buy"}
        -> narrowed_params = {"amount": 25000, "symbol": "AAPL", "side": "buy"}
    """
    
    def can_narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> bool:
        """Return True if this violation can be narrowed.
        
        Checks:
        1. Violation kind is NARROWABLE
        2. Action params contain an "amount" field
        3. Violation message contains "exceeds" (soft limit pattern)
        
        Args:
            violation: The violation to potentially narrow
            action: Action name (e.g., "execute_trade")
            params: Original action parameters
            
        Returns:
            True if this narrower can handle the violation
        """
        return (
            violation.kind == ViolationKind.NARROWABLE
            and "amount" in params
            and "exceeds" in violation.message.lower()
        )
    
    def narrow(
        self,
        violation: Violation,
        action: str,
        params: dict[str, Any],
    ) -> NarrowingResult:
        """Compute narrowed parameters by clamping amount to max_allowed.
        
        Extracts the maximum allowed amount from the violation message and
        clamps the requested amount to that threshold. Preserves all other
        parameters unchanged.
        
        Args:
            violation: The NARROWABLE violation
            action: Action name
            params: Original action parameters
            
        Returns:
            NarrowingResult with clamped amount and constraint description
            
        Raises:
            ValueError: If max_allowed cannot be extracted from violation message
        """
        # Extract max_allowed from violation message
        # Expected pattern: "Amount $X exceeds soft limit of $Y"
        # or: "Amount X exceeds soft limit of Y"
        max_allowed = self._extract_max_allowed(violation.message)
        
        if max_allowed is None:
            return NarrowingResult(
                can_narrow=False,
                narrowed_params=params,
                constraints_applied=[],
                narrowing_reason=f"Could not extract max_allowed from message: {violation.message}",
            )
        
        # Clamp amount to max_allowed
        original_amount = params["amount"]
        clamped_amount = min(original_amount, max_allowed)
        
        # Build narrowed params (shallow copy with clamped amount)
        narrowed_params = {**params, "amount": clamped_amount}
        
        return NarrowingResult(
            can_narrow=True,
            narrowed_params=narrowed_params,
            constraints_applied=[f"amount <= {max_allowed}"],
            narrowing_reason=f"Clamped amount from {original_amount} to {clamped_amount} (max: {max_allowed})",
        )
    
    def _extract_max_allowed(self, message: str) -> float | None:
        """Extract maximum allowed amount from violation message.
        
        Supports patterns:
        - "exceeds soft limit of $25000"
        - "exceeds soft limit of 25000"
        - "exceeds limit of $25000.50"
        
        Args:
            message: Violation message containing threshold
            
        Returns:
            Maximum allowed amount, or None if not found
        """
        # Pattern: "exceeds ... limit of $?NUMBER"
        # Matches both integer and decimal amounts with optional $ prefix
        pattern = r'exceeds\s+(?:soft\s+)?limit\s+of\s+\$?([0-9]+(?:\.[0-9]+)?)'
        
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                return None
        
        return None
