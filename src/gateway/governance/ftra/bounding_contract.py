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
FTRA Bounding Contract Configuration and Enforcement.

The bounding contract defines allowed instruments, venues, and counterparties
for financial transactions. This acts as a whitelist-based boundary control
for the Forward-Looking Trajectory Reachability Analyzer.

Security Note:
    Empty configuration (no whitelists populated) is rejected as a fail-safe
    measure to prevent accidental bypass of boundary controls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Set


@dataclass
class BoundingContractConfig:
    """
    Configuration for FTRA boundary controls.
    
    At least one of the whitelist fields must be non-empty to prevent
    accidental misconfiguration that would allow unrestricted trading.
    
    Attributes:
        allowed_instruments: Set of allowed instrument symbols (e.g., {"AAPL", "MSFT"})
        allowed_venues: Set of allowed trading venues (e.g., {"NYSE", "NASDAQ"})
        allowed_counterparties: Set of allowed counterparty identifiers
    """
    
    allowed_instruments: Set[str] = field(default_factory=set)
    allowed_venues: Set[str] = field(default_factory=set)
    allowed_counterparties: Set[str] = field(default_factory=set)


class BoundingContractEnforcer:
    """
    Enforces FTRA bounding contract boundary controls.
    
    Validates that configuration is non-empty (at least one whitelist populated)
    and provides enforcement primitives for checking actions against the contract.
    
    Raises:
        ValueError: If all whitelist fields in config are empty.
    """
    
    def __init__(self, config: BoundingContractConfig):
        """
        Initialize enforcer with bounding contract configuration.
        
        Args:
            config: Bounding contract configuration.
            
        Raises:
            ValueError: If config has all empty whitelists (fail-safe validation).
        """
        # Issue #3 fix: reject empty configuration
        if (
            not config.allowed_instruments
            and not config.allowed_venues
            and not config.allowed_counterparties
        ):
            raise ValueError(
                "BoundingContractConfig must specify at least one of: "
                "allowed_instruments, allowed_venues, or allowed_counterparties. "
                "Empty configuration is rejected as a fail-safe measure."
            )
        
        self.config = config
    
    def validate_instrument(self, instrument: str) -> bool:
        """
        Check if instrument is allowed.
        
        Args:
            instrument: Instrument symbol to validate.
            
        Returns:
            True if allowed (or no instrument whitelist configured), False otherwise.
        """
        if not self.config.allowed_instruments:
            return True  # No instrument restriction
        return instrument in self.config.allowed_instruments
    
    def validate_venue(self, venue: str) -> bool:
        """
        Check if venue is allowed.
        
        Args:
            venue: Venue identifier to validate.
            
        Returns:
            True if allowed (or no venue whitelist configured), False otherwise.
        """
        if not self.config.allowed_venues:
            return True  # No venue restriction
        return venue in self.config.allowed_venues
    
    def validate_counterparty(self, counterparty: str) -> bool:
        """
        Check if counterparty is allowed.
        
        Args:
            counterparty: Counterparty identifier to validate.
            
        Returns:
            True if allowed (or no counterparty whitelist configured), False otherwise.
        """
        if not self.config.allowed_counterparties:
            return True  # No counterparty restriction
        return counterparty in self.config.allowed_counterparties
