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

"""Data models for the bounding contract subsystem.

Phase 5 Master Plan: Core data structures for server-side bounding contracts
that enable EXTERNALLY_REVERSIBLE classification for execute_trade_bounded.
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContractSeverity(str, Enum):
    """Severity classification for bounding contract violations."""

    HARD_BLOCK = "HARD_BLOCK"
    HITL_ESCALATE = "HITL_ESCALATE"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    ADVISORY = "ADVISORY"


@dataclass(frozen=True)
class ContractResult:
    """Result of a single bounding contract evaluation."""

    contract_id: str = field(metadata={"description": "Contract identifier (B1-B10)"})
    admitted: bool = field(
        metadata={
            "description": "True if contract passed, False if failed or provider unavailable"
        }
    )
    severity: ContractSeverity = field(
        metadata={"description": "Escalation severity if admitted=False"}
    )
    findings: list[dict[str, Any]] = field(
        default_factory=list,
        metadata={
            "description": "Structured diagnostic information for audit trail and human review"
        },
    )
    code: str | None = field(
        default=None,
        metadata={
            "description": (
                "Violation code for a refusal; None means the tier derives "
                "BOUNDING_<contract_id>_<severity>"
            )
        },
    )

    def __post_init__(self) -> None:
        """Validate contract result invariants."""
        if not isinstance(self.admitted, bool):
            raise TypeError(f"admitted must be bool, got {type(self.admitted)}")
        if not isinstance(self.severity, ContractSeverity):
            raise TypeError(
                f"severity must be ContractSeverity, got {type(self.severity)}"
            )
        if not isinstance(self.findings, list):
            raise TypeError(f"findings must be list, got {type(self.findings)}")
        if self.severity == ContractSeverity.ADVISORY and not self.admitted:
            raise ValueError(
                f"Contract {self.contract_id}: ADVISORY severity must not block "
                f"(admitted must be True). Use HITL_ESCALATE or HARD_BLOCK instead."
            )


@dataclass(frozen=True)
class BoundedTradeRequest:
    """Input parameters for execute_trade_bounded bounding contract evaluation."""

    symbol: str = field(metadata={"description": "Ticker symbol (e.g., 'AAPL', 'BTC')"})
    amount: float = field(
        metadata={
            "description": "Trade notional value in USD (must be finite and strictly positive)"
        }
    )
    side: str = field(metadata={"description": "Trade direction: 'buy' or 'sell'"})
    venue: str = field(
        metadata={"description": "Execution venue (e.g., 'NYSE', 'NASDAQ', 'COINBASE')"}
    )
    counterparty: str | None = field(
        default=None,
        metadata={
            "description": "Counterparty identifier for OTC trades (optional for exchange trades)"
        },
    )
    trader_role: str = field(
        default="autonomous",
        metadata={"description": "Trader role for audit trail (default: 'autonomous')"},
    )
    jurisdiction: str | None = field(
        default=None,
        metadata={
            "description": "Regulatory jurisdiction for B9 filter (e.g., 'US', 'EU', 'APAC')"
        },
    )
    rollback_window_seconds: int = field(
        default=300,
        metadata={
            "description": "Maximum rollback window in seconds (B10 validation, default: 5 minutes)"
        },
    )
    transaction_id: str | None = field(
        default=None,
        metadata={
            "description": "Unique transaction UUID for idempotency and audit trail"
        },
    )

    def __post_init__(self) -> None:
        """Validate bounded trade request invariants."""
        if not isinstance(self.symbol, str) or not self.symbol.strip():
            raise ValueError("symbol must not be empty")

        if not isinstance(self.venue, str) or not self.venue.strip():
            raise ValueError("venue must not be empty")

        if isinstance(self.amount, bool) or not isinstance(self.amount, (int, float)):
            raise ValueError(
                f"amount must be a finite positive number (not bool), got {self.amount!r} "
                f"(symbol={self.symbol})"
            )

        if not math.isfinite(self.amount):
            raise ValueError(
                f"amount must be finite, got {self.amount!r} (symbol={self.symbol})"
            )

        if self.amount <= 0.0:
            raise ValueError(
                f"amount must be positive (> 0), got {self.amount} (symbol={self.symbol})"
            )

        if self.side not in ("buy", "sell"):
            raise ValueError(
                f"side must be 'buy' or 'sell', got {self.side!r} (symbol={self.symbol})"
            )

        if (
            isinstance(self.rollback_window_seconds, bool)
            or not isinstance(self.rollback_window_seconds, (int, float))
            or not math.isfinite(self.rollback_window_seconds)
            or self.rollback_window_seconds < 0
        ):
            raise ValueError(
                f"rollback_window_seconds must be non-negative (not bool), got {self.rollback_window_seconds!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for logging and audit trail."""
        return {
            "symbol": self.symbol,
            "amount": self.amount,
            "side": self.side,
            "venue": self.venue,
            "counterparty": self.counterparty,
            "trader_role": self.trader_role,
            "jurisdiction": self.jurisdiction,
            "rollback_window_seconds": self.rollback_window_seconds,
            "transaction_id": self.transaction_id,
        }
