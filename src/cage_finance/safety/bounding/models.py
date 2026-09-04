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

Per Section 3.2 (Contract evaluation model):
- Each contract returns ContractResult(admitted, severity, findings)
- admitted=False triggers escalation based on severity
- findings contain structured diagnostic information

Per Section 3.3 (Severity model):
- HARD_BLOCK: Safety invariant violation → reject immediately
- HITL_ESCALATE: Policy threshold exceeded → defer queue
- ADVISORY: Informational warning → log only
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContractSeverity(str, Enum):
    """Severity classification for bounding contract violations.

    Per Phase 5 Master Plan Section 3.3:
    - HARD_BLOCK: Safety invariant violation (e.g., B1 max notional, B2 drawdown)
      → reject immediately with RefusalReceipt
    - HITL_ESCALATE: Policy threshold exceeded (e.g., B3 liquidity, B6 high-impact)
      → route to human review via DeferQueue
    - ADVISORY: Informational warning (e.g., approaching threshold)
      → log structured finding but allow execution

    Enforcement semantics:
    - Any contract returning admitted=False with HARD_BLOCK severity blocks execution
    - Any contract returning admitted=False with HITL_ESCALATE severity triggers
      defer queue routing (human review before execution)
    - ADVISORY severity never blocks, regardless of admitted field value
    """

    HARD_BLOCK = "HARD_BLOCK"
    HITL_ESCALATE = "HITL_ESCALATE"
    ADVISORY = "ADVISORY"


@dataclass(frozen=True)
class ContractResult:
    """Result of a single bounding contract evaluation.

    Per Phase 5 Master Plan Section 3.2:
    - admitted=True: Contract passed, execution may proceed
    - admitted=False: Contract failed, escalation based on severity
    - findings: Structured diagnostic information for audit trail

    Fail-closed semantics (Section 3.4):
    - Missing provider data → admitted=False, severity=HARD_BLOCK
    - Non-finite numerics (NaN/inf) → admitted=False, severity=HARD_BLOCK
    - Unknown contract IDs → admitted=False, severity=HARD_BLOCK
    """

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

    def __post_init__(self) -> None:
        """Validate contract result invariants."""
        if not isinstance(self.severity, ContractSeverity):
            raise TypeError(
                f"severity must be ContractSeverity, got {type(self.severity)}"
            )
        if not isinstance(self.findings, list):
            raise TypeError(f"findings must be list, got {type(self.findings)}")
        # Validate that ADVISORY severity never blocks
        if self.severity == ContractSeverity.ADVISORY and not self.admitted:
            # This is a developer error — ADVISORY contracts should always admit
            # or use a different severity level
            raise ValueError(
                f"Contract {self.contract_id}: ADVISORY severity must not block "
                f"(admitted must be True). Use HITL_ESCALATE or HARD_BLOCK instead."
            )


@dataclass(frozen=True)
class BoundedTradeRequest:
    """Input parameters for execute_trade_bounded bounding contract evaluation.

    Per Phase 5 Master Plan Section 5.1:
    - Extends TradeOrder model with rollback_window_seconds for B10 validation
    - All contracts (B1-B10) evaluate this unified request model
    - Immutable to prevent TOCTOU vulnerabilities between contract evaluations

    Fail-closed validation:
    - Non-finite amount → rejected before reaching contracts
    - Missing required fields → rejected before reaching contracts
    - Unknown venues/counterparties → rejected by B4/B9 contracts
    """

    symbol: str = field(metadata={"description": "Ticker symbol (e.g., 'AAPL', 'BTC')"})
    amount: float = field(
        metadata={
            "description": "Trade notional value in USD (must be finite, non-negative)"
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
        import math

        # Fail-closed: Missing/empty symbol or venue rejected immediately
        if not self.symbol or not self.symbol.strip():
            raise ValueError("symbol must not be empty")

        if not self.venue or not self.venue.strip():
            raise ValueError("venue must not be empty")

        # Fail-closed: Non-finite amounts rejected immediately
        if not math.isfinite(self.amount):
            raise ValueError(
                f"amount must be finite, got {self.amount!r} (symbol={self.symbol})"
            )

        # Fail-closed: Negative amounts rejected immediately
        if self.amount < 0:
            raise ValueError(
                f"amount must be non-negative, got {self.amount} (symbol={self.symbol})"
            )

        # Fail-closed: Invalid side rejected immediately
        if self.side not in ("buy", "sell"):
            raise ValueError(
                f"side must be 'buy' or 'sell', got {self.side!r} (symbol={self.symbol})"
            )

        # Fail-closed: Invalid rollback window rejected immediately
        if self.rollback_window_seconds < 0:
            raise ValueError(
                f"rollback_window_seconds must be non-negative, got {self.rollback_window_seconds}"
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
