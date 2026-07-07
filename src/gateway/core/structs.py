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
Core Structures for the Gateway Service.
"""

import re
import uuid

from pydantic import BaseModel, Field, field_validator


class TradeOrder(BaseModel):
    """
    Schema for financial trading actions.
    This schema is used for both proposed trades (Agent) and executed trades (Gateway).
    It enforces strict validation rules for symbol, amount, and confidence.
    """

    # User-provided fields
    symbol: str = Field(..., description="Ticker symbol of the asset")
    amount: float = Field(..., description="Amount to trade")
    currency: str = Field(..., description="Currency code (e.g. USD, EUR)")
    confidence: float = Field(
        ...,
        description="Confidence score (0.0-1.0) of the agent proposing the trade. MUST be >= 0.95 for execution.",
    )

    # Optional order type fields (used by optimistic execution path)
    side: str | None = Field(default=None, description="Order side: 'buy' or 'sell'")
    type: str | None = Field(
        default=None, description="Order type: 'market', 'limit', etc."
    )

    # System-generated fields with defaults
    transaction_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique UUID for the transaction",
    )
    # trader_id and trader_role are optional to allow unit test construction without
    # a full agent identity context; production execution requires these to be populated
    # before the order is submitted to the broker.
    trader_id: str | None = Field(
        default=None, description="Unique identifier for the trading agent"
    )
    trader_role: str | None = Field(
        default=None, description="Role of the trading agent"
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v):
        if not (0.0 <= v <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        return v

    @field_validator("amount")
    @classmethod
    def validate_positive(cls, v):
        if v <= 0:
            raise ValueError("Amount must be positive")
        return v

    @field_validator("transaction_id")
    @classmethod
    def validate_uuid(cls, v):
        # Regex for UUID v4
        uuid_regex = (
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        if not re.match(uuid_regex, v.lower()):
            raise ValueError("Invalid transaction_id format. Must be a valid UUID v4.")
        return v

    @field_validator("symbol")
    @classmethod
    def validate_symbol(cls, v):
        # Normalize to uppercase first
        v = v.upper()
        # Regex for Ticker Symbol (1-5 Uppercase letters)
        if not re.match(r"^[A-Z]{1,5}$", v):
            raise ValueError("Invalid symbol format. Must be 1-5 letters.")
        return v

    @field_validator("trader_role")
    @classmethod
    def validate_role(cls, v):
        if v is None:
            return v
        if v.lower() not in ["junior", "senior"]:
            raise ValueError("Invalid role. Must be 'junior' or 'senior'.")
        return v.lower()
