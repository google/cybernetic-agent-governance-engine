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

"""Tests for bounding contracts B4 (counterparty concentration) and B9 (jurisdiction filter).

These contracts reuse BoundingContractEnforcer from gateway/governance/ftra layer.
Per Phase 5 Master Plan Section 4.5 (B4) and Section 4.10 (B9).
"""

import pytest

from src.cage_finance.safety.bounding.contracts import (
    contract_b4_counterparty_concentration,
    contract_b9_jurisdiction_filter,
)
from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractSeverity,
)
from src.gateway.governance.ftra.bounding_contract import (
    BoundingContractConfig,
    BoundingContractEnforcer,
)


# ───────────────────────────────────────────────────────────────────────────────
# B4 — Counterparty Risk Concentration Tests
# ───────────────────────────────────────────────────────────────────────────────


class TestContractB4CounterpartyConcentration:
    """Tests for contract_b4_counterparty_concentration() — HARD_BLOCK severity."""

    def test_b4_allowed_counterparty_admits(self):
        """B4 admits when counterparty is in allowed whitelist."""
        config = BoundingContractConfig(
            allowed_instruments=["AAPL", "GOOGL"],
            allowed_venues=["NYSE", "NASDAQ"],
            allowed_counterparties=["GOLDMAN_SACHS", "JP_MORGAN"],
        )
        enforcer = BoundingContractEnforcer(config)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            counterparty="GOLDMAN_SACHS",
            jurisdiction="US_FED",
            transaction_id="test-tx-b4-01",
        )

        result = contract_b4_counterparty_concentration(request, enforcer)

        assert result.admitted is True
        assert result.contract_id == "B4"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0

    def test_b4_disallowed_counterparty_rejects(self):
        """B4 rejects when counterparty is not in allowed whitelist."""
        config = BoundingContractConfig(
            allowed_instruments=["AAPL", "GOOGL"],
            allowed_venues=["NYSE", "NASDAQ"],
            allowed_counterparties=["GOLDMAN_SACHS", "JP_MORGAN"],
        )
        enforcer = BoundingContractEnforcer(config)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            counterparty="UNKNOWN_BROKER",  # Not in whitelist
            jurisdiction="US_FED",
            transaction_id="test-tx-b4-02",
        )

        result = contract_b4_counterparty_concentration(request, enforcer)

        assert result.admitted is False
        assert result.contract_id == "B4"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert result.findings[0]["reason"] == "Counterparty not in allowed whitelist"
        assert result.findings[0]["counterparty"] == "UNKNOWN_BROKER"
        assert result.findings[0]["symbol"] == "AAPL"

    def test_b4_no_counterparty_no_whitelist_admits(self):
        """B4 admits when no counterparty specified and no whitelist configured (exchange trade)."""
        config = BoundingContractConfig(
            allowed_instruments=["AAPL", "GOOGL"],
            allowed_venues=["NYSE", "NASDAQ"],
            allowed_counterparties=[],  # No counterparty whitelist
        )
        enforcer = BoundingContractEnforcer(config)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            counterparty=None,  # Exchange trade
            jurisdiction="US_FED",
            transaction_id="test-tx-b4-03",
        )

        result = contract_b4_counterparty_concentration(request, enforcer)

        assert result.admitted is True
        assert result.contract_id == "B4"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0

    def test_b4_no_counterparty_with_whitelist_rejects(self):
        """B4 rejects when no counterparty specified but whitelist is configured (OTC requirement)."""
        config = BoundingContractConfig(
            allowed_instruments=["AAPL", "GOOGL"],
            allowed_venues=["NYSE", "NASDAQ"],
            allowed_counterparties=["GOLDMAN_SACHS", "JP_MORGAN"],  # Whitelist active
        )
        enforcer = BoundingContractEnforcer(config)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="OTC_DESK",
            counterparty=None,  # Missing counterparty for OTC trade
            jurisdiction="US_FED",
            transaction_id="test-tx-b4-04",
        )

        result = contract_b4_counterparty_concentration(request, enforcer)

        assert result.admitted is False
        assert result.contract_id == "B4"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Counterparty whitelist configured but trade has no counterparty"
        )
        assert (
            result.findings[0]["note"]
            == "OTC trades must specify counterparty when whitelist is active"
        )

    def test_b4_empty_string_counterparty_treated_as_missing(self):
        """B4 rejects when counterparty is empty string and whitelist is configured."""
        config = BoundingContractConfig(
            allowed_instruments=["AAPL", "GOOGL"],
            allowed_venues=["NYSE", "NASDAQ"],
            allowed_counterparties=["GOLDMAN_SACHS"],
        )
        enforcer = BoundingContractEnforcer(config)

        # Empty string counterparty is not in whitelist
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            counterparty="",
            jurisdiction="US_FED",
            transaction_id="test-tx-b4-05",
        )

        result = contract_b4_counterparty_concentration(request, enforcer)

        # BoundingContractEnforcer will treat "" as not in whitelist
        assert result.admitted is False
        assert result.contract_id == "B4"
        assert result.severity == ContractSeverity.HARD_BLOCK


# ───────────────────────────────────────────────────────────────────────────────
# B9 — Regional Regulatory Jurisdiction Filter Tests
# ───────────────────────────────────────────────────────────────────────────────


class TestContractB9JurisdictionFilter:
    """Tests for contract_b9_jurisdiction_filter() — HARD_BLOCK severity."""

    def test_b9_allowed_venue_admits(self):
        """B9 admits when venue is in regional whitelist."""
        config = BoundingContractConfig(
            allowed_instruments=["AAPL", "GOOGL"],
            allowed_venues=["NYSE", "NASDAQ"],  # US venues
            allowed_counterparties=["GOLDMAN_SACHS"],
        )
        enforcer = BoundingContractEnforcer(config)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            counterparty="GOLDMAN_SACHS",
            jurisdiction="US_FED",
            transaction_id="test-tx-b9-01",
        )

        result = contract_b9_jurisdiction_filter(request, enforcer)

        assert result.admitted is True
        assert result.contract_id == "B9"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0

    def test_b9_disallowed_venue_rejects(self):
        """B9 rejects when venue is not in regional whitelist."""
        config = BoundingContractConfig(
            allowed_instruments=["AAPL", "GOOGL"],
            allowed_venues=["NYSE", "NASDAQ"],  # US venues only
            allowed_counterparties=["GOLDMAN_SACHS"],
        )
        enforcer = BoundingContractEnforcer(config)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="HKEX",  # Hong Kong Exchange not in US whitelist
            counterparty="GOLDMAN_SACHS",
            jurisdiction="APAC_MAS",
            transaction_id="test-tx-b9-02",
        )

        result = contract_b9_jurisdiction_filter(request, enforcer)

        assert result.admitted is False
        assert result.contract_id == "B9"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Venue not allowed in current regulatory jurisdiction"
        )
        assert result.findings[0]["venue"] == "HKEX"
        assert result.findings[0]["jurisdiction"] == "APAC_MAS"
        assert "Regional compliance filter (B9)" in result.findings[0]["note"]

    def test_b9_regional_overlay_us_fed(self):
        """B9 enforces US_FED regional venue whitelist."""
        us_config = BoundingContractConfig(
            allowed_instruments=["SPY", "QQQ"],
            allowed_venues=["NYSE", "NASDAQ", "CBOE"],  # US-only venues
            allowed_counterparties=["GOLDMAN_SACHS", "JP_MORGAN"],
        )
        us_enforcer = BoundingContractEnforcer(us_config)

        # US venue — admitted
        us_request = BoundedTradeRequest(
            symbol="SPY",
            amount=5000.0,
            side="buy",
            venue="CBOE",
            counterparty="GOLDMAN_SACHS",
            jurisdiction="US_FED",
            transaction_id="test-tx-b9-03",
        )

        result_us = contract_b9_jurisdiction_filter(us_request, us_enforcer)
        assert result_us.admitted is True

        # EU venue — rejected
        eu_request = BoundedTradeRequest(
            symbol="SPY",
            amount=5000.0,
            side="buy",
            venue="EUREX",
            counterparty="GOLDMAN_SACHS",
            jurisdiction="US_FED",
            transaction_id="test-tx-b9-04",
        )

        result_eu = contract_b9_jurisdiction_filter(eu_request, us_enforcer)
        assert result_eu.admitted is False
        assert result_eu.findings[0]["venue"] == "EUREX"

    def test_b9_regional_overlay_eu_ecb(self):
        """B9 enforces EU_ECB regional venue whitelist."""
        eu_config = BoundingContractConfig(
            allowed_instruments=["DAX", "STOXX50"],
            allowed_venues=["EUREX", "XETRA", "EURONEXT"],  # EU-only venues
            allowed_counterparties=["DEUTSCHE_BANK", "BNP_PARIBAS"],
        )
        eu_enforcer = BoundingContractEnforcer(eu_config)

        # EU venue — admitted
        eu_request = BoundedTradeRequest(
            symbol="DAX",
            amount=3000.0,
            side="buy",
            venue="EUREX",
            counterparty="DEUTSCHE_BANK",
            jurisdiction="EU_ECB",
            transaction_id="test-tx-b9-05",
        )

        result_eu = contract_b9_jurisdiction_filter(eu_request, eu_enforcer)
        assert result_eu.admitted is True

        # US venue — rejected
        us_request = BoundedTradeRequest(
            symbol="DAX",
            amount=3000.0,
            side="buy",
            venue="NYSE",
            counterparty="DEUTSCHE_BANK",
            jurisdiction="EU_ECB",
            transaction_id="test-tx-b9-06",
        )

        result_us = contract_b9_jurisdiction_filter(us_request, eu_enforcer)
        assert result_us.admitted is False
        assert result_us.findings[0]["venue"] == "NYSE"

    def test_b9_regional_overlay_apac_mas(self):
        """B9 enforces APAC_MAS regional venue whitelist."""
        apac_config = BoundingContractConfig(
            allowed_instruments=["HSI", "NIKKEI225"],
            allowed_venues=["HKEX", "SGX", "TSE"],  # APAC-only venues
            allowed_counterparties=["DBS", "HSBC"],
        )
        apac_enforcer = BoundingContractEnforcer(apac_config)

        # APAC venue — admitted
        apac_request = BoundedTradeRequest(
            symbol="HSI",
            amount=2000.0,
            side="buy",
            venue="HKEX",
            counterparty="DBS",
            jurisdiction="APAC_MAS",
            transaction_id="test-tx-b9-07",
        )

        result_apac = contract_b9_jurisdiction_filter(apac_request, apac_enforcer)
        assert result_apac.admitted is True

        # US venue — rejected
        us_request = BoundedTradeRequest(
            symbol="HSI",
            amount=2000.0,
            side="buy",
            venue="NASDAQ",
            counterparty="DBS",
            jurisdiction="APAC_MAS",
            transaction_id="test-tx-b9-08",
        )

        result_us = contract_b9_jurisdiction_filter(us_request, apac_enforcer)
        assert result_us.admitted is False
        assert result_us.findings[0]["venue"] == "NASDAQ"

    def test_b9_empty_venue_whitelist_permits_all(self):
        """B9 permits all venues when venue whitelist is empty (no restriction for venue dimension).
        
        BoundingContractEnforcer design: empty whitelist for a dimension means no restriction
        for that dimension, as long as at least one other whitelist is populated.
        This allows partial whitelisting (e.g., restrict instruments but not venues).
        """
        config = BoundingContractConfig(
            allowed_instruments=["AAPL"],
            allowed_venues=[],  # Empty whitelist → no venue restriction
            allowed_counterparties=["GOLDMAN_SACHS"],
        )
        enforcer = BoundingContractEnforcer(config)

        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",  # Any venue should be allowed
            counterparty="GOLDMAN_SACHS",
            jurisdiction="US_FED",
            transaction_id="test-tx-b9-09",
        )

        result = contract_b9_jurisdiction_filter(request, enforcer)

        # Empty venue whitelist → no restriction (permissive)
        assert result.admitted is True
        assert result.contract_id == "B9"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0
