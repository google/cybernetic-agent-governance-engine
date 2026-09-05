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

"""Unit tests for src.gateway.governance.null_components.

Verifies:
  1. NullTelemetryProvider: Typed empty dataframe schema, zero-row count,
     and CausalGatekeeper fail-closed degradation on insufficient data.
  2. NullColdStore: Dev simulation, prod rejection (CAGE_ENV=prod), receipt digest calculation.
  3. NullSafetyFilter and NullConsensusProvider: Explicit denial contracts.
"""

import os
from unittest.mock import patch
import numpy as np
import pandas as pd
import pytest

from src.gateway.governance.null_components import (
    NullColdStore,
    NullConsensusProvider,
    NullSafetyFilter,
    NullTelemetryProvider,
)
from src.gateway.governance.causal.gatekeeper import causal_safety_check


class TestNullTelemetryProvider:
    """Contract tests for NullTelemetryProvider (W1.6)."""

    def test_returns_empty_dataframe_with_correct_schema(self):
        provider = NullTelemetryProvider()
        df = provider.get_latest_data(n_samples=50)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0
        expected_cols = ["market_volatility", "trade_amount", "risk_score"]
        assert list(df.columns) == expected_cols
        for col in expected_cols:
            assert df[col].dtype == np.float64

    def test_default_n_samples(self):
        provider = NullTelemetryProvider()
        df = provider.get_latest_data()
        assert len(df) == 0

    def test_causal_gatekeeper_fail_closed_on_null_telemetry(self):
        """CausalGatekeeper must fail closed (return False) when passed NullTelemetryProvider data."""
        provider = NullTelemetryProvider()
        df = provider.get_latest_data()

        # causal_safety_check must evaluate insufficient samples and fail closed
        result = causal_safety_check(
            current_telemetry=df,
            trade_amount=1000.0,
            action="execute_trade",
            market_volatility=0.5,
        )
        assert result is False


class TestNullColdStore:
    """Contract tests for NullColdStore (W1.5)."""

    def test_dev_mode_instantiation_and_properties(self):
        with patch.dict(os.environ, {"CAGE_ENV": "dev"}):
            store = NullColdStore()
            assert store.backend_id == "null"
            health = store.health()
            assert health.available is True
            assert health.backend_id == "null"

    def test_prod_mode_raises_runtime_error(self):
        with patch.dict(os.environ, {"CAGE_ENV": "prod"}):
            with pytest.raises(RuntimeError, match="CAGE_ENV=prod requires real cold storage"):
                NullColdStore()

    @pytest.mark.asyncio
    async def test_put_batch_calculates_sha256_and_receipt(self):
        with patch.dict(os.environ, {"CAGE_ENV": "test"}):
            store = NullColdStore()
            content = b"evidence_payload_bytes"
            receipt = await store.put_batch("batches/batch_1.json", content)

            assert receipt.backend_id == "null"
            assert receipt.key == "batches/batch_1.json"
            assert receipt.uri == "null://batches/batch_1.json"
            assert len(receipt.content_sha256) == 64
            assert not (await store.exists("batches/batch_1.json"))


class TestNullSafetyFilterAndConsensus:
    """Bare kernel fallback contracts."""

    def test_safety_filter_denies_actions(self):
        filter_ = NullSafetyFilter()
        verdict = filter_.verify_action("execute_trade", {"symbol": "AAPL"})
        assert "UNSAFE" in verdict

    @pytest.mark.asyncio
    async def test_atomic_verify_denies(self):
        filter_ = NullSafetyFilter()
        allowed, reason = await filter_.atomic_verify_and_commit("execute_trade", {})
        assert allowed is False
        assert "UNSAFE" in reason

    @pytest.mark.asyncio
    async def test_consensus_provider_rejects(self):
        provider = NullConsensusProvider()
        result = await provider.check_consensus("execute_trade", {})
        assert result["status"] == "REJECT"
        assert result["agreement_level"] == 0.0

