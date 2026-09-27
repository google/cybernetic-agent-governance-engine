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

"""Synthetic telemetry generator for finance causal gatekeeper evaluation."""

from datetime import datetime, timezone

import numpy as np
import pandas as pd


def generate_mock_telemetry(n_samples: int = 1000) -> pd.DataFrame:
    """
    Generates synthetic historical telemetry data for the finance causal model.
    W: Market Volatility (Confounder)
    X: Trade Amount (Treatment)
    Y: Risk Score (Outcome)

    A ``timestamp`` column is included so that the telemetry freshness check
    treats this data as fresh. Timestamps are generated as recent UTC values
    (within the last hour) so they always pass the staleness threshold.
    """
    np.random.seed(42)
    # Confounder: Market Volatility (0.0 to 1.0)
    market_volatility = np.random.uniform(0.1, 0.9, n_samples)

    # Treatment: Trade Amount (influenced by volatility)
    # Higher volatility generally leads to smaller trade amounts, plus baseline
    trade_amount = np.random.normal(5000, 1000, n_samples) - (market_volatility * 2000)
    trade_amount = np.clip(trade_amount, 100, 10000)

    # Outcome: Risk Score (influenced by both volatility and trade amount)
    # Higher volatility -> higher risk
    # Higher trade amount -> higher risk
    risk_score = (
        (market_volatility * 0.5)
        + (trade_amount / 10000 * 0.5)
        + np.random.normal(0, 0.05, n_samples)
    )
    risk_score = np.clip(risk_score, 0.0, 1.0)

    # Timestamps: spread over the last 60 minutes so freshness check passes.
    now_epoch = datetime.now(tz=timezone.utc).timestamp()
    timestamps = now_epoch - np.random.uniform(0, 3600, n_samples)

    return pd.DataFrame(
        {
            "market_volatility": market_volatility,
            "trade_amount": trade_amount,
            "risk_score": risk_score,
            "timestamp": timestamps,
        }
    )


__all__ = ["generate_mock_telemetry"]
