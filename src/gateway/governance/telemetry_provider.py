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
[CTRL_TEL_003] Live Telemetry Provider for DoWhy Causal Gatekeeper
==================================================================

Replaces generate_mock_telemetry() (np.random.seed(42)) in causal_gatekeeper.py
with production telemetry sourced from Langfuse governance spans.

Control CTRL_TEL_003 (see config/control_mappings.json) requires that world-model
validation reflect actual runtime conditions, not synthetic data.  The placebo
refutation in causal_gatekeeper.py proves the *math* works against mock data;
it says nothing about whether the deployed agent's world-model beliefs are
coherent with live market dynamics.

Architecture:
  - BaseTelemetryProvider:       Abstract interface consumed by SymbolicGovernor.
  - LangfuseTelemetryProvider:   Fetches {market_volatility, trade_amount, risk_score}
                                 triples from Langfuse governance spans tagged
                                 iso42001.control_id=A.6.2.8 (UCA-4 governance).
  - MockTelemetryProvider:       Retained for test environments; wraps the original
                                 generate_mock_telemetry() function.

Integration:
  The SymbolicGovernor already exposes a `telemetry_provider` constructor arg:
    governor = SymbolicGovernor(
        ...
        telemetry_provider=LangfuseTelemetryProvider.from_env(),
    )
  No interface changes are required in symbolic_governor.py.

Fallback policy:
  If Langfuse returns fewer than MIN_SAMPLES live samples, the provider falls
  back to mock data and logs a WARNING so the gap is visible in audit trails.
  This prevents the causal gatekeeper from failing open on cold-start.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod

import numpy as np
import pandas as pd

logger = logging.getLogger("Gateway.Governance.TelemetryProvider")

# EV-4 Migration: MIN_SAMPLES is now sourced from config/governance_thresholds.json
# with environment variable overrides supported (CAUSAL_MIN_SAMPLES or legacy
# CAUSAL_MIN_LIVE_SAMPLES). See schemas/thresholds.py for details.
from src.gateway.governance.schemas.thresholds import get_causal_min_samples

# Minimum number of live Langfuse samples required before trusting the
# LangfuseTelemetryProvider over the MockTelemetryProvider fallback.
# CTRL_TEL_003 implication: below this threshold, the world-model cannot be
# considered representative of live market conditions.
MIN_SAMPLES: int = get_causal_min_samples()


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseTelemetryProvider(ABC):
    """Abstract interface for telemetry data consumed by the causal gatekeeper.

    Concrete providers must return a DataFrame with exactly three columns:
        market_volatility  float  [0, 1]
        trade_amount       float  [0, ∞)
        risk_score         float  [0, 1]
    """

    @abstractmethod
    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Return the most recent n_samples telemetry records.

        The returned DataFrame MUST contain these columns:
            market_volatility, trade_amount, risk_score

        Raises:
            NotImplementedError if the concrete class does not implement this.
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Mock provider (test / cold-start fallback)
# ---------------------------------------------------------------------------


class MockTelemetryProvider(BaseTelemetryProvider):
    """Wraps the original generate_mock_telemetry() helper.

    Used in:
      - Unit tests (deterministic seed)
      - Cold-start fallback when Langfuse has fewer than MIN_SAMPLES live records
      - Environments where LANGFUSE_PUBLIC_KEY is not configured

    The seed is configurable via CAUSAL_MOCK_SEED (default: 42) so tests can
    exercise different synthetic distributions.
    """

    def __init__(self, seed: int = 42) -> None:
        self._seed = seed

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Generate deterministic synthetic telemetry."""
        np.random.seed(self._seed)
        market_volatility = np.random.uniform(0.1, 0.9, n_samples)
        trade_amount = np.random.normal(5000, 1000, n_samples) - (
            market_volatility * 2000
        )
        trade_amount = np.clip(trade_amount, 100, 10_000)
        risk_score = (
            (market_volatility * 0.5)
            + (trade_amount / 10_000 * 0.5)
            + np.random.normal(0, 0.05, n_samples)
        )
        risk_score = np.clip(risk_score, 0.0, 1.0)
        return pd.DataFrame(
            {
                "market_volatility": market_volatility,
                "trade_amount": trade_amount,
                "risk_score": risk_score,
            }
        )


# ---------------------------------------------------------------------------
# Live Langfuse provider
# ---------------------------------------------------------------------------


class LangfuseTelemetryProvider(BaseTelemetryProvider):
    """[CTRL_TEL_003] Pull live governance telemetry from Langfuse.

    Queries Langfuse for recent traces tagged with governance spans
    (iso42001.control_id = A.6.2.8) and extracts:
        - market_volatility: from span metadata ("market_volatility" key)
        - trade_amount:      from span input payload ("amount" key)
        - risk_score:        from span scores (Langfuse score name "risk_score")

    If fewer than MIN_SAMPLES live records are available, falls back to
    MockTelemetryProvider and emits a WARNING stamped to the audit log so
    the gap is visible to governance examiners.

    Args:
        langfuse_client:  An initialised ``langfuse.Langfuse`` instance.
        fallback:         Provider to use when live data is insufficient.
                          Defaults to MockTelemetryProvider(seed=42).
    """

    def __init__(
        self,
        langfuse_client: object,
        fallback: BaseTelemetryProvider | None = None,
    ) -> None:
        self._client = langfuse_client
        self._fallback = fallback or MockTelemetryProvider()

    @classmethod
    def from_env(cls) -> LangfuseTelemetryProvider:
        """Construct from LANGFUSE_* environment variables.

        Required env vars:
            LANGFUSE_PUBLIC_KEY
            LANGFUSE_SECRET_KEY
            LANGFUSE_HOST  (default: https://cloud.langfuse.com)

        Falls back to MockTelemetryProvider if the Langfuse SDK is not
        installed or credentials are missing.
        """
        try:
            from langfuse import Langfuse  # type: ignore[import]

            public_key = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
            secret_key = os.environ.get("LANGFUSE_SECRET_KEY", "")
            host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")

            if not (public_key and secret_key):
                logger.warning(
                    "[CTRL_TEL_003] LANGFUSE_PUBLIC_KEY/SECRET_KEY not set — "
                    "causal gatekeeper will use MockTelemetryProvider. "
                    "This is acceptable in non-production environments but MUST "
                    "be remediated before a governance examination."
                )
                return cls(langfuse_client=None, fallback=MockTelemetryProvider())

            client = Langfuse(
                public_key=public_key,
                secret_key=secret_key,
                host=host,
            )
            logger.info(
                "[CTRL_TEL_003] LangfuseTelemetryProvider initialised (host=%s).", host
            )
            return cls(langfuse_client=client)

        except ImportError:
            logger.warning(
                "[CTRL_TEL_003] langfuse package not installed — "
                "falling back to MockTelemetryProvider."
            )
            return cls(langfuse_client=None, fallback=MockTelemetryProvider())

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Fetch live trade governance telemetry from Langfuse.

        Queries traces with the 'execute_trade' name, extracts governance
        metadata, and builds the causal model DataFrame.

        Falls back to MockTelemetryProvider when:
          - Langfuse client is None (missing credentials / offline)
          - Fewer than MIN_SAMPLES records are available
          - Any exception is raised during the fetch
        """
        if self._client is None:
            logger.warning(
                "[CTRL_TEL_003] No Langfuse client — using MockTelemetryProvider fallback."
            )
            return self._fallback.get_latest_data(n_samples)

        try:
            # Fetch recent execute_trade traces from Langfuse.
            # The Langfuse SDK `fetch_traces` returns a paginated response;
            # we limit to n_samples to bound latency.
            response = self._client.fetch_traces(  # type: ignore[attr-defined]
                name="execute_trade",
                limit=n_samples,
            )
            traces = response.data if hasattr(response, "data") else []

            rows: list[dict] = []
            for trace in traces:
                # Extract governance metadata injected by the governed trader node.
                # Keys are set by NeMoOTelCallback and evaluator_node.py.
                meta = getattr(trace, "metadata", {}) or {}
                input_data = getattr(trace, "input", {}) or {}
                scores_list = getattr(trace, "scores", []) or []

                # Build the score lookup: {name -> value}
                scores = {
                    getattr(s, "name", ""): getattr(s, "value", None)
                    for s in scores_list
                }

                market_vol = meta.get("market_volatility")
                trade_amount = (input_data or {}).get("amount")
                risk_score = scores.get("risk_score") or meta.get("risk_score")

                # Only include rows where all three variables are present.
                if (
                    market_vol is not None
                    and trade_amount is not None
                    and risk_score is not None
                ):
                    rows.append(
                        {
                            "market_volatility": float(market_vol),
                            "trade_amount": float(trade_amount),
                            "risk_score": float(risk_score),
                        }
                    )

            if len(rows) < MIN_SAMPLES:
                logger.warning(
                    "[CTRL_TEL_003] Only %d live Langfuse samples available "
                    "(minimum %d required). Falling back to MockTelemetryProvider. "
                    "Remediate by ensuring governance spans emit market_volatility, "
                    "amount, and risk_score metadata on execute_trade traces.",
                    len(rows),
                    MIN_SAMPLES,
                )
                return self._fallback.get_latest_data(n_samples)

            logger.info(
                "[CTRL_TEL_003] LangfuseTelemetryProvider returning %d live samples "
                "for DoWhy causal model.",
                len(rows),
            )
            return pd.DataFrame(rows)

        except Exception as exc:
            logger.error(
                "[CTRL_TEL_003] LangfuseTelemetryProvider fetch failed (%s) — "
                "falling back to MockTelemetryProvider.",
                exc,
            )
            return self._fallback.get_latest_data(n_samples)
